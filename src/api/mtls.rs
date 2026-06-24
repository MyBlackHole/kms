use crate::crypto::traits::HashEngine;
use axum::http::Request;
use axum_server::accept::Accept;
use futures::FutureExt;
use hyper::body::Incoming;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, private_key};
use std::future::Future;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tower::Service;

#[derive(Clone, Debug)]
pub struct TlsIdentity {
    pub peer_addr: SocketAddr,
    pub fingerprint: String,
    pub subject: String,
}

impl TlsIdentity {
    pub fn authenticated(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct MtlsService<S> {
    inner: S,
    identity: Option<TlsIdentity>,
}

impl<S> MtlsService<S> {
    fn new(inner: S, identity: Option<TlsIdentity>) -> Self {
        Self { inner, identity }
    }
}

impl<S> Service<Request<Incoming>> for MtlsService<S>
where
    S: Service<Request<Incoming>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + Sync + 'static,
    S::Response: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        let identity = self.identity.clone();
        let mut inner = self.inner.clone();

        async move {
            if let Some(identity) = identity {
                req.extensions_mut().insert(identity);
            }
            inner.call(req).await
        }
        .boxed()
    }
}

#[derive(Clone)]
pub struct MtlsAcceptor {
    config: Arc<ServerConfig>,
}

impl MtlsAcceptor {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }
}

impl<S> Accept<TcpStream, S> for MtlsAcceptor
where
    S: Clone + Send + 'static,
    S: Service<Request<Incoming>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + Sync + 'static,
    S::Response: Send + 'static,
{
    type Stream = TlsStream<TcpStream>;
    type Service = MtlsService<S>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let config = self.config.clone();
        async move {
            let peer_addr = stream
                .peer_addr()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
            let acceptor = TlsAcceptor::from(config);
            let tls_stream = acceptor.accept(stream).await?;
            let identity = extract_identity(peer_addr, &tls_stream);
            Ok((tls_stream, MtlsService::new(service, identity)))
        }
        .boxed()
    }
}

pub fn build_rustls_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_pem = std::fs::read(cert_path).map_err(|e| anyhow::anyhow!("读取证书失败: {}", e))?;
    let key_pem = std::fs::read(key_path).map_err(|e| anyhow::anyhow!("读取密钥失败: {}", e))?;

    let cert_chain = certs(&mut BufReader::new(cert_pem.as_slice()))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| anyhow::anyhow!("证书解析失败: {}", e))?;

    let key = read_private_key(key_pem.as_slice())
        .map_err(|e| anyhow::anyhow!("密钥解析失败: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("未找到私钥"))?;

    let mut server_config = if let Some(ca_path) = client_ca_path {
        let ca_pem =
            std::fs::read(ca_path).map_err(|e| anyhow::anyhow!("读取 CA 证书失败: {}", e))?;
        let mut roots = RootCertStore::empty();
        for cert in certs(&mut BufReader::new(ca_pem.as_slice())) {
            roots
                .add(cert.map_err(|e| anyhow::anyhow!("CA 证书解析失败: {}", e))?)
                .map_err(|e| anyhow::anyhow!("CA 证书添加失败: {}", e))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| anyhow::anyhow!("mTLS 证书验证器初始化失败: {}", e))?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert_chain, key)
            .map_err(|e| anyhow::anyhow!("TLS 配置失败: {}", e))?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| anyhow::anyhow!("TLS 配置失败: {}", e))?
    };
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(server_config))
}

fn read_private_key(key_pem: &[u8]) -> io::Result<Option<PrivateKeyDer<'static>>> {
    let mut reader = BufReader::new(key_pem);
    private_key(&mut reader)
}

fn extract_identity(peer_addr: SocketAddr, stream: &TlsStream<TcpStream>) -> Option<TlsIdentity> {
    let (_, session) = stream.get_ref();
    let certs = session.peer_certificates()?;
    let first = certs.first()?;
    let fingerprint = hex::encode(crate::crypto::sm3_engine::Sm3Engine::new().hash(first.as_ref()));
    let subject = format!("mtls:{}", &fingerprint[..16.min(fingerprint.len())]);
    Some(TlsIdentity {
        peer_addr,
        fingerprint,
        subject,
    })
}
