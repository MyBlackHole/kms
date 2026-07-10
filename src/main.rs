use clap::Parser;
use kms::api;
use kms::audit;
use kms::auth;
use kms::config;
use kms::crypto;
use kms::crypto::HashEngine;
use kms::hsm;
use kms::key;
#[cfg(feature = "monitoring")]
use kms::monitor;
use kms::policy;
use kms::store;

fn resolve_software_seed(cfg: &config::Config) -> Option<String> {
    cfg.hsm.software_master_seed.clone().or_else(|| {
        cfg.crypto.master_seed_path.as_ref().and_then(|p| {
            std::fs::read(p).ok().map(|bytes| {
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            })
        })
    })
}

/// 打印安全启动摘要
fn print_security_startup_summary(cfg: &config::Config, profile: config::SecurityProfile) {
    let level = match cfg.auth.security_level {
        config::SecurityLevel::Level3 => "Level3 (等保三级)",
        config::SecurityLevel::Level4 => {
            if profile.is_production() {
                "Level4 (等保四级) — 生产画像 — 封闭安全策略"
            } else {
                "Level4 (等保四级) — 开发/CI 画像 — 非生产模式"
            }
        }
    };
    tracing::info!(
        target: "security",
        "=== 安全启动摘要 ==="
    );
    tracing::info!(target: "security", "安全等级: {}", level);
    tracing::info!(target: "security", "运行画像: {}", profile.as_str());
    tracing::info!(target: "security", "HSM 模式: {}", cfg.hsm.mode);
    tracing::info!(target: "security", "审计链: {}", cfg.audit.enable_chain);
    tracing::info!(target: "security", "审计签名: {}", cfg.audit.enable_signing);
    tracing::info!(target: "security", "抗抵赖: {}", cfg.auth.anti_repudiation);
    if cfg.auth.admin_token.is_some() {
        tracing::info!(target: "security", "admin_token: 已配置");
    } else {
        tracing::warn!(target: "security", "admin_token: 未配置 — 仅限开发/测试用途");
    }
    if cfg.auth.security_level == config::SecurityLevel::Level3 && !profile.is_production() {
        tracing::warn!(
            target: "security",
            "⚠ 非四级生产模式 — 宽松 Bearer 认证仅在 Level3/Dev Profile 下允许"
        );
    }
    tracing::info!(target: "security", "=== 安全启动摘要结束 ===");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let cli = config::Cli::parse();

    // 处理 CLI 子命令
    if cli.hash_self {
        let hash = kms::trust::TrustVerifier::compute_self_hash();
        println!("{}", hash);
        return Ok(());
    }
    let mut cfg = config::Config::load(&cli.config).unwrap_or_else(|_| {
        tracing::warn!("无法加载配置文件，使用默认配置");
        config::Config {
            server: config::ServerConfig {
                host: "127.0.0.1".into(),
                port: 8443,
                workers: 4,
                tls: None,
                session_ttl_secs: 3600,
            },
            database: config::DatabaseConfig {
                url: "sqlite://data/kms.db?mode=rwc".into(),
                max_connections: 10,
                run_migrations: true,
            },
            crypto: config::CryptoConfig {
                kek_path: "data/master.key".into(),
                key_rotation_days: 365,
                max_key_versions: 10,
                master_seed_path: None,
            },
            audit: config::AuditConfig {
                log_path: "data/audit.log".into(),
                retention_days: 365,
                enable_chain: true,
                enable_signing: true,
            },
            hsm: config::HsmConfig {
                mode: "software".into(),
                pkcs11_module_path: None,
                pkcs11_slot_id: None,
                pkcs11_pin: None,
                software_master_seed: None,
            },
            policy: config::PolicyConfig {
                enable_rbac: true,
                enforce_https: true,
            },
            trust: kms::trust::TrustConfig::default(),
            tpm: config::TpmConfig {
                mode: "software".into(),
                tcti: None,
                enable_startup_measurement: true,
                app_pcr_index: 16,
            },
            cluster: config::ClusterConfig {
                node_id: uuid::Uuid::new_v4().to_string(),
                peers: vec![],
                peer_port: 9443,
                enabled: false,
            },
            auth: config::AuthConfig {
                totp_issuer: "KMS".into(),
                admin_token: None,
                security_level: config::SecurityLevel::Level3,
                anti_repudiation: false,
                sensitive_operations: config::AuthConfig::default().sensitive_operations,
            },
            profile: config::SecurityProfile::default(),
            level4: config::Level4Config::default(),
        }
    });

    // 应用 CLI --profile 覆盖
    if let Some(p) = cli.profile {
        cfg.profile = p;
    }

    let effective_profile = cfg.effective_profile();

    // Level4 启动自检
    if cfg.auth.security_level == config::SecurityLevel::Level4 && effective_profile.is_production()
    {
        tracing::info!("Level4 生产画像 — 执行启动自检");
        // HSM 必选检查已经由 validate() 完成
        // 输出醒目标记
        tracing::warn!("⚠ 当前为四级等保生产模式 — 所有安全控制已强制启用");
    }

    // 启动安全摘要
    print_security_startup_summary(&cfg, effective_profile);

    // 可信验证：检查二进制和配置文件完整性
    if let Some(ref expected_hash) = cfg.trust.expected_binary_hash {
        if !kms::trust::TrustVerifier::verify_binary(expected_hash) {
            anyhow::bail!("二进制文件完整性校验失败，拒绝启动");
        }
        tracing::info!("二进制完整性校验通过");
    }
    if let Some(ref expected_hash) = cfg.trust.expected_config_hash {
        let config_data = std::fs::read(&cli.config).unwrap_or_default();
        if !kms::trust::TrustVerifier::verify_config(&config_data, expected_hash) {
            anyhow::bail!("配置文件完整性校验失败，拒绝启动");
        }
        tracing::info!("配置文件完整性校验通过");
    }

    std::fs::create_dir_all("data")?;

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .connect(&cfg.database.url)
        .await?;

    if cfg.database.run_migrations {
        store::migrations::run_migrations(&pool).await?;
        tracing::info!("数据库迁移完成");
    }

    // 如果配置了 master_seed_path，自动管理种子文件
    if let Some(ref seed_path) = cfg.crypto.master_seed_path {
        let seed_dir = seed_path.parent().unwrap_or(std::path::Path::new("data"));
        std::fs::create_dir_all(seed_dir)?;
        if !seed_path.exists() {
            let mut buf = vec![0u8; 32];
            getrandom::getrandom(&mut buf)?;
            std::fs::write(seed_path, &buf)?;
            let fp = hex::encode(kms::crypto::sm3_engine::Sm3Engine::new().hash(&buf));
            tracing::info!(
                "已生成新的 master seed (SM3: {}): {}",
                &fp[..16],
                seed_path.display()
            );
        }
    }

    let software_seed = resolve_software_seed(&cfg);
    let started_at = std::time::Instant::now();

    let kek_provider: Box<dyn hsm::traits::KekProvider> = match cfg.hsm.mode.as_str() {
        "software" => Box::new(hsm::software_provider::SoftwareKekProvider::new(
            software_seed.as_deref(),
        )?),
        "pkcs11" => {
            #[cfg(feature = "pkcs11-hsm")]
            {
                let module = cfg
                    .hsm
                    .pkcs11_module_path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("PKCS#11 模式需要指定 module_path"))?;
                let slot = cfg
                    .hsm
                    .pkcs11_slot_id
                    .ok_or_else(|| anyhow::anyhow!("PKCS#11 模式需要指定 slot_id"))?;
                let pin = cfg
                    .hsm
                    .pkcs11_pin
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("PKCS#11 模式需要指定 PIN"))?;
                Box::new(hsm::pkcs11_provider::Pkcs11KekProvider::new(
                    module, slot, pin,
                )?)
            }
            #[cfg(not(feature = "pkcs11-hsm"))]
            {
                anyhow::bail!(
                    "PKCS#11 模式需要启用 pkcs11-hsm feature: cargo build --features pkcs11-hsm"
                )
            }
        }
        "sdf" => Box::new(hsm::sdf_provider::SdfKekProvider::new(
            software_seed.as_deref(),
        )?),
        other => anyhow::bail!("不支持的 HSM 模式: {}", other),
    };
    tracing::info!("KEK 提供程序: {}", kek_provider.name());

    // 处理 evidence 导出 CLI 命令
    if let Some(ref evidence_dir) = cli.evidence {
        std::fs::create_dir_all(evidence_dir)?;
        kms::evidence::export_evidence_package(&pool, evidence_dir).await?;
        return Ok(());
    }

    // 处理管理子命令（等保四级）
    if let Some(ref cmd) = cli.command {
        return match cmd {
            config::CliCommand::ExportKeys { output } => {
                kms::backup::export_keys(&pool, output).await?;
                tracing::info!("密钥已导出至: {}", output.display());
                Ok(())
            }
            config::CliCommand::ImportKeys { input } => {
                let count = kms::backup::import_keys(&pool, input).await?;
                tracing::info!("已导入 {} 个密钥", count);
                Ok(())
            }
            config::CliCommand::BackupSeed { output } => {
                let seed_path = cfg
                    .crypto
                    .master_seed_path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("配置中未设置 master_seed_path"))?;
                kms::backup::export_master_seed(seed_path, output).await?;
                Ok(())
            }
            config::CliCommand::RestoreSeed { input } => {
                let seed_path = cfg
                    .crypto
                    .master_seed_path
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("配置中未设置 master_seed_path"))?;
                kms::backup::import_master_seed(input, seed_path)?;
                Ok(())
            }
        };
    }

    let key_store = key::store::KeyStoreSqlite::new(pool.clone());
    let key_manager = key::manager::KeyManager::new(Box::new(key_store));

    // 初始化 TPM 可信根（等保四级）
    let tpm_provider: Box<dyn kms::trust::tpm::TrustedPlatformModule> = {
        match cfg.tpm.mode.as_str() {
            "tpm" => {
                #[cfg(feature = "tpm")]
                {
                    if let Some(ref tcti) = cfg.tpm.tcti {
                        Box::new(kms::trust::tpm::TssTpm::connect_with_tcti(tcti)?)
                    } else {
                        Box::new(kms::trust::tpm::TssTpm::connect()?)
                    }
                }
                #[cfg(not(feature = "tpm"))]
                {
                    tracing::warn!("tpm mode 需要 'tpm' feature，降级为 SoftwareTpm");
                    Box::new(kms::trust::tpm::SoftwareTpm::new())
                }
            }
            _ => {
                tracing::info!("TPM 模式: software（开发/测试）");
                Box::new(kms::trust::tpm::SoftwareTpm::new())
            }
        }
    };

    // 启动时 PCR 度量（可信启动链）
    if cfg.tpm.enable_startup_measurement {
        let binary_hash = kms::trust::TrustVerifier::compute_self_hash();
        let pcr_idx = kms::trust::tpm::PcrIndex::KmsApp;
        if let Err(e) = tpm_provider.pcr_extend(pcr_idx, binary_hash.as_bytes()) {
            tracing::warn!("TPM PCR 度量失败 (非致命): {}", e);
        } else {
            tracing::info!("TPM PCR[{}] 度量二进制哈希: {}", 16, &binary_hash[..16]);
        }
        // 同时度量配置文件
        if let Ok(config_data) = std::fs::read_to_string(&cli.config) {
            let _ =
                tpm_provider.pcr_extend(kms::trust::tpm::PcrIndex::KmsApp, config_data.as_bytes());
        }
    }

    let primary_store = Box::new(audit::sqlite_store::SqliteAuditStore::new(pool.clone()));
    #[cfg(feature = "monitoring")]
    let audit_store: Box<dyn audit::logger::AuditStore> = {
        let syslog_store = Box::new(monitor::syslog::SyslogAuditStore::new());
        Box::new(monitor::syslog::DualAuditStore::new(
            primary_store,
            syslog_store,
        ))
    };
    #[cfg(not(feature = "monitoring"))]
    let audit_store: Box<dyn audit::logger::AuditStore> = primary_store;
    let audit_logger = audit::logger::AuditLogger::new(
        audit_store,
        None,
        cfg.audit.enable_chain,
        cfg.audit.enable_signing,
        cfg.auth.security_level,
    );

    let policy_engine = std::sync::Arc::new(policy::engine::PolicyEngine::new());
    let envelope = crypto::envelope::EnvelopeEncryption::new();

    // Level4 使用 level4.session_timeout_seconds，level3 使用 server.session_ttl_secs
    let effective_session_ttl = if cfg.auth.security_level == config::SecurityLevel::Level4 {
        cfg.level4.session_timeout_seconds
    } else {
        cfg.server.session_ttl_secs
    };
    let session_manager =
        std::sync::Arc::new(auth::session::SessionManager::new(effective_session_ttl));
    let totp_secret_issuer = cfg.auth.totp_issuer.clone();
    let token_store = auth::token::TokenStore::new(pool.clone());
    let auth = std::sync::Arc::new(api::middleware::Auth::new(cfg.auth.admin_token.clone()));

    // Level4 二次鉴权管理器
    let reauth_manager = if cfg.auth.security_level == config::SecurityLevel::Level4 {
        Some(std::sync::Arc::new(auth::reauth::ReauthManager::new(
            cfg.auth.sensitive_operations.clone(),
            cfg.level4.sensitive_operation_reauth_ttl_seconds,
            effective_profile,
        )))
    } else {
        None
    };

    let approval_store = kms::approval::SqliteApprovalStore::new(pool.clone());
    let dep_store = kms::key::dependency::SqliteDependencyStore::new(pool.clone());

    let app_state = std::sync::Arc::new(api::routes::AppState {
        key_manager,
        envelope,
        kek_provider,
        audit_logger,
        policy_engine: (*policy_engine).clone(),
        session_manager: session_manager.clone(),
        totp_secret_issuer,
        pool: pool.clone(),
        token_store: token_store.clone(),
        approval_store,
        dep_store,
        blocklist: kms::monitor::blocklist::SharedBlocklist::new(),
        tpm: tpm_provider,
        started_at,
        totp_attempts: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        security_level: cfg.auth.security_level,
        anti_repudiation: cfg.auth.anti_repudiation,
        // Level4 配置分享
        security_profile: effective_profile,
        level4_config: cfg.level4.clone(),
        reauth_manager: reauth_manager.clone(),
    });

    let mw_state = api::middleware::AuthMiddlewareState {
        auth: auth.clone(),
        policy: policy_engine.clone(),
        session_manager: session_manager.clone(),
        token_store: std::sync::Arc::new(token_store),
        require_mtls: cfg
            .server
            .tls
            .as_ref()
            .and_then(|tls| tls.client_ca_path.as_ref())
            .is_some(),
        security_level: cfg.auth.security_level,
        reauth_manager,
        sensitive_operations: cfg.auth.sensitive_operations.clone(),
    };

    let app = api::routes::build_router(app_state)
        .route_layer(axum::middleware::from_fn_with_state(
            mw_state,
            api::middleware::auth_middleware,
        ))
        .layer(axum::middleware::from_fn(
            api::middleware::request_tracking_middleware,
        ));

    let addr = format!("{}:{}", cfg.server.host, cfg.server.port);
    tracing::info!("KMS 服务启动于 {}", addr);

    // Graceful shutdown: handle SIGTERM (systemd) and SIGINT (Ctrl+C)
    let shutdown_signal = async {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm_stream = signal(SignalKind::terminate()).ok();
        let mut sigint_stream = signal(SignalKind::interrupt()).ok();

        tokio::select! {
            _ = async {
                if let Some(ref mut s) = sigterm_stream {
                    s.recv().await;
                }
            } => {
                tracing::info!("收到 SIGTERM 信号，开始优雅关闭...");
            }
            _ = async {
                if let Some(ref mut s) = sigint_stream {
                    s.recv().await;
                }
            } => {
                tracing::info!("收到 SIGINT 信号，开始优雅关闭...");
            }
        }
    };

    match &cfg.server.tls {
        Some(tls) => {
            use axum_server::Handle;
            use std::time::Duration;

            let server_config = api::mtls::build_rustls_config(
                &tls.cert_path,
                &tls.key_path,
                tls.client_ca_path.as_deref(),
            )?;

            let handle = Handle::new();
            let server_handle = tokio::spawn(
                axum_server::bind(
                    addr.parse::<std::net::SocketAddr>()
                        .map_err(|e| anyhow::anyhow!("地址格式错误: {}", e))?,
                )
                .acceptor(api::mtls::MtlsAcceptor::new(server_config))
                .handle(handle.clone())
                .serve(app.into_make_service()),
            );

            shutdown_signal.await;
            handle.graceful_shutdown(Some(Duration::from_secs(30)));
            server_handle
                .await
                .map_err(|e| anyhow::anyhow!("服务异常: {}", e))??;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal)
                .await?;
        }
    }

    tracing::info!("KMS 服务已安全关闭");
    Ok(())
}
