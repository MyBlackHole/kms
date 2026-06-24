use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub server_url: String,
    pub token: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub accept_invalid_certs: bool,
    pub print_json: bool,
    pub output_format: OutputFormat,
}

#[derive(Debug, Clone, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
}

impl ServerConfig {
    pub fn load(
        server: Option<String>,
        token: Option<String>,
        accept_invalid_certs: bool,
        print_json: bool,
        output: OutputFormat,
    ) -> Self {
        let from_file = Self::load_config_file();
        let server_url = server
            .or_else(|| std::env::var("KMS_HOST").ok())
            .or(from_file
                .as_ref()
                .and_then(|c| c.server.as_ref()?.url.clone()))
            .unwrap_or_else(|| "http://127.0.0.1:8443".to_string());

        let token = token
            .or_else(|| std::env::var("KMS_TOKEN").ok())
            .or(from_file
                .as_ref()
                .and_then(|c| c.auth.as_ref()?.token.clone()));

        Self {
            server_url,
            token,
            cert_path: None,
            key_path: None,
            accept_invalid_certs,
            print_json,
            output_format: output,
        }
    }

    fn load_config_file() -> Option<FileConfig> {
        let path = home_dir()?.join(".kms").join("config.toml");
        if !path.exists() {
            return None;
        }
        let content = std::fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .or_else(|| {
            if cfg!(windows) {
                std::env::var("USERPROFILE").ok()
            } else {
                None
            }
        })
        .map(PathBuf::from)
}

#[derive(serde::Deserialize)]
struct FileConfig {
    server: Option<FileServerConfig>,
    auth: Option<FileAuthConfig>,
}

#[derive(serde::Deserialize)]
struct FileServerConfig {
    url: Option<String>,
}

#[derive(serde::Deserialize)]
struct FileAuthConfig {
    token: Option<String>,
}
