use crate::cli::types::ConfigureAction;
use std::io::Write;
use std::path::PathBuf;

pub async fn handle(action: &ConfigureAction) -> crate::Result<()> {
    match action {
        ConfigureAction::Init => init().await,
        ConfigureAction::Show => show().await,
    }
}

async fn init() -> crate::Result<()> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.toml");

    if path.exists() {
        print!("配置已存在 ({}), 覆盖? [y/N] ", path.display());
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("取消");
            return Ok(());
        }
    }

    println!("-- KMS HTTP 设置 --");

    let url = prompt("Server URL", "http://127.0.0.1:8443");
    let _accept_invalid = prompt_bool("接受自签名 TLS 证书?", false);
    let token = prompt_optional("管理 Token（留空跳过）");
    let custom_headers = prompt_bool("添加自定义 HTTP 头?", false);

    let mut headers_toml = String::new();
    if custom_headers {
        loop {
            let name = prompt_optional("Header 名称（留空结束）");
            if name.is_empty() {
                break;
            }
            let value = prompt_optional("Header 值");
            headers_toml.push_str(&format!("{}=\"{}\"\n", name, value));
        }
    }

    let token_line = if token.is_empty() {
        String::new()
    } else {
        format!("token = \"{}\"\n", token)
    };

    let content = format!(
        r#"[server]
url = "{url}"

[auth]
{token_line}
"#
    );

    std::fs::write(&path, content.trim())?;
    println!("\n配置已写入: {}", path.display());
    Ok(())
}

async fn show() -> crate::Result<()> {
    let path = config_dir().join("config.toml");
    if !path.exists() {
        println!("配置文件不存在: {}", path.display());
        println!("运行 `kms-cli configure init` 创建");
        return Ok(());
    }
    let content = std::fs::read_to_string(&path)?;
    println!("{}", content);
    Ok(())
}

fn prompt(label: &str, default: &str) -> String {
    print!("{} [{}]: ", label, default);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed
    }
}

fn prompt_bool(label: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    print!("{} [{}]: ", label, hint);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default,
    }
}

fn prompt_optional(label: &str) -> String {
    print!("{}: ", label);
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

fn config_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".kms")
}
