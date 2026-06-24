use clap::Parser;
use kms::cli::client::KmsClient;
use kms::cli::cmds;
use kms::cli::config::{OutputFormat, ServerConfig};
use kms::cli::types::{AuthAction, CliCommand};

#[derive(Parser)]
#[command(name = "kms-cli", about = "KMS 命令行管理工具")]
struct Cli {
    #[arg(global = true, long, env = "KMS_HOST")]
    server: Option<String>,

    #[arg(global = true, long, env = "KMS_TOKEN")]
    token: Option<String>,

    #[arg(global = true, long, default_value = "table", value_parser = ["table", "json"])]
    output: String,

    #[arg(global = true, long)]
    print_json: bool,

    #[arg(global = true, long)]
    accept_invalid_certs: bool,

    #[command(subcommand)]
    command: CliCommand,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let output = match cli.output.as_str() {
        "json" => OutputFormat::Json,
        _ => OutputFormat::Table,
    };

    let cfg = ServerConfig::load(
        cli.server,
        cli.token,
        cli.accept_invalid_certs,
        cli.print_json,
        output,
    );

    use CliCommand::*;
    match &cli.command {
        Auth {
            action: AuthAction::TotpCode { secret },
        } => {
            if let Err(e) = cmds::auth::handle_totp_code(secret) {
                eprintln!("错误: {}", e);
                std::process::exit(1);
            }
            return;
        }
        Configure { action } => {
            if let Err(e) = cmds::configure::handle(action).await {
                eprintln!("错误: {}", e);
                std::process::exit(1);
            }
            return;
        }
        Server { action } => {
            if let Err(e) = cmds::server::handle(action).await {
                eprintln!("错误: {}", e);
                std::process::exit(1);
            }
            return;
        }
        Debug { .. } => {} // fall through, 需要 client
        _ => {}
    }

    let client = match KmsClient::new(&cfg) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("错误: 初始化客户端失败: {}", e);
            std::process::exit(1);
        }
    };

    // debug 命令需要 client（rng/hmac 走 KMIP，sm3/sha256 本地）
    if let Debug { .. } = &cli.command {
        if let Err(e) = cmds::debug::dispatch(Some(&client), &cli.command).await {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let result = cmds::dispatch(&cli.command, &client).await;
    match result {
        Ok(value) => {
            if let Some(v) = value {
                kms::cli::output::print_result(&v, &cfg.output_format);
            }
        }
        Err(e) => {
            eprintln!("错误: {}", e);
            eprintln!("提示: 使用 --print-json 查看原始请求/响应以便调试");
            std::process::exit(1);
        }
    }
}
