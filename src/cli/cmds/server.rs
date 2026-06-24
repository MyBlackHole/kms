use crate::cli::types::ServerAction;
use crate::crypto::sm3_engine::Sm3Engine;
use crate::crypto::traits::HashEngine;
use std::path::PathBuf;

pub async fn handle(action: &ServerAction) -> crate::Result<()> {
    match action {
        ServerAction::HashSelf { path } => cmd_hash_self(path.as_deref()),
        ServerAction::Evidence { dir } => cmd_evidence(dir).await,
    }
}

fn cmd_hash_self(path: Option<&str>) -> crate::Result<()> {
    let target = path.map(PathBuf::from).unwrap_or_else(|| {
        std::env::current_exe().unwrap_or_else(|_| "target/debug/kms-server".into())
    });
    let data = std::fs::read(&target)?;
    let engine = Sm3Engine::new();
    let hash = engine.hash(&data);
    println!("{}  {}", hex::encode(&hash), target.display());
    Ok(())
}

async fn cmd_evidence(_dir: &str) -> crate::Result<()> {
    println!("证据导出需要直接运行 kms-server --evidence <dir>");
    println!("kms-cli 不支持远程证据导出（需要本地数据库访问）");
    Ok(())
}
