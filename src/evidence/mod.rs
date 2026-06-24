use serde::Serialize;
use std::path::Path;

/// 合规自评报告
#[derive(Serialize)]
pub struct ComplianceReport {
    pub version: String,
    pub generated_at: String,
    pub items: Vec<ComplianceItem>,
}

#[derive(Serialize)]
pub struct ComplianceItem {
    pub id: u32,
    pub name: String,
    pub status: String, // ✅ / ⚠️ / ❌
    pub description: String,
}

/// 导出合规证据包
pub async fn export_evidence_package(
    pool: &sqlx::SqlitePool,
    output_dir: &Path,
) -> crate::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();

    // 1. 导出密钥元数据
    let keys: Vec<(String,)> = sqlx::query_as("SELECT data FROM keys ORDER BY created_at DESC")
        .fetch_all(pool)
        .await?;
    let keys_json = serde_json::to_string_pretty(&keys)?;
    std::fs::write(output_dir.join("keys.json"), &keys_json)?;

    // 2. 导出审计链
    let audit_rows: Vec<(String,)> =
        sqlx::query_as("SELECT data FROM audit_log ORDER BY timestamp")
            .fetch_all(pool)
            .await
            .unwrap_or_default();
    let audit_json = serde_json::to_string_pretty(&audit_rows)?;
    std::fs::write(output_dir.join("audit_chain.json"), &audit_json)?;

    // 3. 生成自评报告
    // 等保四级合规项
    let level4_items: Vec<ComplianceItem> = vec![
        ComplianceItem {
            id: 21,
            name: "TPM 可信根".into(),
            status: "✅".into(),
            description: "已支持软件 TPM 与真实 TPM（tpm feature + tss-esapi + TCTI）".to_string(),
        },
        ComplianceItem {
            id: 22,
            name: "硬件密码模块".into(),
            status: "⚠️".into(),
            description: "PKCS#11/SDF 接口骨架，需真实 HSM/密码卡".to_string(),
        },
        ComplianceItem {
            id: 23,
            name: "入侵自动阻断".into(),
            status: "✅".into(),
            description: "Blocklist 模块已实现（累进封禁 + 过期解封）".to_string(),
        },
        ComplianceItem {
            id: 24,
            name: "全盘加密".into(),
            status: "⚠️".into(),
            description: "部署文档已覆盖 LUKS 配置，需运维执行".to_string(),
        },
        ComplianceItem {
            id: 25,
            name: "可信启动链".into(),
            status: "⚠️".into(),
            description: "TPM PCR 度量框架已就绪，需 Secure Boot + 固件支持".to_string(),
        },
        ComplianceItem {
            id: 26,
            name: "物理安全".into(),
            status: "⚠️".into(),
            description: "加固文档已覆盖，需机箱侵入检测 + HSM 锁".to_string(),
        },
        ComplianceItem {
            id: 27,
            name: "节点间可信通信".into(),
            status: "❌".into(),
            description: "集群 mTLS 预留接口，当前为单机部署".to_string(),
        },
        ComplianceItem {
            id: 28,
            name: "灾难恢复 RTO/RPO".into(),
            status: "⚠️".into(),
            description: "异地备份方案文档已定，需演练验证".to_string(),
        },
        ComplianceItem {
            id: 29,
            name: "资源隔离与 MAC".into(),
            status: "⚠️".into(),
            description: "cgroup 配置 + SELinux 策略文档已覆盖".to_string(),
        },
    ];

    let report = ComplianceReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: now.clone(),
        items: vec![
            ComplianceItem {
                id: 1,
                name: "强身份鉴别".into(),
                status: "✅".into(),
                description: "TOTP 双因子 + mTLS 客户端证书".into(),
            },
            ComplianceItem {
                id: 2,
                name: "最小权限访问控制".into(),
                status: "✅".into(),
                description: "RBAC + 密钥 ACL + 策略绑定".into(),
            },
            ComplianceItem {
                id: 3,
                name: "三权分立".into(),
                status: "✅".into(),
                description: "系统/安全/审计管理员分离".into(),
            },
            ComplianceItem {
                id: 4,
                name: "双人复核".into(),
                status: "✅".into(),
                description: "审批工作流".into(),
            },
            ComplianceItem {
                id: 5,
                name: "密钥分层".into(),
                status: "✅".into(),
                description: "CMK→KEK→DEK 信封加密".into(),
            },
            ComplianceItem {
                id: 6,
                name: "密钥生命周期".into(),
                status: "✅".into(),
                description: "创建→轮换→禁用→归档→销毁".into(),
            },
            ComplianceItem {
                id: 7,
                name: "密钥版本管理".into(),
                status: "✅".into(),
                description: "版本号 + 材料哈希".into(),
            },
            ComplianceItem {
                id: 8,
                name: "依赖索引".into(),
                status: "✅".into(),
                description: "依赖关系追踪，防误删".into(),
            },
            ComplianceItem {
                id: 9,
                name: "传输加密".into(),
                status: "✅".into(),
                description: "TLS 1.3 + mTLS".into(),
            },
            ComplianceItem {
                id: 10,
                name: "存储加密".into(),
                status: "✅".into(),
                description: "SM4-GCM + 信封加密".into(),
            },
            ComplianceItem {
                id: 11,
                name: "完整性保护".into(),
                status: "✅".into(),
                description: "GCM tag + AAD + SM3".into(),
            },
            ComplianceItem {
                id: 12,
                name: "审计日志".into(),
                status: "✅".into(),
                description: "全操作审计记录".into(),
            },
            ComplianceItem {
                id: 13,
                name: "审计防篡改".into(),
                status: "✅".into(),
                description: "SM3 哈希链 + SM2 签名".into(),
            },
            ComplianceItem {
                id: 14,
                name: "可信验证".into(),
                status: "✅".into(),
                description: "二进制 + 配置 SM3 校验".into(),
            },
            ComplianceItem {
                id: 15,
                name: "主机加固".into(),
                status: "✅".into(),
                description: "mlock 锁定 + seccomp/systemd 加固".into(),
            },
            ComplianceItem {
                id: 16,
                name: "高可用".into(),
                status: "✅".into(),
                description: "优雅关闭 + systemd 自动重启".into(),
            },
            ComplianceItem {
                id: 17,
                name: "灾难恢复".into(),
                status: "✅".into(),
                description: "Seed 备份 + 密钥导出导入".into(),
            },
            ComplianceItem {
                id: 18,
                name: "外部密码模块".into(),
                status: "✅".into(),
                description: "PKCS#11 / SDF 接口".into(),
            },
            ComplianceItem {
                id: 19,
                name: "集中管控".into(),
                status: "✅".into(),
                description: "Syslog 审计 + Prometheus 指标".into(),
            },
            ComplianceItem {
                id: 20,
                name: "合规证据包".into(),
                status: "✅".into(),
                description: "证据导出 + 自评报告".into(),
            },
        ],
    };
    let mut all_items = report.items;
    all_items.extend(level4_items);
    let report = ComplianceReport {
        items: all_items,
        ..report
    };
    let report_json = serde_json::to_string_pretty(&report)?;
    std::fs::write(output_dir.join("compliance_report.json"), &report_json)?;

    tracing::info!("合规证据包已导出至: {}", output_dir.display());
    Ok(())
}
