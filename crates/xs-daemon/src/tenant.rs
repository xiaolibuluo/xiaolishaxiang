// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! 租户配置：TOML 加载、Bearer token 校验、mtime 轮询热加载。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{info, warn};
use xs_policy::Policy;

/// 单个租户的配额配置。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantQuota {
    /// 最大并发沙箱数（0=不限制）。
    #[serde(default = "default_max_sandboxes")]
    pub max_sandboxes: u32,
    /// 单沙箱最大命令数（0=使用池默认值）。
    #[serde(default)]
    pub max_commands_per_sandbox: u64,
}

const fn default_max_sandboxes() -> u32 {
    16
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self {
            max_sandboxes: default_max_sandboxes(),
            max_commands_per_sandbox: 0,
        }
    }
}

/// 单个租户配置（对应 tenants/{tenant_id}.toml）。
#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    /// Bearer token 的 SHA-256 十六进制哈希（不存明文）。
    pub token_sha256: String,
    #[serde(default)]
    pub quota: TenantQuota,
    /// 内联策略表；缺省为默认全放行策略。
    #[serde(default)]
    pub policy: Policy,
}

impl TenantConfig {
    /// 校验给定明文 token 是否匹配（SHA-256 + 常量时间比较）。
    #[must_use]
    pub fn verify_token(&self, token: &str) -> bool {
        let digest = Sha256::digest(token.as_bytes());
        let hex = to_hex(&digest);
        constant_time_eq(hex.as_bytes(), self.token_sha256.trim().as_bytes())
    }
}

/// 对字节串做 lowercase hex 编码（避免引入 hex crate）。
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 常量时间比较，防时序侧信道。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 租户注册表：扫描目录加载全部租户配置，支持 mtime 轮询热加载。
pub struct TenantRegistry {
    dir: PathBuf,
    inner: RwLock<RegistryInner>,
    reload_interval: Duration,
}

struct RegistryInner {
    /// tenant_id -> (配置, 文件 mtime)
    tenants: HashMap<String, (Arc<TenantConfig>, SystemTime)>,
    last_scan: SystemTime,
}

impl TenantRegistry {
    /// 创建注册表并立即执行首次加载。
    ///
    /// 目录不存在时返回带 0 租户的注册表（warn 降级，不 panic）。
    pub async fn load(dir: impl Into<PathBuf>, reload_interval_secs: u64) -> Arc<Self> {
        let registry = Arc::new(Self {
            dir: dir.into(),
            inner: RwLock::new(RegistryInner {
                tenants: HashMap::new(),
                last_scan: SystemTime::UNIX_EPOCH,
            }),
            reload_interval: Duration::from_secs(reload_interval_secs),
        });
        registry.reload().await;
        registry
    }

    /// 扫描目录，加载/更新 mtime 变化的租户配置文件。
    pub async fn reload(&self) {
        let mut inner = self.inner.write().await;
        let dir = self.dir.clone();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                if inner.tenants.is_empty() {
                    warn!("租户目录不可读（0 租户运行）: {} err={e}", dir.display());
                } else {
                    warn!(
                        "租户目录读取失败（沿用现有配置）: {} err={e}",
                        dir.display()
                    );
                }
                inner.last_scan = SystemTime::now();
                return;
            }
        };

        let mut seen = std::collections::HashSet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let Some(tenant_id) = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            seen.insert(tenant_id.clone());

            let mtime = entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);

            // mtime 未变化则跳过（热加载增量）
            if let Some((_, existing_mtime)) = inner.tenants.get(&tenant_id) {
                if *existing_mtime == mtime {
                    continue;
                }
            }

            match load_tenant_file(&path) {
                Ok(cfg) => {
                    info!("租户配置已加载: {tenant_id} ({})", path.display());
                    inner.tenants.insert(tenant_id, (Arc::new(cfg), mtime));
                }
                Err(e) => {
                    warn!("租户配置加载失败（跳过）: {} err={e}", path.display());
                }
            }
        }

        // 移除已删除的租户文件
        inner.tenants.retain(|id, _| seen.contains(id));
        inner.last_scan = SystemTime::now();
    }

    /// 按 tenant_id 查询配置；必要时触发周期性重载。
    pub async fn get(&self, tenant_id: &str) -> Option<Arc<TenantConfig>> {
        self.maybe_reload().await;
        let inner = self.inner.read().await;
        inner.tenants.get(tenant_id).map(|(cfg, _)| cfg.clone())
    }

    /// 当前已加载租户数。
    pub async fn len(&self) -> usize {
        let inner = self.inner.read().await;
        inner.tenants.len()
    }

    /// 是否无已加载租户。
    pub async fn is_empty(&self) -> bool {
        let inner = self.inner.read().await;
        inner.tenants.is_empty()
    }

    /// 距上次扫描超过 reload_interval 时执行增量重载。
    async fn maybe_reload(&self) {
        let need = {
            let inner = self.inner.read().await;
            inner
                .last_scan
                .elapsed()
                .is_ok_and(|e| e >= self.reload_interval)
        };
        if need {
            self.reload().await;
        }
    }

    /// 启动后台周期重载任务。
    pub fn start_hot_reload(self: &Arc<Self>) {
        let registry = self.clone();
        let interval = self.reload_interval;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                registry.reload().await;
            }
        });
    }
}

/// 从磁盘解析单个租户 TOML 文件。
fn load_tenant_file(path: &Path) -> Result<TenantConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("读取失败: {e}"))?;
    let cfg: TenantConfig = toml::from_str(&content).map_err(|e| format!("TOML 解析失败: {e}"))?;
    if cfg.token_sha256.trim().is_empty() {
        return Err("token_sha256 不能为空".to_string());
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn sha256_hex(s: &str) -> String {
        to_hex(&Sha256::digest(s.as_bytes()))
    }

    fn write_tenant(dir: &Path, name: &str, token: &str) -> PathBuf {
        let path = dir.join(format!("{name}.toml"));
        let content = format!(
            r#"
token_sha256 = "{}"

[quota]
max_sandboxes = 4
max_commands_per_sandbox = 100

[policy]
default_action = "allow"
"#,
            sha256_hex(token)
        );
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn token_verify_constant_time() {
        let cfg = TenantConfig {
            token_sha256: sha256_hex("secret-token"),
            quota: TenantQuota::default(),
            policy: Policy::default(),
        };
        assert!(cfg.verify_token("secret-token"));
        assert!(!cfg.verify_token("wrong-token"));
        assert!(!cfg.verify_token(""));
    }

    #[tokio::test]
    #[serial]
    async fn registry_load_and_hot_reload() {
        let dir = std::env::temp_dir().join(format!("xs-tenant-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        write_tenant(&dir, "tenant-a", "token-a");

        let registry = TenantRegistry::load(dir.clone(), 3600).await;
        assert_eq!(registry.len().await, 1);

        let cfg = registry.get("tenant-a").await.expect("tenant-a exists");
        assert!(cfg.verify_token("token-a"));
        assert_eq!(cfg.quota.max_sandboxes, 4);
        assert!(registry.get("unknown").await.is_none());

        // 热加载：新增租户文件后手动 reload
        write_tenant(&dir, "tenant-b", "token-b");
        registry.reload().await;
        assert_eq!(registry.len().await, 2);
        assert!(registry.get("tenant-b").await.is_some());

        // 删除文件后 reload 移除租户
        std::fs::remove_file(dir.join("tenant-a.toml")).unwrap();
        registry.reload().await;
        assert!(registry.get("tenant-a").await.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    #[serial]
    async fn missing_dir_degrades_to_zero_tenants() {
        let registry = TenantRegistry::load("/nonexistent/xs-tenant-dir", 3600).await;
        assert_eq!(registry.len().await, 0);
    }
}
