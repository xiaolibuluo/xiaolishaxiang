// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! 沙箱池：预热 N 个已建域 Sandbox，acquire/release 实现零冷启动。

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;
use xs_api::Sandbox;

use crate::{PoolStats, SandboxHandle};

/// 沙箱池配置。
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub min_idle: usize,
    pub max_size: usize,
    pub gc_interval_secs: u64,
    pub default_ttl_secs: u64,
    pub default_max_commands: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_idle: 4,
            max_size: 128,
            gc_interval_secs: 30,
            default_ttl_secs: 3600,
            default_max_commands: 1000,
        }
    }
}

struct PoolInner {
    idle: VecDeque<SandboxHandle>,
    active: Vec<String>,
    config: PoolConfig,
}

pub struct SandboxPool {
    inner: Arc<Mutex<PoolInner>>,
}

impl SandboxPool {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                idle: VecDeque::new(),
                active: Vec::new(),
                config,
            })),
        }
    }

    pub async fn warmup(&self, n: usize, tenant_id: &str, config_toml: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        for _ in 0..n {
            let sb = build_sandbox(config_toml).map_err(|e| format!("warmup: {e}"))?;
            let handle = SandboxHandle {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                sandbox: sb,
                created_at: SystemTime::now(),
                command_count: 0,
                max_commands: inner.config.default_max_commands,
                ttl_secs: inner.config.default_ttl_secs,
            };
            inner.idle.push_back(handle);
        }
        info!("warmup 完成: {n} 个沙箱就绪");
        Ok(())
    }

    pub async fn acquire(
        &self,
        tenant_id: &str,
        config_toml: &str,
    ) -> Result<SandboxHandle, String> {
        let mut inner = self.inner.lock().await;
        if let Some(handle) = inner.idle.pop_front() {
            inner.active.push(handle.id.clone());
            debug!("acquire from pool: {}", handle.id);
            Ok(handle)
        } else {
            let sb = build_sandbox(config_toml).map_err(|e| format!("acquire: {e}"))?;
            let handle = SandboxHandle {
                id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.to_string(),
                sandbox: sb,
                created_at: SystemTime::now(),
                command_count: 0,
                max_commands: inner.config.default_max_commands,
                ttl_secs: inner.config.default_ttl_secs,
            };
            inner.active.push(handle.id.clone());
            debug!("acquire 动态创建: {}", handle.id);
            Ok(handle)
        }
    }

    pub async fn release(&self, handle: SandboxHandle) {
        let mut inner = self.inner.lock().await;
        inner.active.retain(|id| id != &handle.id);
        if handle.is_expired() || inner.idle.len() >= inner.config.max_size {
            debug!("release 丢弃 {}（过期或池满）", handle.id);
        } else {
            debug!("release 回池: {}", handle.id);
            inner.idle.push_back(handle);
        }
    }

    pub async fn stats(&self) -> PoolStats {
        let inner = self.inner.lock().await;
        PoolStats {
            total: inner.idle.len() + inner.active.len(),
            idle: inner.idle.len(),
            active: inner.active.len(),
        }
    }

    pub fn start_gc(self: Arc<Self>) {
        tokio::spawn(async move {
            let interval = {
                let inner = self.inner.lock().await;
                Duration::from_secs(inner.config.gc_interval_secs)
            };
            loop {
                tokio::time::sleep(interval).await;
                let mut inner = self.inner.lock().await;
                let before = inner.idle.len();
                inner.idle.retain(|h| !h.is_expired());
                let removed = before - inner.idle.len();
                if removed > 0 {
                    info!("GC 清理 {removed} 个过期沙箱");
                }
            }
        });
    }
}

fn build_sandbox(config_toml: &str) -> Result<Sandbox, xs_core::XsError> {
    let cfg = xs_core::SandboxConfig::from_toml(config_toml)?;
    xs_api::build(&cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_CONFIG: &str = r#"
min_assurance = "A-"
allow_io_uring = false
"#;

    #[tokio::test]
    async fn pool_warmup_and_acquire() {
        let pool = SandboxPool::new(PoolConfig::default());
        pool.warmup(2, "test-tenant", MINIMAL_CONFIG)
            .await
            .expect("warmup");
        let stats = pool.stats().await;
        assert_eq!(stats.total, 2);

        let h = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire");
        assert!(!h.id.is_empty());
    }
}
