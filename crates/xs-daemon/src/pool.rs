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

    /// 从活跃列表移除指定 id（句柄被销毁、不回池时调用）。
    pub async fn discard(&self, id: &str) {
        let mut inner = self.inner.lock().await;
        inner.active.retain(|x| x != id);
        debug!("discard 移除活跃记录: {id}");
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
    use serial_test::serial;
    use std::path::PathBuf;

    const MINIMAL_CONFIG: &str = r#"
min_assurance = "A-"
allow_io_uring = false
"#;

    /// D2 修复配套：初始化 tracing subscriber（幂等，重复调用安全）。
    /// Sandbox::run 的审计判定（no-record => no-execute）要求 subscriber 可用。
    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with_target(false)
            .try_init();
    }

    fn true_cmd() -> xs_api::SandboxCommand {
        xs_api::SandboxCommand {
            program: PathBuf::from("/bin/true"),
            args: vec![],
            env: vec![],
        }
    }

    #[tokio::test]
    #[serial]
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

    #[tokio::test]
    #[serial]
    async fn pool_acquire_run_release_chain() {
        init_tracing();
        let pool = SandboxPool::new(PoolConfig::default());
        pool.warmup(1, "test-tenant", MINIMAL_CONFIG)
            .await
            .expect("warmup");

        // acquire：idle 弹出
        let mut h = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire");
        let stats = pool.stats().await;
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.active, 1);

        // run：沙箱内执行真实命令
        let status = h.sandbox.run(true_cmd()).expect("run /bin/true");
        assert!(matches!(status, xs_api::ExitStatus::Exited(0)));
        h.command_count += 1;

        // release：未过期且池未满，回池复用
        pool.release(h).await;
        let stats = pool.stats().await;
        assert_eq!(stats.idle, 1);
        assert_eq!(stats.active, 0);

        // 再次 acquire 应复用同一沙箱（command_count 保留）
        let h2 = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("re-acquire");
        assert_eq!(h2.command_count, 1, "复用的沙箱应保留 command_count");
    }

    #[tokio::test]
    #[serial]
    async fn pool_release_expired_handle_dropped() {
        let pool = SandboxPool::new(PoolConfig::default());
        let mut h = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire");
        // 通过 max_commands 强制过期
        h.max_commands = 1;
        h.command_count = 1;
        assert!(h.is_expired());

        pool.release(h).await;
        let stats = pool.stats().await;
        assert_eq!(stats.idle, 0, "过期句柄不应回池");
        assert_eq!(stats.active, 0);
    }

    #[tokio::test]
    #[serial]
    async fn pool_release_full_pool_drops_handle() {
        let config = PoolConfig {
            max_size: 1,
            ..PoolConfig::default()
        };
        let pool = SandboxPool::new(config);
        pool.warmup(1, "test-tenant", MINIMAL_CONFIG)
            .await
            .expect("warmup");

        let h1 = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire h1");
        // idle 已空，h2 动态创建
        let h2 = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire h2");

        pool.release(h1).await; // idle 0 < max_size 1，回池
        pool.release(h2).await; // idle 1 >= max_size 1，丢弃

        let stats = pool.stats().await;
        assert_eq!(stats.idle, 1, "池满时多余句柄应被丢弃");
        assert_eq!(stats.active, 0);
    }

    #[tokio::test]
    #[serial]
    async fn pool_handle_expiry_logic() {
        let pool = SandboxPool::new(PoolConfig::default());
        let mut h = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire");
        assert!(!h.is_expired(), "新句柄不应过期");

        // max_commands 触发过期
        h.command_count = h.max_commands;
        assert!(h.is_expired(), "命令数达上限应过期");

        // TTL 触发过期
        let mut h2 = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire h2");
        h2.ttl_secs = 1;
        h2.created_at = SystemTime::now() - Duration::from_secs(2);
        assert!(h2.is_expired(), "超过 TTL 应过期");
    }

    #[tokio::test]
    #[serial]
    async fn pool_gc_removes_expired_handles() {
        let config = PoolConfig {
            gc_interval_secs: 1,
            default_ttl_secs: 2,
            ..PoolConfig::default()
        };
        let pool = Arc::new(SandboxPool::new(config));
        pool.warmup(1, "test-tenant", MINIMAL_CONFIG)
            .await
            .expect("warmup");
        assert_eq!(pool.stats().await.idle, 1);

        pool.clone().start_gc();
        // 等待 TTL 过期 + 至少一次 GC 周期
        tokio::time::sleep(Duration::from_millis(3500)).await;
        assert_eq!(pool.stats().await.idle, 0, "GC 应清理过期空闲沙箱");
    }
}
