// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! 沙箱池集成测试：并发 acquire/release、限流、生命周期完整链路。
//! 本测试使用真实的 Sandbox 构建与命令执行，验证池在 release 模式下的健壮性。

use serial_test::serial;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use xs_api::SandboxCommand;
use xs_daemon::pool::{PoolConfig, SandboxPool};

const MINIMAL_CONFIG: &str = r#"
min_assurance = "A-"
allow_io_uring = false
"#;

/// D2 修复配套：初始化 tracing subscriber（幂等，重复调用安全）。
/// Sandbox::run 的审计判定（no-record => no-execute）要求 subscriber 可用。
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .try_init();
}

fn true_cmd() -> SandboxCommand {
    SandboxCommand {
        program: PathBuf::from("/bin/true"),
        args: vec![],
        env: vec![],
    }
}

fn exit_cmd(code: i32) -> SandboxCommand {
    SandboxCommand {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".to_string(), format!("exit {code}")],
        env: vec![],
    }
}

fn sleep_cmd(secs: u64) -> SandboxCommand {
    SandboxCommand {
        program: PathBuf::from("/bin/sleep"),
        args: vec![secs.to_string()],
        env: vec![],
    }
}

// ── 并发 acquire/release ──

#[tokio::test]
#[serial]
async fn concurrent_acquire_release_no_panic() {
    init_tracing();
    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    pool.warmup(4, "test-tenant", MINIMAL_CONFIG)
        .await
        .expect("warmup");

    let mut handles = tokio::task::JoinSet::new();
    for i in 0..10 {
        let pool = pool.clone();
        handles.spawn(async move {
            let mut h = pool
                .acquire("test-tenant", MINIMAL_CONFIG)
                .await
                .unwrap_or_else(|_| panic!("task {i}: acquire"));
            let cmd = if i % 2 == 0 { true_cmd() } else { exit_cmd(1) };
            let _ = h.sandbox.run(cmd);
            h.command_count += 1;
            pool.release(h).await;
        });
    }

    while handles.join_next().await.is_some() {}

    let stats = pool.stats().await;
    assert_eq!(stats.active, 0, "所有句柄应已归还");
    assert!(
        stats.total >= 4,
        "池中至少应有 warmup 数量的沙箱（含动态创建的）"
    );
}

// ── 池耗尽后动态创建 ──

#[tokio::test]
#[serial]
async fn pool_exhaustion_creates_dynamic_sandbox() {
    init_tracing();
    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    // 不预热：池为空
    let h = pool
        .acquire("test-tenant", MINIMAL_CONFIG)
        .await
        .expect("动态创建");
    assert!(!h.id.is_empty());

    let stats = pool.stats().await;
    assert_eq!(stats.active, 1);
    assert_eq!(stats.idle, 0);

    // 执行命令验证沙箱可用
    let status = h.sandbox.run(true_cmd()).expect("run");
    assert!(matches!(status, xs_api::ExitStatus::Exited(0)));

    pool.release(h).await;
}

// ── 并发限流：max_size 上限 ──

#[tokio::test]
#[serial]
async fn pool_respects_max_size_on_release() {
    let config = PoolConfig {
        max_size: 3,
        min_idle: 0,
        ..PoolConfig::default()
    };
    let pool = Arc::new(SandboxPool::new(config));

    // 获取 5 个（全部动态创建，超出 max_size）
    let mut acquired = Vec::new();
    for _ in 0..5 {
        let h = pool
            .acquire("test-tenant", MINIMAL_CONFIG)
            .await
            .expect("acquire");
        acquired.push(h);
    }

    // 全部归还：只有前 max_size=3 个应回池
    for h in acquired {
        pool.release(h).await;
    }

    let stats = pool.stats().await;
    assert_eq!(stats.idle, 3, "max_size=3，池中最多保留 3 个空闲");
    assert_eq!(stats.active, 0);
}

// ── 命令执行与退出码透传 ──
// 注：此测试依赖沙箱目录，并行执行时受 getcwd 隔离影响；加 #[serial] 强制串行。

#[tokio::test]
#[serial]
async fn command_exit_code_transparent() {
    init_tracing();
    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    let mut h = pool
        .acquire("test-tenant", MINIMAL_CONFIG)
        .await
        .expect("acquire");

    // sh -c 'exit 0' → 0
    let status = h.sandbox.run(exit_cmd(0)).expect("run exit 0");
    assert!(
        matches!(status, xs_api::ExitStatus::Exited(0)),
        "exit_cmd(0) 应退出 0"
    );

    // sh -c 'exit 1' → 1
    let status = h.sandbox.run(exit_cmd(1)).expect("run exit 1");
    assert!(
        matches!(status, xs_api::ExitStatus::Exited(1)),
        "exit_cmd(1) 应退出 1"
    );

    h.command_count += 2;
    pool.release(h).await;
}

// ── 沙箱过期不回归 ──

#[tokio::test]
#[serial]
async fn expired_sandbox_not_returned_to_pool() {
    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    pool.warmup(1, "test-tenant", MINIMAL_CONFIG)
        .await
        .expect("warmup");

    let mut h = pool
        .acquire("test-tenant", MINIMAL_CONFIG)
        .await
        .expect("acquire");

    // 强制标记过期（命令数超限）
    h.max_commands = 1;
    h.command_count = 1;
    assert!(h.is_expired());

    pool.release(h).await;

    let stats = pool.stats().await;
    assert_eq!(stats.idle, 0, "过期沙箱不应回池");
}

// ── 池 GC 清理 ──

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn gc_cleans_stale_sandboxes() {
    let config = PoolConfig {
        gc_interval_secs: 1,
        default_ttl_secs: 2,
        min_idle: 0,
        ..PoolConfig::default()
    };
    let pool = Arc::new(SandboxPool::new(config));
    pool.warmup(2, "test-tenant", MINIMAL_CONFIG)
        .await
        .expect("warmup");
    assert_eq!(pool.stats().await.idle, 2);

    pool.clone().start_gc();
    // 等待 TTL 过期 + 至少一次 GC
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert_eq!(pool.stats().await.idle, 0, "GC 应清理过期沙箱");
}

// ── 并发 acquire 下统计一致性 ──

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn concurrent_stats_consistent() {
    init_tracing();
    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    pool.warmup(8, "test-tenant", MINIMAL_CONFIG)
        .await
        .expect("warmup");

    let mut handles = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let pool = pool.clone();
        handles.spawn(async move {
            let mut h = pool
                .acquire("test-tenant", MINIMAL_CONFIG)
                .await
                .expect("acquire");
            // 短暂持有模拟工作
            let _ = h.sandbox.run(sleep_cmd(0));
            h.command_count += 1;
            pool.release(h).await;
        });
    }

    while handles.join_next().await.is_some() {}

    let stats = pool.stats().await;
    assert_eq!(stats.active, 0);
    // total 应等于 idle（全部归还）
    assert_eq!(stats.total, stats.idle + stats.active);
}
