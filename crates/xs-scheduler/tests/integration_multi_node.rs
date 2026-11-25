// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! 调度器多节点集成测试：故障摘除、负载再分配、心跳超时、并发安全。

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use tonic::IntoRequest;
use xs_scheduler::node::{NodeRegistry, HEARTBEAT_TIMEOUT};
use xs_scheduler::scheduler_proto::{
    scheduler_service_server::SchedulerService, AllocateSandboxRequest, DeregisterNodeRequest,
    HeartbeatRequest, NodeLoad, RegisterNodeRequest,
};
use xs_scheduler::service::SchedulerServiceImpl;

// ── 测试辅助 ──

fn svc() -> SchedulerServiceImpl {
    SchedulerServiceImpl {
        registry: NodeRegistry::new(),
        scheduler_id: "test-scheduler".to_string(),
        gc_lock: Arc::new(Mutex::new(())),
    }
}

fn node_load(cpu: f64, mem: f64, active: u32, idle: u32) -> NodeLoad {
    NodeLoad {
        cpu_percent: cpu,
        mem_percent: mem,
        active_sandboxes: active,
        idle_sandboxes: idle,
        uptime_secs: 0,
    }
}

async fn register_node(svc: &SchedulerServiceImpl, id: &str, addr: &str, max: u32) {
    svc.register_node(
        RegisterNodeRequest {
            node_id: id.to_string(),
            address: addr.to_string(),
            max_sandboxes: max,
            version: "1.0.11".to_string(),
        }
        .into_request(),
    )
    .await
    .unwrap();
}

async fn send_heartbeat(
    svc: &SchedulerServiceImpl,
    id: &str,
    cpu: f64,
    mem: f64,
    active: u32,
    idle: u32,
) {
    svc.heartbeat(
        HeartbeatRequest {
            node_id: id.to_string(),
            load: Some(node_load(cpu, mem, active, idle)),
        }
        .into_request(),
    )
    .await
    .unwrap();
}

async fn allocate(svc: &SchedulerServiceImpl) -> (String, String, String) {
    let resp = svc
        .allocate_sandbox(
            AllocateSandboxRequest {
                tenant_id: "demo".to_string(),
                config_toml: String::new(),
                ttl_secs: 3600,
                max_commands: 100,
            }
            .into_request(),
        )
        .await
        .unwrap()
        .into_inner();
    (resp.node_id, resp.node_address, resp.error)
}

// ── 故障摘除：节点心跳超时后被 GC 清理，分配只选健康节点 ──

#[tokio::test]
async fn fault_isolation_gc_removes_stale_node() {
    let svc = svc();

    register_node(&svc, "node-a", "10.0.0.1:50051", 16).await;
    register_node(&svc, "node-b", "10.0.0.2:50051", 16).await;
    send_heartbeat(&svc, "node-a", 20.0, 30.0, 3, 5).await;
    send_heartbeat(&svc, "node-b", 25.0, 35.0, 4, 6).await;
    assert_eq!(svc.registry.len().await, 2);

    // 手动将 node-b 标记为心跳超时
    svc.registry
        .set_last_heartbeat_for_test(
            "node-b",
            SystemTime::now() - HEARTBEAT_TIMEOUT - Duration::from_secs(1),
        )
        .await;

    // GC 应摘除 node-b
    let removed = svc.registry.gc_stale().await;
    assert_eq!(removed, 1);
    assert_eq!(svc.registry.len().await, 1);

    // 健康节点只剩 node-a
    let healthy = svc.registry.list_healthy().await;
    assert_eq!(healthy.len(), 1);
    assert_eq!(healthy[0].id, "node-a");
}

#[tokio::test]
async fn allocate_only_returns_healthy_node_after_partial_failure() {
    let svc = svc();

    register_node(&svc, "node-a", "10.0.0.1:50051", 16).await;
    register_node(&svc, "node-b", "10.0.0.2:50051", 16).await;
    send_heartbeat(&svc, "node-a", 20.0, 30.0, 3, 5).await;
    send_heartbeat(&svc, "node-b", 25.0, 35.0, 4, 6).await;

    // node-a 负载更低，应优先分配
    let (id, _, err) = allocate(&svc).await;
    assert_eq!(id, "node-a");
    assert!(err.is_empty());

    // 模拟 node-a 故障（心跳超时）
    svc.registry
        .set_last_heartbeat_for_test(
            "node-a",
            SystemTime::now() - HEARTBEAT_TIMEOUT - Duration::from_secs(1),
        )
        .await;
    svc.registry.gc_stale().await;

    // 再次分配，只剩 node-b
    let (id, _, err) = allocate(&svc).await;
    assert_eq!(id, "node-b");
    assert!(err.is_empty());
}

#[tokio::test]
async fn allocate_returns_error_when_all_nodes_unhealthy() {
    let svc = svc();

    register_node(&svc, "node-x", "10.0.0.1:50051", 16).await;
    send_heartbeat(&svc, "node-x", 10.0, 10.0, 1, 15).await;

    // 标记超时
    svc.registry
        .set_last_heartbeat_for_test(
            "node-x",
            SystemTime::now() - HEARTBEAT_TIMEOUT - Duration::from_secs(1),
        )
        .await;
    svc.registry.gc_stale().await;

    let (id, _, err) = allocate(&svc).await;
    assert!(id.is_empty());
    assert_eq!(err, "无可用节点");
}

// ── 负载再分配：高负载节点不被选中 ──

#[tokio::test]
async fn load_aware_allocation_prefers_low_load_node() {
    let svc = svc();

    register_node(&svc, "node-hot", "10.0.0.1:50051", 16).await;
    send_heartbeat(&svc, "node-hot", 95.0, 90.0, 14, 2).await;

    register_node(&svc, "node-cool", "10.0.0.2:50051", 16).await;
    send_heartbeat(&svc, "node-cool", 10.0, 15.0, 2, 14).await;

    let (id, _, _) = allocate(&svc).await;
    assert_eq!(id, "node-cool");
}

#[tokio::test]
async fn load_rebalance_after_usage_change() {
    let svc = svc();

    register_node(&svc, "node-a", "10.0.0.1:50051", 16).await;
    send_heartbeat(&svc, "node-a", 20.0, 20.0, 4, 12).await;

    register_node(&svc, "node-b", "10.0.0.2:50051", 16).await;
    send_heartbeat(&svc, "node-b", 50.0, 50.0, 8, 8).await;

    // 首次分配 → node-a（负载更低）
    let (id, _, _) = allocate(&svc).await;
    assert_eq!(id, "node-a");

    // node-a 负载上升，node-b 下降
    send_heartbeat(&svc, "node-a", 90.0, 90.0, 15, 1).await;
    send_heartbeat(&svc, "node-b", 5.0, 10.0, 1, 15).await;

    // 二次分配 → node-b
    let (id, _, _) = allocate(&svc).await;
    assert_eq!(id, "node-b");
}

// ── 并发注册 / 分配安全 ──

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_register_and_allocate() {
    let svc = Arc::new(svc());

    // 并发注册 5 个节点
    let mut handles = Vec::new();
    for i in 0..5 {
        let svc = svc.clone();
        handles.push(tokio::spawn(async move {
            register_node(&svc, &format!("node-{i}"), &format!("10.0.0.{i}:50051"), 16).await;
            send_heartbeat(&svc, &format!("node-{i}"), 10.0 * i as f64, 10.0, i, 16 - i).await;
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(svc.registry.len().await, 5);

    // 并发 allocate 10 次
    let mut alloc_handles = Vec::new();
    for _ in 0..10 {
        let svc = svc.clone();
        alloc_handles.push(tokio::spawn(async move { allocate(&svc).await }));
    }

    for h in alloc_handles {
        let (id, _, err) = h.await.unwrap();
        assert!(!id.is_empty());
        assert!(err.is_empty());
    }
}

// ── 注销后不再参与分配 ──

#[tokio::test]
async fn deregister_removes_from_allocation_pool() {
    let svc = svc();

    register_node(&svc, "keep", "10.0.0.1:50051", 16).await;
    register_node(&svc, "remove", "10.0.0.2:50051", 16).await;
    send_heartbeat(&svc, "keep", 30.0, 30.0, 4, 8).await;
    send_heartbeat(&svc, "remove", 10.0, 10.0, 2, 14).await;

    // remove 负载更低，优先被选
    let (id, _, _) = allocate(&svc).await;
    assert_eq!(id, "remove");

    // 注销 remove
    svc.deregister_node(
        DeregisterNodeRequest {
            node_id: "remove".to_string(),
        }
        .into_request(),
    )
    .await
    .unwrap();

    // 只剩 keep
    let (id, _, _) = allocate(&svc).await;
    assert_eq!(id, "keep");
    assert_eq!(svc.registry.len().await, 1);
}
