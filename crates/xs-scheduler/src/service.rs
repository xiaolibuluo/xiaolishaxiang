// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! SchedulerService gRPC 实现：节点注册/心跳、负载均衡分配。

use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::allocate::select_best_node;
use crate::node::{NodeInfo, NodeRegistry};
use crate::scheduler_proto::scheduler_service_server::SchedulerService;
use crate::scheduler_proto::*;

/// SchedulerService 的 gRPC 实现。
#[derive(Clone)]
pub struct SchedulerServiceImpl {
    pub registry: NodeRegistry,
    pub scheduler_id: String,
    /// 用于防并发 GC（避免 tokio::spawn 中并发 mut 写竞态）。
    pub gc_lock: Arc<Mutex<()>>,
}

#[tonic::async_trait]
impl SchedulerService for SchedulerServiceImpl {
    async fn register_node(
        &self,
        request: Request<RegisterNodeRequest>,
    ) -> Result<Response<RegisterNodeResponse>, Status> {
        let req = request.into_inner();
        let info = NodeInfo {
            id: req.node_id.clone(),
            address: req.address.clone(),
            version: req.version.clone(),
            max_sandboxes: req.max_sandboxes,
            load: NodeLoad {
                cpu_percent: 0.0,
                mem_percent: 0.0,
                active_sandboxes: 0,
                idle_sandboxes: 0,
                uptime_secs: 0,
            },
            registered_at: SystemTime::now(),
            last_heartbeat: SystemTime::now(),
        };
        self.registry
            .register(info)
            .await
            .map_err(Status::already_exists)?;
        Ok(Response::new(RegisterNodeResponse {
            accepted: true,
            scheduler_id: self.scheduler_id.clone(),
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let req = request.into_inner();
        self.registry
            .heartbeat(&req.node_id, req.load.unwrap_or_default())
            .await
            .map_err(Status::not_found)?;
        Ok(Response::new(HeartbeatResponse { acknowledged: true }))
    }

    async fn deregister_node(
        &self,
        request: Request<DeregisterNodeRequest>,
    ) -> Result<Response<DeregisterNodeResponse>, Status> {
        let req = request.into_inner();
        self.registry
            .deregister(&req.node_id)
            .await
            .map_err(Status::not_found)?;
        Ok(Response::new(DeregisterNodeResponse { success: true }))
    }

    async fn allocate_sandbox(
        &self,
        request: Request<AllocateSandboxRequest>,
    ) -> Result<Response<AllocateSandboxResponse>, Status> {
        let req = request.into_inner();
        let healthy = self.registry.list_healthy().await;
        if healthy.is_empty() {
            return Ok(Response::new(AllocateSandboxResponse {
                node_id: String::new(),
                node_address: String::new(),
                sandbox_id: String::new(),
                created_at: String::new(),
                error: "无可用节点".to_string(),
            }));
        }

        match select_best_node(&healthy) {
            Some(best) => {
                info!(
                    node_id = %best.id,
                    address = %best.address,
                    tenant_id = %req.tenant_id,
                    "分配沙箱到节点"
                );
                Ok(Response::new(AllocateSandboxResponse {
                    node_id: best.id,
                    node_address: best.address,
                    sandbox_id: String::new(),
                    created_at: String::new(),
                    error: String::new(),
                }))
            }
            None => Ok(Response::new(AllocateSandboxResponse {
                node_id: String::new(),
                node_address: String::new(),
                sandbox_id: String::new(),
                created_at: String::new(),
                error: "负载均衡无可用节点".to_string(),
            })),
        }
    }
}

impl SchedulerServiceImpl {
    /// 启动后台 GC 任务：每 10s 清理 15s 无心跳的超时节点。
    pub fn start_gc(self: &Arc<Self>) {
        let svc = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let _lock = svc.gc_lock.lock().await;
                let removed = svc.registry.gc_stale().await;
                if removed > 0 {
                    warn!("GC 摘除 {removed} 个超时节点");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::IntoRequest;

    fn test_svc() -> SchedulerServiceImpl {
        SchedulerServiceImpl {
            registry: NodeRegistry::new(),
            scheduler_id: "test-scheduler".to_string(),
            gc_lock: Arc::new(Mutex::new(())),
        }
    }

    #[tokio::test]
    async fn register_and_heartbeat_cycle() {
        let svc = test_svc();
        let resp = svc
            .register_node(
                RegisterNodeRequest {
                    node_id: "n1".to_string(),
                    address: "127.0.0.1:50051".to_string(),
                    max_sandboxes: 8,
                    version: "1.0.11".to_string(),
                }
                .into_request(),
            )
            .await
            .unwrap()
            .into_inner();
        assert!(resp.accepted);
        assert_eq!(resp.scheduler_id, "test-scheduler");

        svc.heartbeat(
            HeartbeatRequest {
                node_id: "n1".to_string(),
                load: Some(NodeLoad {
                    cpu_percent: 25.0,
                    mem_percent: 50.0,
                    active_sandboxes: 3,
                    idle_sandboxes: 5,
                    uptime_secs: 60,
                }),
            }
            .into_request(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn duplicate_register_rejected() {
        let svc = test_svc();
        let req = RegisterNodeRequest {
            node_id: "n1".to_string(),
            address: "127.0.0.1:50051".to_string(),
            max_sandboxes: 8,
            version: "1.0.11".to_string(),
        };
        svc.register_node(req.clone().into_request()).await.unwrap();
        let result = svc.register_node(req.into_request()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn allocate_returns_node_on_healthy() {
        let svc = test_svc();
        svc.register_node(
            RegisterNodeRequest {
                node_id: "cool".to_string(),
                address: "10.0.0.1:50051".to_string(),
                max_sandboxes: 16,
                version: "1.0.11".to_string(),
            }
            .into_request(),
        )
        .await
        .unwrap();
        svc.heartbeat(
            HeartbeatRequest {
                node_id: "cool".to_string(),
                load: Some(NodeLoad {
                    cpu_percent: 10.0,
                    mem_percent: 20.0,
                    active_sandboxes: 2,
                    idle_sandboxes: 6,
                    uptime_secs: 3600,
                }),
            }
            .into_request(),
        )
        .await
        .unwrap();

        let resp = svc
            .allocate_sandbox(
                AllocateSandboxRequest {
                    tenant_id: "demo".to_string(),
                    config_toml: "".to_string(),
                    ttl_secs: 3600,
                    max_commands: 100,
                }
                .into_request(),
            )
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.node_id, "cool");
        assert_eq!(resp.node_address, "10.0.0.1:50051");
        assert!(resp.error.is_empty());
    }

    #[tokio::test]
    async fn allocate_empty_when_no_nodes() {
        let svc = test_svc();
        let resp = svc
            .allocate_sandbox(
                AllocateSandboxRequest {
                    tenant_id: "demo".to_string(),
                    config_toml: "".to_string(),
                    ttl_secs: 3600,
                    max_commands: 100,
                }
                .into_request(),
            )
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.error, "无可用节点");
    }

    #[tokio::test]
    async fn deregister_removes_node() {
        let svc = test_svc();
        svc.register_node(
            RegisterNodeRequest {
                node_id: "n1".to_string(),
                address: "127.0.0.1:50051".to_string(),
                max_sandboxes: 8,
                version: "1.0.11".to_string(),
            }
            .into_request(),
        )
        .await
        .unwrap();

        svc.deregister_node(
            DeregisterNodeRequest {
                node_id: "n1".to_string(),
            }
            .into_request(),
        )
        .await
        .unwrap();
        assert_eq!(svc.registry.len().await, 0);
    }
}
