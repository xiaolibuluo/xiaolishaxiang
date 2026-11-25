// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! xiaolishaxiang 守护进程入口：gRPC API + 沙箱池。

#![allow(clippy::result_large_err)]

use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

use xs_daemon::pool::{PoolConfig, SandboxPool};
use xs_daemon::sandbox_proto::sandbox_service_server::{SandboxService, SandboxServiceServer};
use xs_daemon::sandbox_proto::*;

/// gRPC 服务实现。
#[derive(Clone)]
struct SandboxServiceImpl {
    pool: Arc<SandboxPool>,
}

#[tonic::async_trait]
#[allow(clippy::result_large_err)]
impl SandboxService for SandboxServiceImpl {
    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let req = request.into_inner();
        let handle = self
            .pool
            .acquire(&req.tenant_id, &req.config_toml)
            .await
            .map_err(|e| Status::internal(format!("创建沙箱失败: {e}")))?;
        let sandbox_id = handle.id.clone();
        let created_at = chrono_now();
        self.pool.release(handle).await;
        Ok(Response::new(CreateSandboxResponse {
            sandbox_id,
            created_at,
        }))
    }

    async fn run_command(
        &self,
        _request: Request<RunCommandRequest>,
    ) -> Result<Response<RunCommandResponse>, Status> {
        Err(Status::unimplemented("RunCommand 待实现"))
    }

    async fn destroy_sandbox(
        &self,
        _request: Request<DestroySandboxRequest>,
    ) -> Result<Response<DestroySandboxResponse>, Status> {
        Err(Status::unimplemented("DestroySandbox 待实现"))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let report = xs_api::health();
        let stats = self.pool.stats().await;
        Ok(Response::new(HealthCheckResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            sandbox_ok: report.sandbox_ok,
            latency_us: report.latency_us,
            rss_kb: report.rss_kb,
            pool_active: stats.active as u32,
            pool_idle: stats.idle as u32,
            uptime_secs: 0,
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse { sandboxes: vec![] }))
    }
}

fn chrono_now() -> String {
    "2026-01-01T00:00:00Z".to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    info!("xiaolishaxiang daemon v{}", env!("CARGO_PKG_VERSION"));

    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    pool.clone().start_gc();
    info!("沙箱池 GC 已启动");

    let addr = "0.0.0.0:50051".parse()?;
    let svc = SandboxServiceImpl { pool };

    info!("gRPC 监听 {addr}");
    tonic::transport::Server::builder()
        .add_service(SandboxServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
