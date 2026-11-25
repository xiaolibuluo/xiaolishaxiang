// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! xiaolishaxiang 守护进程入口：gRPC API + 沙箱池。

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use xs_daemon::pool::{PoolConfig, SandboxPool};
use xs_daemon::sandbox_proto::sandbox_service_server::{SandboxService, SandboxServiceServer};
use xs_daemon::sandbox_proto::*;
use xs_daemon::SandboxHandle;

/// gRPC 服务实现。
#[derive(Clone)]
struct SandboxServiceImpl {
    pool: Arc<SandboxPool>,
    active: Arc<Mutex<HashMap<String, SandboxHandle>>>,
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
        self.active.lock().await.insert(sandbox_id.clone(), handle);
        info!("沙箱创建: {sandbox_id} tenant={}", req.tenant_id);
        Ok(Response::new(CreateSandboxResponse {
            sandbox_id,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        }))
    }

    async fn run_command(
        &self,
        request: Request<RunCommandRequest>,
    ) -> Result<Response<RunCommandResponse>, Status> {
        let req = request.into_inner();
        let mut active = self.active.lock().await;
        let handle = active
            .get_mut(&req.sandbox_id)
            .ok_or_else(|| Status::not_found(format!("沙箱 {} 不存在", req.sandbox_id)))?;

        if handle.is_expired() {
            warn!("沙箱 {} 已过期，拒绝执行", req.sandbox_id);
            return Err(Status::resource_exhausted("沙箱已过期"));
        }

        let program = PathBuf::from(&req.program);
        let sargs: Vec<String> = req.args.clone();
        let env_pairs: Vec<(String, String)> = req
            .env
            .iter()
            .filter_map(|e| e.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let cmd = xs_api::SandboxCommand {
            program,
            args: sargs,
            env: env_pairs,
        };

        let t0 = std::time::Instant::now();
        let result = handle.sandbox.run(cmd);
        let latency = t0.elapsed().as_micros() as u64;

        handle.command_count += 1;

        match result {
            Ok(status) => {
                let exit_code = match status {
                    xs_api::ExitStatus::Exited(code) => code,
                    xs_api::ExitStatus::Signaled(sig) => {
                        warn!("沙箱 {} 命令被信号 {} 终止", req.sandbox_id, sig);
                        -sig
                    }
                };
                Ok(Response::new(RunCommandResponse {
                    exit_code,
                    stdout: String::new(),
                    stderr: String::new(),
                    latency_us: latency,
                }))
            }
            Err(e) => {
                warn!("沙箱 {} 命令执行失败: {}", req.sandbox_id, e);
                Err(Status::internal(format!("命令执行失败: {e}")))
            }
        }
    }

    async fn destroy_sandbox(
        &self,
        request: Request<DestroySandboxRequest>,
    ) -> Result<Response<DestroySandboxResponse>, Status> {
        let req = request.into_inner();
        let mut active = self.active.lock().await;
        match active.remove(&req.sandbox_id) {
            Some(handle) => {
                info!(
                    "沙箱销毁: {} commands={}",
                    req.sandbox_id, handle.command_count
                );
                Ok(Response::new(DestroySandboxResponse { success: true }))
            }
            None => Err(Status::not_found(format!("沙箱 {} 不存在", req.sandbox_id))),
        }
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let report = xs_api::health();
        let stats = self.pool.stats().await;
        let active_count = self.active.lock().await.len();
        Ok(Response::new(HealthCheckResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            sandbox_ok: report.sandbox_ok,
            latency_us: report.latency_us,
            rss_kb: report.rss_kb,
            pool_active: (stats.active + active_count) as u32,
            pool_idle: stats.idle as u32,
            uptime_secs: 0,
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let active = self.active.lock().await;
        let sandboxes: Vec<SandboxInfo> = active
            .iter()
            .map(|(id, h)| SandboxInfo {
                sandbox_id: id.clone(),
                tenant_id: h.tenant_id.clone(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                command_count: h.command_count,
                state: if h.is_expired() {
                    "draining".to_string()
                } else {
                    "idle".to_string()
                },
            })
            .collect();
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }
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
    let svc = SandboxServiceImpl {
        pool,
        active: Arc::new(Mutex::new(HashMap::new())),
    };

    info!("gRPC 监听 {addr}");
    tonic::transport::Server::builder()
        .add_service(SandboxServiceServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}
