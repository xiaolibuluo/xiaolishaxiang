// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! xiaolishaxiang 守护进程入口：gRPC API + 沙箱池 + HTTP 健康端点。

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use axum::{extract::State, routing::get, Json, Router};
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use xs_daemon::pool::{PoolConfig, SandboxPool};
use xs_daemon::sandbox_proto::sandbox_service_server::{SandboxService, SandboxServiceServer};
use xs_daemon::sandbox_proto::*;
use xs_daemon::SandboxHandle;

// ── Metrics ──────────────────────────────────────────────────────────

struct Metrics {
    sandbox_created: IntCounter,
    command_total: IntCounter,
    command_errors: IntCounter,
    active_sandboxes: IntGauge,
    registry: Registry,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        let sandbox_created =
            IntCounter::new("xs_sandbox_created_total", "Total sandboxes created").unwrap();
        let command_total = IntCounter::new("xs_command_total", "Total commands executed").unwrap();
        let command_errors =
            IntCounter::new("xs_command_errors_total", "Total command execution errors").unwrap();
        let active_sandboxes =
            IntGauge::new("xs_active_sandboxes", "Number of active sandboxes").unwrap();

        registry
            .register(Box::new(sandbox_created.clone()))
            .unwrap();
        registry.register(Box::new(command_total.clone())).unwrap();
        registry.register(Box::new(command_errors.clone())).unwrap();
        registry
            .register(Box::new(active_sandboxes.clone()))
            .unwrap();

        Self {
            sandbox_created,
            command_total,
            command_errors,
            active_sandboxes,
            registry,
        }
    }
}

// ── HTTP 共享状态 ───────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    pool: Arc<SandboxPool>,
    active: Arc<Mutex<HashMap<String, SandboxHandle>>>,
    start_time: SystemTime,
    metrics: Arc<Metrics>,
}

// ── gRPC 服务实现 ───────────────────────────────────────────────────

#[derive(Clone)]
struct SandboxServiceImpl {
    pool: Arc<SandboxPool>,
    active: Arc<Mutex<HashMap<String, SandboxHandle>>>,
    metrics: Arc<Metrics>,
}

#[tonic::async_trait]
#[allow(clippy::result_large_err)]
impl SandboxService for SandboxServiceImpl {
    type RunCommandStreamStream = std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<RunCommandStreamResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn run_command_stream(
        &self,
        request: Request<RunCommandRequest>,
    ) -> Result<Response<Self::RunCommandStreamStream>, Status> {
        let req = request.into_inner();
        let mut active = self.active.lock().await;
        let handle = active
            .get_mut(&req.sandbox_id)
            .ok_or_else(|| Status::not_found(format!("沙箱 {} 不存在", req.sandbox_id)))?;

        if handle.is_expired() {
            warn!("沙箱 {} 已过期，拒绝流式执行", req.sandbox_id);
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
                self.metrics.command_total.inc();
                let exit_code = match status {
                    xs_api::ExitStatus::Exited(code) => code,
                    xs_api::ExitStatus::Signaled(sig) => {
                        warn!("沙箱 {} 流式命令被信号 {} 终止", req.sandbox_id, sig);
                        -sig
                    }
                };

                let stream = tokio_stream::iter(vec![Ok(RunCommandStreamResponse {
                    payload: Some(run_command_stream_response::Payload::Result(
                        CommandResult {
                            exit_code,
                            latency_us: latency,
                        },
                    )),
                })]);
                Ok(Response::new(Box::pin(stream)))
            }
            Err(e) => {
                self.metrics.command_errors.inc();
                warn!("沙箱 {} 流式命令执行失败: {}", req.sandbox_id, e);
                Err(Status::internal(format!("命令执行失败: {e}")))
            }
        }
    }

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
        let created_at = system_time_to_iso8601(&handle.created_at);
        self.active.lock().await.insert(sandbox_id.clone(), handle);
        self.metrics.sandbox_created.inc();
        self.metrics
            .active_sandboxes
            .set(self.active.lock().await.len() as i64);
        info!("沙箱创建: {sandbox_id} tenant={}", req.tenant_id);
        Ok(Response::new(CreateSandboxResponse {
            sandbox_id,
            created_at,
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
                self.metrics.command_total.inc();
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
                self.metrics.command_errors.inc();
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
                self.metrics.active_sandboxes.set(active.len() as i64);
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
                created_at: system_time_to_iso8601(&h.created_at),
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

// ── 时间戳工具 ─────────────────────────────────────────────────────

fn system_time_to_iso8601(t: &SystemTime) -> String {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // 从 1970-01-01 起计算年月日
    let mut year = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let year_days = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        year += 1;
    }
    let leap = is_leap_year(year);
    let month_days: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u32;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── HTTP 路由处理 ───────────────────────────────────────────────────

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let report = xs_api::health();
    let stats = state.pool.stats().await;
    let active_count = state.active.lock().await.len();
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "sandbox_ok": report.sandbox_ok,
        "pool_active": stats.active + active_count,
        "pool_idle": stats.idle,
        "uptime_secs": state.start_time.elapsed().unwrap_or_default().as_secs(),
    }))
}

async fn ready_handler(State(_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let report = xs_api::health();
    if report.sandbox_ok {
        Json(serde_json::json!({"status": "ready"}))
    } else {
        Json(serde_json::json!({
            "status": "not_ready",
            "reason": "sandbox health check failed"
        }))
    }
}

async fn live_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "alive"}))
}

async fn metrics_handler(State(state): State<Arc<AppState>>) -> String {
    let encoder = TextEncoder::new();
    let metric_families = state.metrics.registry.gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

// ── 入口 ────────────────────────────────────────────────────────────

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

    let active = Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Metrics::new());
    let start_time = SystemTime::now();

    // gRPC server
    let svc = SandboxServiceImpl {
        pool: pool.clone(),
        active: active.clone(),
        metrics: metrics.clone(),
    };

    let addr_grpc: SocketAddr = "0.0.0.0:50051".parse()?;
    info!("gRPC 监听 {addr_grpc}");
    let grpc_server = tonic::transport::Server::builder()
        .add_service(SandboxServiceServer::new(svc))
        .serve(addr_grpc);

    // HTTP server (health / ready / live / metrics)
    let state = Arc::new(AppState {
        pool,
        active,
        start_time,
        metrics,
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/live", get(live_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let addr_http: SocketAddr = "0.0.0.0:3000".parse()?;
    info!("HTTP 监听 {addr_http}");
    let listener = tokio::net::TcpListener::bind(&addr_http).await?;
    let http_server = axum::serve(listener, app);

    tokio::select! {
        r = grpc_server => { r?; }
        r = http_server => { r?; }
    }

    Ok(())
}
