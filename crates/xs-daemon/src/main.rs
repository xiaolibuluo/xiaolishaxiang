// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! xiaolishaxiang 守护进程入口：gRPC API + 沙箱池 + HTTP 健康端点。

#![allow(clippy::result_large_err)]

// allow-file-length: daemon 服务处理器与 HTTP 端点聚合入口，保持单文件内聚
/// 数字水印（源码层）：小黎的部落。
const XIAOLISHAXIANG_WATERMARK_TEXT: &str = "小黎的部落（www.qingdujian.com）";
/// 数字水印（二进制层）：经 #[used] 保留于编译产物只读数据段，
/// 可用 strings <binary> | grep xiaolishaxiang-watermark 提取验证。
#[used]
static XIAOLISHAXIANG_WATERMARK_BIN: &[u8] =
    "xiaolishaxiang-watermark:v1:小黎的部落（www.qingdujian.com）".as_bytes();

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use axum::{extract::State, routing::get, Json, Router};
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use xs_daemon::audit::{AuditEventKind, AuditLog};
use xs_daemon::pool::{PoolConfig, SandboxPool};
use xs_daemon::sandbox_proto::sandbox_service_server::{SandboxService, SandboxServiceServer};
use xs_daemon::sandbox_proto::*;
use xs_daemon::scheduler_client::SchedulerClient;
use xs_daemon::tenant::TenantRegistry;
use xs_daemon::SandboxHandle;

// ── 信号常量 ────────────────────────────────────────────────────────

/// seccomp 违规信号（架构不匹配或 KILL_PROCESS 策略时内核发送）。
const SIGSYS: i32 = 31;

// ── Metrics ──────────────────────────────────────────────────────────

struct Metrics {
    sandbox_creates: IntCounter,
    sandbox_destroys: IntCounter,
    command_total: IntCounter,
    command_errors: IntCounter,
    command_latency: Histogram,
    /// L1 seccomp 违规计数：子进程因 SIGSYS 终止时递增。
    seccomp_violations: IntCounter,
    active_sandboxes: IntGauge,
    pool_size: IntGauge,
    rss_bytes: IntGauge,
    registry: Registry,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        let sandbox_creates =
            IntCounter::new("xs_sandbox_creates_total", "Total sandboxes created").unwrap();
        let sandbox_destroys =
            IntCounter::new("xs_sandbox_destroys_total", "Total sandboxes destroyed").unwrap();
        let command_total = IntCounter::new("xs_command_total", "Total commands executed").unwrap();
        let command_errors =
            IntCounter::new("xs_command_errors_total", "Total command execution errors").unwrap();
        let command_latency = Histogram::with_opts(
            HistogramOpts::new(
                "xs_command_latency_seconds",
                "Command execution latency in seconds",
            )
            .buckets(vec![
                0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0,
            ]),
        )
        .unwrap();
        let seccomp_violations = IntCounter::new(
            "xs_seccomp_violations_total",
            "Total seccomp violations (reserved, pending L1 wiring)",
        )
        .unwrap();
        let active_sandboxes =
            IntGauge::new("xs_sandbox_active", "Number of active sandboxes").unwrap();
        let pool_size =
            IntGauge::new("xs_sandbox_pool_size", "Sandbox pool size (idle + active)").unwrap();
        let rss_bytes =
            IntGauge::new("xs_rss_bytes", "Daemon process resident memory in bytes").unwrap();

        registry
            .register(Box::new(sandbox_creates.clone()))
            .unwrap();
        registry
            .register(Box::new(sandbox_destroys.clone()))
            .unwrap();
        registry.register(Box::new(command_total.clone())).unwrap();
        registry.register(Box::new(command_errors.clone())).unwrap();
        registry
            .register(Box::new(command_latency.clone()))
            .unwrap();
        registry
            .register(Box::new(seccomp_violations.clone()))
            .unwrap();
        registry
            .register(Box::new(active_sandboxes.clone()))
            .unwrap();
        registry.register(Box::new(pool_size.clone())).unwrap();
        registry.register(Box::new(rss_bytes.clone())).unwrap();

        Self {
            sandbox_creates,
            sandbox_destroys,
            command_total,
            command_errors,
            command_latency,
            seccomp_violations,
            active_sandboxes,
            pool_size,
            rss_bytes,
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
    start_time: SystemTime,
    audit: AuditLog,
    registry: Arc<TenantRegistry>,
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
        let token = extract_bearer_token(request.metadata());
        let req = request.into_inner();
        let mut active = self.active.lock().await;
        let handle = active
            .get_mut(&req.sandbox_id)
            .ok_or_else(|| Status::not_found(format!("沙箱 {} 不存在", req.sandbox_id)))?;

        if handle.is_expired() {
            warn!("沙箱 {} 已过期，拒绝流式执行", req.sandbox_id);
            return Err(Status::resource_exhausted("沙箱已过期"));
        }

        // ── P3：租户归属认证 + 策略执行 ──
        let Some(tenant) = self.registry.get(&handle.tenant_id).await else {
            self.metrics.command_errors.inc();
            return Err(Status::unauthenticated("租户不存在或已注销"));
        };
        if !tenant.verify_token(&token) {
            self.metrics.command_errors.inc();
            return Err(Status::unauthenticated("token 校验失败"));
        }
        if !tenant.policy.evaluate(&req.program).is_allowed() {
            self.metrics.command_errors.inc();
            warn!(sandbox_id = %req.sandbox_id, program = %req.program, "策略拒绝流式执行");
            return Err(Status::permission_denied(format!(
                "策略拒绝执行: {}",
                req.program
            )));
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
                self.metrics
                    .command_latency
                    .observe(latency as f64 / 1_000_000.0);
                let exit_code = match status {
                    xs_api::ExitStatus::Exited(code) => code,
                    xs_api::ExitStatus::Signaled(sig) => {
                        warn!("沙箱 {} 流式命令被信号 {} 终止", req.sandbox_id, sig);
                        if sig == SIGSYS {
                            self.metrics.seccomp_violations.inc();
                        }
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
        let token = extract_bearer_token(request.metadata());
        let req = request.into_inner();
        let trace_id = uuid::Uuid::new_v4().to_string();

        // ── P3：租户认证 ──
        let Some(tenant) = self.registry.get(&req.tenant_id).await else {
            self.audit
                .record(
                    AuditEventKind::Create,
                    &trace_id,
                    &req.tenant_id,
                    "",
                    "error",
                    Some("unauthenticated: unknown tenant".to_string()),
                )
                .await;
            return Err(Status::unauthenticated("未知租户"));
        };
        if !tenant.verify_token(&token) {
            self.audit
                .record(
                    AuditEventKind::Create,
                    &trace_id,
                    &req.tenant_id,
                    "",
                    "error",
                    Some("unauthenticated: bad token".to_string()),
                )
                .await;
            return Err(Status::unauthenticated("token 校验失败"));
        }

        // ── P3：配额检查（max_sandboxes，0 = 不限制）──
        if tenant.quota.max_sandboxes > 0 {
            let tenant_active = self
                .active
                .lock()
                .await
                .values()
                .filter(|h| h.tenant_id == req.tenant_id)
                .count();
            if tenant_active >= tenant.quota.max_sandboxes as usize {
                self.audit
                    .record(
                        AuditEventKind::Create,
                        &trace_id,
                        &req.tenant_id,
                        "",
                        "error",
                        Some(format!(
                            "quota exceeded: max_sandboxes={}",
                            tenant.quota.max_sandboxes
                        )),
                    )
                    .await;
                return Err(Status::resource_exhausted(format!(
                    "租户沙箱配额超限（max_sandboxes={}）",
                    tenant.quota.max_sandboxes
                )));
            }
        }

        let handle = match self.pool.acquire(&req.tenant_id, &req.config_toml).await {
            Ok(h) => h,
            Err(e) => {
                self.audit
                    .record(
                        AuditEventKind::Create,
                        &trace_id,
                        &req.tenant_id,
                        "",
                        "error",
                        Some(e.clone()),
                    )
                    .await;
                return Err(Status::internal(format!("创建沙箱失败: {e}")));
            }
        };
        let sandbox_id = handle.id.clone();
        let created_at = system_time_to_iso8601(&handle.created_at);
        self.active.lock().await.insert(sandbox_id.clone(), handle);
        self.metrics.sandbox_creates.inc();
        self.metrics
            .active_sandboxes
            .set(self.active.lock().await.len() as i64);
        self.audit
            .record(
                AuditEventKind::Create,
                &trace_id,
                &req.tenant_id,
                &sandbox_id,
                "ok",
                None,
            )
            .await;
        info!(trace_id = %trace_id, sandbox_id = %sandbox_id, tenant_id = %req.tenant_id, "沙箱创建");
        Ok(Response::new(CreateSandboxResponse {
            sandbox_id,
            created_at,
        }))
    }

    async fn run_command(
        &self,
        request: Request<RunCommandRequest>,
    ) -> Result<Response<RunCommandResponse>, Status> {
        let token = extract_bearer_token(request.metadata());
        let req = request.into_inner();
        let trace_id = uuid::Uuid::new_v4().to_string();
        let mut active = self.active.lock().await;
        let handle = active
            .get_mut(&req.sandbox_id)
            .ok_or_else(|| Status::not_found(format!("沙箱 {} 不存在", req.sandbox_id)))?;

        if handle.is_expired() {
            warn!("沙箱 {} 已过期，拒绝执行", req.sandbox_id);
            return Err(Status::resource_exhausted("沙箱已过期"));
        }

        // ── P3：租户归属认证 ──
        let tenant_id = handle.tenant_id.clone();
        let Some(tenant) = self.registry.get(&tenant_id).await else {
            self.metrics.command_errors.inc();
            return Err(Status::unauthenticated("租户不存在或已注销"));
        };
        if !tenant.verify_token(&token) {
            self.metrics.command_errors.inc();
            self.audit
                .record(
                    AuditEventKind::Run,
                    &trace_id,
                    &tenant_id,
                    &req.sandbox_id,
                    "error",
                    Some("unauthenticated: bad token".to_string()),
                )
                .await;
            return Err(Status::unauthenticated("token 校验失败"));
        }

        // ── P3：策略执行 ──
        if !tenant.policy.evaluate(&req.program).is_allowed() {
            self.metrics.command_errors.inc();
            self.audit
                .record(
                    AuditEventKind::Run,
                    &trace_id,
                    &tenant_id,
                    &req.sandbox_id,
                    "error",
                    Some(format!("policy denied: {}", req.program)),
                )
                .await;
            warn!(trace_id = %trace_id, sandbox_id = %req.sandbox_id, program = %req.program, "策略拒绝执行");
            return Err(Status::permission_denied(format!(
                "策略拒绝执行: {}",
                req.program
            )));
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
                self.metrics
                    .command_latency
                    .observe(latency as f64 / 1_000_000.0);
                let exit_code = match status {
                    xs_api::ExitStatus::Exited(code) => code,
                    xs_api::ExitStatus::Signaled(sig) => {
                        warn!(trace_id = %trace_id, sandbox_id = %req.sandbox_id, signal = sig, "命令被信号终止");
                        if sig == SIGSYS {
                            self.metrics.seccomp_violations.inc();
                        }
                        -sig
                    }
                };
                self.audit
                    .record(
                        AuditEventKind::Run,
                        &trace_id,
                        &tenant_id,
                        &req.sandbox_id,
                        "ok",
                        Some(format!("exit_code={exit_code} latency_us={latency}")),
                    )
                    .await;
                Ok(Response::new(RunCommandResponse {
                    exit_code,
                    stdout: String::new(),
                    stderr: String::new(),
                    latency_us: latency,
                }))
            }
            Err(e) => {
                self.metrics.command_errors.inc();
                self.audit
                    .record(
                        AuditEventKind::Run,
                        &trace_id,
                        &tenant_id,
                        &req.sandbox_id,
                        "error",
                        Some(e.to_string()),
                    )
                    .await;
                warn!(trace_id = %trace_id, sandbox_id = %req.sandbox_id, error = %e, "命令执行失败");
                Err(Status::internal(format!("命令执行失败: {e}")))
            }
        }
    }

    async fn destroy_sandbox(
        &self,
        request: Request<DestroySandboxRequest>,
    ) -> Result<Response<DestroySandboxResponse>, Status> {
        let token = extract_bearer_token(request.metadata());
        let req = request.into_inner();
        let trace_id = uuid::Uuid::new_v4().to_string();
        let mut active = self.active.lock().await;

        // ── P3：租户归属认证（先查后删，失败不移除）──
        if let Some(handle) = active.get(&req.sandbox_id) {
            let allowed = match self.registry.get(&handle.tenant_id).await {
                Some(t) => t.verify_token(&token),
                None => false,
            };
            if !allowed {
                self.audit
                    .record(
                        AuditEventKind::Destroy,
                        &trace_id,
                        &handle.tenant_id,
                        &req.sandbox_id,
                        "error",
                        Some("unauthenticated".to_string()),
                    )
                    .await;
                return Err(Status::unauthenticated("token 校验失败"));
            }
        }

        match active.remove(&req.sandbox_id) {
            Some(handle) => {
                self.metrics.sandbox_destroys.inc();
                self.metrics.active_sandboxes.set(active.len() as i64);
                self.pool.discard(&handle.id).await;
                self.audit
                    .record(
                        AuditEventKind::Destroy,
                        &trace_id,
                        &handle.tenant_id,
                        &req.sandbox_id,
                        "ok",
                        Some(format!("command_count={}", handle.command_count)),
                    )
                    .await;
                info!(trace_id = %trace_id, sandbox_id = %req.sandbox_id, command_count = handle.command_count, "沙箱销毁");
                Ok(Response::new(DestroySandboxResponse { success: true }))
            }
            None => {
                self.audit
                    .record(
                        AuditEventKind::Destroy,
                        &trace_id,
                        "",
                        &req.sandbox_id,
                        "error",
                        Some("not_found".to_string()),
                    )
                    .await;
                Err(Status::not_found(format!("沙箱 {} 不存在", req.sandbox_id)))
            }
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
            uptime_secs: self.start_time.elapsed().unwrap_or_default().as_secs(),
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

/// 从 gRPC metadata 提取 Bearer token；缺失或格式错误返回空字符串。
fn extract_bearer_token(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

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

/// 读取 /proc/self/status 的 VmRSS（kB），返回字节数；失败返回 0。
fn current_rss_bytes() -> i64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: i64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
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
    let stats = state.pool.stats().await;
    state
        .metrics
        .pool_size
        .set((stats.idle + stats.active) as i64);
    state.metrics.rss_bytes.set(current_rss_bytes());
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
    info!("数字水印: {}", XIAOLISHAXIANG_WATERMARK_TEXT);

    let pool = Arc::new(SandboxPool::new(PoolConfig::default()));
    pool.clone().start_gc();
    info!("沙箱池 GC 已启动");

    let active = Arc::new(Mutex::new(HashMap::new()));
    let metrics = Arc::new(Metrics::new());
    let start_time = SystemTime::now();
    let audit = AuditLog::new(PathBuf::from("audit.jsonl")).await;

    // P3：租户注册表（认证 + 配额 + 策略），60s 周期热加载
    let registry = TenantRegistry::load("/etc/xiaolishaxiang/tenants", 60).await;
    registry.start_hot_reload();
    info!(tenants = registry.len().await, "租户注册表已加载");

    // P4：向调度器注册（环境变量 XS_SCHEDULER_ADDR，缺省 localhost:50052）
    let scheduler_addr =
        std::env::var("XS_SCHEDULER_ADDR").unwrap_or_else(|_| "localhost:50052".to_string());
    let _scheduler = SchedulerClient::connect_and_register(
        &scheduler_addr,
        "localhost:50051",
        pool.clone(),
        active.clone(),
        start_time,
    )
    .await
    .ok();

    // gRPC server
    let svc = SandboxServiceImpl {
        pool: pool.clone(),
        active: active.clone(),
        metrics: metrics.clone(),
        start_time,
        audit,
        registry,
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
