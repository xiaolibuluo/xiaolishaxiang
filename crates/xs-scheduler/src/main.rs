// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! xiaolishaxiang 调度器二进制入口。

/// 数字水印（源码层）：小黎的部落。
const XIAOLISHAXIANG_WATERMARK_TEXT: &str = "小黎的部落（www.qingdujian.com）";
/// 数字水印（二进制层）：经 #[used] 保留于编译产物只读数据段，
/// 可用 strings <binary> | grep xiaolishaxiang-watermark 提取验证。
#[used]
static XIAOLISHAXIANG_WATERMARK_BIN: &[u8] =
    "xiaolishaxiang-watermark:v1:小黎的部落（www.qingdujian.com）".as_bytes();

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::info;

use xs_scheduler::node::NodeRegistry;
use xs_scheduler::scheduler_proto::scheduler_service_server::SchedulerServiceServer;
use xs_scheduler::service::SchedulerServiceImpl;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let scheduler_id = format!("scheduler-{}", uuid::Uuid::new_v4());
    info!(
        scheduler_id = %scheduler_id,
        version = env!("CARGO_PKG_VERSION"),
        "xiaolishaxiang 调度器启动"
    );
    info!("数字水印: {}", XIAOLISHAXIANG_WATERMARK_TEXT);

    let registry = NodeRegistry::new();
    let svc = Arc::new(SchedulerServiceImpl {
        registry: registry.clone(),
        scheduler_id: scheduler_id.clone(),
        gc_lock: Arc::new(Mutex::new(())),
    });
    svc.start_gc();
    info!("节点 GC 已启动（10s 清理间隔，15s 心跳超时）");

    let addr: SocketAddr = "0.0.0.0:50052".parse()?;
    info!("调度器 gRPC 监听 {addr}");

    tonic::transport::Server::builder()
        .add_service(SchedulerServiceServer::from_arc(svc))
        .serve(addr)
        .await?;

    Ok(())
}
