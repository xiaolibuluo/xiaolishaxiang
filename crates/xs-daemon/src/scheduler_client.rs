// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

//! 调度器客户端：daemon 向调度器注册、维持心跳、优雅注销。

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::pool::SandboxPool;
use crate::sandbox_proto::scheduler_service_client::SchedulerServiceClient;
use crate::sandbox_proto::{
    DeregisterNodeRequest, HeartbeatRequest, NodeLoad, RegisterNodeRequest,
};

/// 调度器客户端句柄：持有 gRPC 连接、心跳任务、节点标识。
///
/// Drop 时自动向调度器发送 DeregisterNode。
pub struct SchedulerClient {
    node_id: String,
    client: SchedulerServiceClient<Channel>,
    /// 心跳任务句柄（abort 即停止）
    heartbeat_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SchedulerClient {
    /// 向调度器注册当前 daemon 节点，并启动 5s 周期心跳任务。
    ///
    /// # Errors
    /// 连接或注册失败时返回错误字符串。
    pub async fn connect_and_register(
        scheduler_addr: &str,
        daemon_addr: &str,
        pool: Arc<SandboxPool>,
        active: Arc<Mutex<std::collections::HashMap<String, crate::SandboxHandle>>>,
        start_time: SystemTime,
    ) -> Result<Self, String> {
        let node_id = format!(
            "daemon-{}",
            uuid::Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("0")
        );

        let mut client = SchedulerServiceClient::connect(format!("http://{scheduler_addr}"))
            .await
            .map_err(|e| format!("连接调度器 {scheduler_addr} 失败: {e}"))?;

        // 注册节点
        let resp = client
            .register_node(RegisterNodeRequest {
                node_id: node_id.clone(),
                address: daemon_addr.to_string(),
                max_sandboxes: 128,
                version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .await
            .map_err(|e| format!("节点注册失败: {e}"))?
            .into_inner();

        if !resp.accepted {
            return Err("调度器拒绝注册".to_string());
        }

        info!(
            node_id = %node_id,
            scheduler_id = %resp.scheduler_id,
            "已注册到调度器"
        );

        // 启动心跳任务
        let heartbeat_handle = tokio::spawn(Self::heartbeat_loop(
            node_id.clone(),
            scheduler_addr.to_string(),
            pool,
            active,
            start_time,
        ));

        Ok(Self {
            node_id,
            client,
            heartbeat_handle: Some(heartbeat_handle),
        })
    }

    /// 获取本节点 ID。
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// 心跳循环：每 5s 采集负载并上报调度器。
    async fn heartbeat_loop(
        node_id: String,
        scheduler_addr: String,
        pool: Arc<SandboxPool>,
        active: Arc<Mutex<std::collections::HashMap<String, crate::SandboxHandle>>>,
        start_time: SystemTime,
    ) {
        // 重新建立独立连接（避免与注册请求共享连接带来的竞态）
        let mut client = loop {
            match SchedulerServiceClient::connect(format!("http://{scheduler_addr}")).await {
                Ok(c) => break c,
                Err(e) => {
                    warn!("心跳连接调度器失败，5s 后重试: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        };

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            let load = collect_node_load(&pool, &active, start_time).await;
            match client
                .heartbeat(HeartbeatRequest {
                    node_id: node_id.clone(),
                    load: Some(load),
                })
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    warn!(node_id = %node_id, "心跳上报失败: {e}");
                    // 重连
                    match SchedulerServiceClient::connect(format!("http://{scheduler_addr}")).await
                    {
                        Ok(c) => client = c,
                        Err(e2) => warn!("心跳重连失败: {e2}"),
                    }
                }
            }
        }
    }
}

impl Drop for SchedulerClient {
    fn drop(&mut self) {
        // 停止心跳
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }

        // 尝试同步注销（tokio runtime 仍存活时）
        let node_id = self.node_id.clone();
        let mut client = self.client.clone();
        tokio::task::spawn(async move {
            match client
                .deregister_node(DeregisterNodeRequest {
                    node_id: node_id.clone(),
                })
                .await
            {
                Ok(_) => info!(node_id = %node_id, "已向调度器注销"),
                Err(e) => warn!(node_id = %node_id, "注销失败: {e}"),
            }
        });
    }
}

/// 采集当前节点负载（CPU/内存/活跃沙箱数/空闲数/运行时长）。
///
/// CPU 和内存通过 /proc/self/status 和 /proc/stat 读取。
/// 活跃沙箱数从 active map 获取，空闲数从池统计获取。
async fn collect_node_load(
    pool: &SandboxPool,
    active: &Mutex<std::collections::HashMap<String, crate::SandboxHandle>>,
    start_time: SystemTime,
) -> NodeLoad {
    let stats = pool.stats().await;
    let active_count = active.lock().await.len() as u32;
    let uptime = start_time.elapsed().unwrap_or_default().as_secs();

    // 简化的 CPU/内存采集（从 /proc/self/status 读取 VmRSS，
    // CPU 百分比通过两次采集 /proc/stat 差值计算过于复杂，
    // 此处用固定 0 值，后续版本对接真正的 /proc 采样）
    let (cpu_pct, mem_pct) = read_system_load();

    NodeLoad {
        cpu_percent: cpu_pct,
        mem_percent: mem_pct,
        active_sandboxes: active_count,
        idle_sandboxes: stats.idle as u32,
        uptime_secs: uptime,
    }
}

/// 读取系统 CPU 和内存使用率。
///
/// 内存：VmRSS / MemTotal（从 /proc/meminfo 读取）。
/// CPU：当前版本返回 0.0（后续对接 /proc/stat 差值采样）。
fn read_system_load() -> (f64, f64) {
    let mem_pct = read_mem_percent();
    (0.0, mem_pct)
}

fn read_mem_percent() -> f64 {
    let meminfo = match std::fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => return 0.0,
    };
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail_kb = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0);
        }
    }
    if total_kb == 0 {
        return 0.0;
    }
    ((total_kb - avail_kb) as f64 / total_kb as f64 * 100.0).clamp(0.0, 100.0)
}
