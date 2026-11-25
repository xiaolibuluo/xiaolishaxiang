// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! CLI 调度器客户端：向调度器请求沙箱分配，然后直连 daemon 创建沙箱。

use crate::scheduler_proto::sandbox_service_client::SandboxServiceClient;
use crate::scheduler_proto::scheduler_service_client::SchedulerServiceClient;
use crate::scheduler_proto::{
    AllocateSandboxRequest, AllocateSandboxResponse, CreateSandboxRequest, CreateSandboxResponse,
    DestroySandboxRequest,
};

/// 向调度器请求分配最优节点上的沙箱。
///
/// # Errors
/// 连接失败、调度失败或 gRPC 错误时返回错误消息。
pub async fn allocate_sandbox(
    scheduler_addr: &str,
    tenant_id: &str,
    config_toml: &str,
    ttl_secs: u64,
    max_commands: u64,
) -> Result<AllocateSandboxResponse, String> {
    let mut client = SchedulerServiceClient::connect(format!("http://{scheduler_addr}"))
        .await
        .map_err(|e| format!("连接调度器 {scheduler_addr} 失败: {e}"))?;

    let req = AllocateSandboxRequest {
        tenant_id: tenant_id.to_string(),
        config_toml: config_toml.to_string(),
        ttl_secs,
        max_commands,
    };

    let resp = client
        .allocate_sandbox(req)
        .await
        .map_err(|e| format!("调度请求失败: {e}"))?
        .into_inner();

    if !resp.error.is_empty() {
        return Err(format!("调度失败: {}", resp.error));
    }

    Ok(resp)
}

/// 直连 daemon 节点创建沙箱实例。
///
/// # Errors
/// 连接失败或 gRPC 错误时返回错误消息。
pub async fn create_sandbox_on_node(
    node_addr: &str,
    tenant_id: &str,
    config_toml: &str,
    ttl_secs: u64,
    max_commands: u64,
) -> Result<CreateSandboxResponse, String> {
    let mut client = SandboxServiceClient::connect(format!("http://{node_addr}"))
        .await
        .map_err(|e| format!("连接 daemon {node_addr} 失败: {e}"))?;

    let req = CreateSandboxRequest {
        tenant_id: tenant_id.to_string(),
        config_toml: config_toml.to_string(),
        ttl_secs,
        max_commands,
    };

    let resp = client
        .create_sandbox(req)
        .await
        .map_err(|e| format!("创建沙箱失败: {e}"))?
        .into_inner();

    Ok(resp)
}

/// 直连 daemon 节点销毁沙箱实例。
pub async fn destroy_sandbox_on_node(node_addr: &str, sandbox_id: &str) -> Result<(), String> {
    let mut client = SandboxServiceClient::connect(format!("http://{node_addr}"))
        .await
        .map_err(|e| format!("连接 daemon {node_addr} 失败: {e}"))?;

    let req = DestroySandboxRequest {
        sandbox_id: sandbox_id.to_string(),
    };

    client
        .destroy_sandbox(req)
        .await
        .map_err(|e| format!("销毁沙箱失败: {e}"))?
        .into_inner();

    Ok(())
}
