// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 守护进程核心库：沙箱池、生命周期管理、gRPC 服务实现。

#![allow(clippy::result_large_err)]

pub mod audit;
pub mod pool;
pub mod tenant;

/// proto 生成的 gRPC 代码（由 build.rs 编译 proto/xiaolishaxiang/v1/sandbox.proto）。
pub mod sandbox_proto {
    tonic::include_proto!("xiaolishaxiang.v1");
}

use std::time::SystemTime;
use xs_api::Sandbox;

/// 池化的沙箱句柄：持有已建域的 Sandbox，归还时回池。
pub struct SandboxHandle {
    pub id: String,
    pub tenant_id: String,
    pub sandbox: Sandbox,
    pub created_at: SystemTime,
    pub command_count: u64,
    pub max_commands: u64,
    pub ttl_secs: u64,
}

impl SandboxHandle {
    /// 检查是否过期（TTL 已到或命令数超限）。
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let ttl_expired = self.ttl_secs > 0
            && self
                .created_at
                .elapsed()
                .is_ok_and(|e| e.as_secs() >= self.ttl_secs);
        let cmd_exhausted = self.max_commands > 0 && self.command_count >= self.max_commands;
        ttl_expired || cmd_exhausted
    }
}

/// 沙箱池统计数据。
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total: usize,
    pub idle: usize,
    pub active: usize,
}
