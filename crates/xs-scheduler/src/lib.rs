// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 中心调度器：节点注册/心跳/负载均衡/故障转移。

#![allow(clippy::result_large_err)]

pub mod allocate;
pub mod node;
pub mod service;

/// proto 生成的 gRPC 代码（由 build.rs 编译 proto/xiaolishaxiang/v1/sandbox.proto + scheduler.proto）。
pub mod scheduler_proto {
    tonic::include_proto!("xiaolishaxiang.v1");
}
