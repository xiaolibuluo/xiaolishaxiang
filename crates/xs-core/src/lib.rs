// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 核心 crate。
//!
//! 提供：三层 trait（isolator）、错误模型（error）、保证等级与能力探测类型（assurance）、
//! 审计日志（audit）、配置（config）、能力描述（capability）。
//!
//! 本 crate 为纯 Rust 逻辑，禁止 unsafe；Miri / 变异测试的作用域即本 crate 与 xs-l2-res。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod assurance;
pub mod audit;
pub mod capability;
pub mod config;
pub mod error;
pub mod isolator;
pub mod probe;

pub use assurance::{AssuranceLevel, CapabilityReport, LandlockAbi, ProbeOutcome};
pub use audit::{AuditEvent, AuditKind, AuditSink, AuditWriteOutcome, TracingAuditSink};
pub use capability::{CapabilityId, CapabilitySet};
pub use config::{ResourceQuota, SandboxConfig};
pub use error::{XsError, XsResult};
