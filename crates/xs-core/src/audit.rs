// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 审计日志（xs-core，M1 交付物）。
//!
//! 硬约束（SP-G-01 / SP-L2-04）：
//! - no-record => no-execute：审计不可用则不得执行；
//! - 审计通道独立于业务背压，溢出降级为『标记事件丢失』而非静默丢弃。

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// 审计事件类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditKind {
    /// 能力被请求。
    CapabilityRequest,
    /// 能力/动作被拒绝（含 SP-ID）。
    Denied,
    /// 资源超限事件。
    ResourceExceeded,
    /// 隔离机制安装/卸载。
    IsolatorLifecycle,
    /// 能力探测结果快照。
    ProbeSnapshot,
    /// 审计通道自身事件（如溢出标记）。
    AuditSelf,
}

/// 一条结构化审计事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// 事件类别。
    pub kind: AuditKind,
    /// 关联的 SP-ID（如有，如 SP-L1-01）。
    pub sp_id: Option<String>,
    /// 关联的 sandbox / task 标识。
    pub subject: String,
    /// 事件详情。
    pub detail: String,
    /// 事件时间。
    pub at: SystemTime,
}

impl AuditEvent {
    /// 构造一条事件。
    pub fn new(
        kind: AuditKind,
        sp_id: Option<&str>,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            sp_id: sp_id.map(str::to_string),
            subject: subject.into(),
            detail: detail.into(),
            at: SystemTime::now(),
        }
    }
}

/// 审计写入结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditWriteOutcome {
    /// 已写入。
    Recorded,
    /// 缓冲溢出，事件被标记为丢失（非静默丢弃）。
    DroppedMarked,
}

/// 审计 sink：审计事件的目的地。
///
/// 实现者必须保证写入失败可观测；调用方在 sink 不可用时应拒绝执行。
pub trait AuditSink: Send + Sync {
    /// 写入一条事件。失败返回 Err，由调用方触发 fail-closed。
    fn record(&self, event: &AuditEvent) -> crate::error::XsResult<AuditWriteOutcome>;

    /// sink 当前是否可用（no-record => no-execute 的判定依据）。
    fn is_available(&self) -> bool;
}

/// 基于 tracing 的默认 sink（M1 最小可用实现）。
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: &AuditEvent) -> crate::error::XsResult<AuditWriteOutcome> {
        tracing::info!(
            target: "xs.audit",
            kind = ?event.kind,
            sp_id = event.sp_id.as_deref().unwrap_or("-"),
            subject = %event.subject,
            detail = %event.detail,
            "audit"
        );
        Ok(AuditWriteOutcome::Recorded)
    }

    fn is_available(&self) -> bool {
        // D2 修复：真实判定 tracing subscriber 是否已初始化且接受 INFO 级事件。
        // 验证报告 D2 实证：此前硬编码 true，使 no-record => no-execute 判定
        // 在 CLI 路径（未初始化 subscriber）上形同虚设，事件静默丢弃。
        // enabled! 在无 subscriber 时返回 false，调用方据此 fail-closed。
        tracing::enabled!(tracing::Level::INFO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_construction() {
        let e = AuditEvent::new(AuditKind::Denied, Some("SP-L1-01"), "sb-1", "path escape");
        assert_eq!(e.kind, AuditKind::Denied);
        assert_eq!(e.sp_id.as_deref(), Some("SP-L1-01"));
    }

    #[test]
    fn tracing_sink_available_and_records() {
        // D2 修复配套：is_available 现为真实判定（subscriber 是否初始化），
        // 测试进程需先初始化 subscriber（幂等，重复调用安全）。
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .try_init();
        let sink = TracingAuditSink;
        assert!(sink.is_available());
        let e = AuditEvent::new(AuditKind::CapabilityRequest, None, "sb-1", "fs.read");
        assert_eq!(sink.record(&e).unwrap(), AuditWriteOutcome::Recorded);
    }
}
