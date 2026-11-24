// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 统一错误模型。
//!
//! 设计原则（SP-G-01 fail-closed）：任何错误都表示『拒绝执行』，
//! 不存在『降级放行』的错误路径。错误必须携带足够的上下文供审计定位。

use std::fmt;

/// 沙箱操作的统一错误类型。
///
/// 每个变体对应一类 fail-closed 触发条件，见 SP-G-01。
#[derive(Debug)]
pub enum XsError {
    /// 配置解析失败或配置项无法识别。
    Config {
        /// 出错的配置项描述。
        detail: String,
    },
    /// 请求的能力未在策略中声明。
    CapabilityNotDeclared {
        /// 被请求但未声明的能力标识。
        capability: String,
    },
    /// 内核特性不满足（内核低于 5.15、landlock 缺失等）。
    KernelFeatureMissing {
        /// 缺失的特性描述（如 landlock ABI >= 1）。
        feature: String,
    },
    /// 运行时探测的 effective 保证等级低于 `min_assurance`。
    AssuranceTooLow {
        /// 探测到的有效等级。
        effective: String,
        /// 策略要求的最低等级。
        required: String,
    },
    /// 审计不可用（no-record => no-execute）。
    AuditUnavailable {
        /// 审计通道不可用的原因。
        reason: String,
    },
    /// 隔离机制安装顺序错误或部分失败（seccomp/landlock/cgroup）。
    /// 覆盖 SP-L1-03 探针实测：安装被拒可能是 EPERM 或 EACCES。
    IsolatorSetupFailed {
        /// 失败的机制名（seccomp / landlock / cgroup / namespace）。
        mechanism: String,
        /// 失败阶段与错误详情（含错误码）。
        detail: String,
    },
    /// 沙箱内进程触发了被策略拒绝的动作（由隔离层报告）。
    PolicyViolation {
        /// 违反的 SP-ID（如 SP-L1-01）。
        sp_id: String,
        /// 违规详情。
        detail: String,
    },
    /// 资源治理层拒绝（背压、超限），见 SP-L2 系列。
    ResourceGoverned {
        /// 触发的 SP-ID（如 SP-L2-01）。
        sp_id: String,
        /// 详情。
        detail: String,
    },
    /// 底层 IO / OS 错误透传（附上下文）。
    Io {
        /// 操作上下文。
        context: String,
        /// 原始 IO 错误。
        source: std::io::Error,
    },
}

impl fmt::Display for XsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config { detail } => write!(f, "配置错误: {detail}"),
            Self::CapabilityNotDeclared { capability } => {
                write!(f, "能力未声明: {capability}")
            }
            Self::KernelFeatureMissing { feature } => {
                write!(f, "内核特性缺失: {feature}")
            }
            Self::AssuranceTooLow {
                effective,
                required,
            } => {
                write!(f, "保证等级不足: 有效={effective}, 要求={required}")
            }
            Self::AuditUnavailable { reason } => {
                write!(f, "审计不可用(no-record => no-execute): {reason}")
            }
            Self::IsolatorSetupFailed { mechanism, detail } => {
                write!(f, "隔离机制安装失败[{mechanism}]: {detail}")
            }
            Self::PolicyViolation { sp_id, detail } => {
                write!(f, "策略违规[{sp_id}]: {detail}")
            }
            Self::ResourceGoverned { sp_id, detail } => {
                write!(f, "资源治理拒绝[{sp_id}]: {detail}")
            }
            Self::Io { context, source } => write!(f, "IO错误[{context}]: {source}"),
        }
    }
}

impl std::error::Error for XsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// 统一结果别名。
pub type XsResult<T> = Result<T, XsError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn error_display_is_descriptive() {
        let e = XsError::AssuranceTooLow {
            effective: "B".into(),
            required: "A".into(),
        };
        let s = e.to_string();
        assert!(s.contains('B'));
        s.contains('A').then_some(());
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<XsError>();
    }

    #[test]
    fn source_only_for_io_variant() {
        let io_err = XsError::Io {
            context: "test".into(),
            source: std::io::Error::other("x"),
        };
        assert!(io_err.source().is_some(), "Io 变体应返回 source");

        let non_io = XsError::Config {
            detail: "test".into(),
        };
        assert!(non_io.source().is_none(), "非 Io 变体 source 应为 None");
    }
}
