// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 保证等级（Assurance Level）与运行时能力探测类型。
//!
//! 等级是运行时探测后导出的有效值（effective），不是静态承诺。
//! 见 docs/02-ASSURANCE-LEVELS.md。

use serde::{Deserialize, Serialize};

/// 保证等级，自低到高：C < B < A- < A。
///
/// C 表示无有效系统级隔离，默认拒绝启动。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssuranceLevel {
    /// 容器内 / seccomp 无法收紧 / userns 被禁用：无有效系统级隔离。
    C,
    /// userns 可用但 landlock 缺失，或 cgroup v2 不可委派：降级，仅半可信。
    B,
    /// 内核 5.15~6.1（landlock ABI v1/v2）：文件隔离完整，网络仅 netns。
    /// 配置文件中写作 "A-"（serde rename）。
    #[serde(rename = "A-")]
    AMinus,
    /// 内核 6.2+（landlock ABI v3+）：文件与网络均纳入能力模型。
    A,
}

impl AssuranceLevel {
    /// 该等级是否可用于完全不可信代码。
    #[must_use]
    pub fn is_full_untrusted_capable(self) -> bool {
        matches!(self, Self::A | Self::AMinus)
    }

    /// 人类可读标签（用于审计与报告）。
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::C => "C",
            Self::B => "B",
            Self::AMinus => "A-",
            Self::A => "A",
        }
    }
}

/// landlock ABI 版本（由内核 `landlock_create_ruleset` 探测返回）。
///
/// 版本即能力：v1 仅文件系统，v3 起含网络，v4 起含 IPC/socket。
/// 禁止用布尔『支持/不支持』替代版本号。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LandlockAbi(pub u32);

impl LandlockAbi {
    /// ABI 不可用（内核无 landlock 或低于 5.15）。
    pub const UNSUPPORTED: Self = Self(0);

    /// 是否具备文件系统维度隔离。
    #[must_use]
    pub fn has_fs(self) -> bool {
        self.0 >= 1
    }

    /// 是否具备网络维度隔离（ABI v3，内核 6.2+）。
    #[must_use]
    pub fn has_network(self) -> bool {
        self.0 >= 3
    }
}

/// 单项探测结果：报告可用 = 实测通过（SP-G-02 探测一致性）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOutcome {
    /// 探测项名称（如 landlock / `cgroup_v2_delegation` / `seccomp_tsync`）。
    pub item: String,
    /// 实测是否可用。
    pub available: bool,
    /// 附带说明（版本号、失败原因、错误码等）。
    pub note: String,
}

/// 一次完整能力探测的汇总结果，由 `capabilities()` 返回。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityReport {
    /// 内核版本字符串。
    pub kernel: String,
    /// landlock ABI 探测结果。
    pub landlock_abi: LandlockAbi,
    /// 各探测项的明细结果。
    pub outcomes: Vec<ProbeOutcome>,
    /// 探测导出的有效保证等级。
    pub effective: AssuranceLevel,
}

impl CapabilityReport {
    /// 依据 `min_assurance` 判定是否放行（fail-closed）。
    ///
    /// effective < `min_assurance` 时返回 `AssuranceTooLow` 错误。
    pub fn enforce(&self, min_assurance: AssuranceLevel) -> crate::error::XsResult<AssuranceLevel> {
        if self.effective < min_assurance {
            return Err(crate::error::XsError::AssuranceTooLow {
                effective: self.effective.label().to_string(),
                required: min_assurance.label().to_string(),
            });
        }
        Ok(self.effective)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_ordering() {
        assert!(AssuranceLevel::A > AssuranceLevel::AMinus);
        assert!(AssuranceLevel::AMinus > AssuranceLevel::B);
        assert!(AssuranceLevel::B > AssuranceLevel::C);
    }

    #[test]
    fn is_full_untrusted_capable_all_levels() {
        // A-/A → true；B/C → false
        assert!(AssuranceLevel::A.is_full_untrusted_capable());
        assert!(AssuranceLevel::AMinus.is_full_untrusted_capable());
        assert!(!AssuranceLevel::B.is_full_untrusted_capable());
        assert!(!AssuranceLevel::C.is_full_untrusted_capable());
    }

    #[test]
    fn label_not_empty_and_deterministic() {
        for lv in [
            AssuranceLevel::C,
            AssuranceLevel::B,
            AssuranceLevel::AMinus,
            AssuranceLevel::A,
        ] {
            let s = lv.label();
            assert!(!s.is_empty(), "label 不应为空，等级 {lv:?}");
            assert!(!s.contains("xyzzy"), "label 不应为占位字符串，实际 {s}");
        }
    }

    #[test]
    fn landlock_abi_gates() {
        assert!(!LandlockAbi::UNSUPPORTED.has_fs());
        assert!(LandlockAbi(1).has_fs());
        assert!(!LandlockAbi(2).has_network());
        assert!(LandlockAbi(3).has_network());
        assert!(LandlockAbi(8).has_network());
    }

    #[test]
    fn enforce_fail_closed() {
        let rep = CapabilityReport {
            kernel: "7.0.0".into(),
            landlock_abi: LandlockAbi(8),
            outcomes: vec![],
            effective: AssuranceLevel::B,
        };
        assert!(rep.enforce(AssuranceLevel::A).is_err());
        assert_eq!(rep.enforce(AssuranceLevel::B).unwrap(), AssuranceLevel::B);
    }
}
