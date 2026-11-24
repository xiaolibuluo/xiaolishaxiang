// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 运行时能力探测（SP-G-02：报告可用 = 实测通过）。
//!
//! 注意：本模块只做『读取式』探测（内核版本、sysctl、ABI 版本号）。
//! 涉及真实安装/创建动作的探测（seccomp TSYNC 安装、cgroup 真实委派写回读）
//! 属 xs-l1-sys 职责，其结果通过入口参数汇入本模块组装最终报告。

use crate::assurance::{AssuranceLevel, CapabilityReport, LandlockAbi, ProbeOutcome};
use std::fs;

/// 从 /proc/sys/kernel/osrelease 读取内核版本字符串。
#[must_use]
pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|_| "unknown".to_string(), |s| s.trim().to_string())
}

/// 读取 `unprivileged_userns_clone` sysctl（不存在则按发行版默认需另行判断）。
#[must_use]
pub fn userns_sysctl_enabled() -> Option<bool> {
    fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .ok()
        .map(|s| s.trim() == "1")
}

/// /sys/fs/cgroup 是否为 cgroup2fs（仅挂载存在性，不代表可委派）。
#[must_use]
pub fn cgroup_v2_mounted() -> bool {
    fs::read_to_string("/proc/mounts").is_ok_and(|m| m.lines().any(|l| l.contains("cgroup2")))
}

/// 依据探测项组装有效保证等级（不含 seccomp 实装探测，由 L1 补全后重算）。
///
/// 规则（docs/02-ASSURANCE-LEVELS.md）：
/// - landlock 缺失 → 上限 B；
/// - ABI v1/v2 → 上限 A-；v3+ 才可能到 A；
/// - userns 不可用或容器迹象 → C。
#[must_use]
pub fn derive_level(
    landlock_abi: LandlockAbi,
    userns_ok: bool,
    cgroup_delegable: bool,
    in_container: bool,
) -> AssuranceLevel {
    if in_container || !userns_ok {
        return AssuranceLevel::C;
    }
    if !landlock_abi.has_fs() || !cgroup_delegable {
        return AssuranceLevel::B;
    }
    if landlock_abi.has_network() {
        AssuranceLevel::A
    } else {
        AssuranceLevel::AMinus
    }
}

/// 组装一份能力报告（seccomp 实装结果由 L1 层填入 outcomes）。
#[must_use]
pub fn assemble_report(
    landlock_abi: LandlockAbi,
    userns_ok: bool,
    cgroup_delegable: bool,
    in_container: bool,
    mut extra: Vec<ProbeOutcome>,
) -> CapabilityReport {
    let effective = derive_level(landlock_abi, userns_ok, cgroup_delegable, in_container);
    let mut outcomes = vec![
        ProbeOutcome {
            item: "landlock".into(),
            available: landlock_abi.has_fs(),
            note: format!("abi={}", landlock_abi.0),
        },
        ProbeOutcome {
            item: "userns".into(),
            available: userns_ok,
            note: "sysctl/clone 探测".into(),
        },
        ProbeOutcome {
            item: "cgroup_v2_delegation".into(),
            available: cgroup_delegable,
            note: "真实创建+写回读（见 SP-G-02）".into(),
        },
        ProbeOutcome {
            item: "in_container".into(),
            available: !in_container,
            note: "存在 /.dockerenv 即视为容器".into(),
        },
    ];
    outcomes.append(&mut extra);
    CapabilityReport {
        kernel: kernel_release(),
        landlock_abi,
        outcomes,
        effective,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release_is_not_empty_and_version_like() {
        let s = kernel_release();
        assert!(!s.is_empty(), "内核版本不应为空");
        assert!(
            s.chars().any(|c| c.is_ascii_digit()),
            "内核版本应包含数字，实际: {s}"
        );
        // 不硬编码特定内核，但必须是合法 '.' 版本号格式
        assert!(s.contains('.'), "内核版本应含 '.'，实际: {s}");
    }

    #[test]
    fn userns_sysctl_consistent_with_direct_read() {
        let result = userns_sysctl_enabled();
        let direct = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone");
        match direct {
            Ok(content) => {
                let expected = content.trim() == "1";
                assert_eq!(
                    result,
                    Some(expected),
                    "sysctl 文件存在时函数应返回 Some 且与文件内容一致"
                );
            }
            Err(_) => {
                assert_eq!(result, None, "sysctl 文件不存在时函数应返回 None");
            }
        }
    }

    #[test]
    fn cgroup_v2_mounted_consistent_with_proc_mounts() {
        let result = cgroup_v2_mounted();
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let has_cgroup2 = mounts.lines().any(|l| l.contains("cgroup2"));
        assert_eq!(
            result, has_cgroup2,
            "cgroup_v2_mounted 应与 /proc/mounts 一致；函数返回 {result}，mounts 含 cgroup2={has_cgroup2}"
        );
    }

    #[test]
    fn derive_level_matrix() {
        // 容器内直接 C
        assert_eq!(
            derive_level(LandlockAbi(8), true, true, true),
            AssuranceLevel::C
        );
        // userns 不可用 C
        assert_eq!(
            derive_level(LandlockAbi(8), false, true, false),
            AssuranceLevel::C
        );
        // landlock 缺失 B
        assert_eq!(
            derive_level(LandlockAbi::UNSUPPORTED, true, true, false),
            AssuranceLevel::B
        );
        // cgroup 不可委派 B
        assert_eq!(
            derive_level(LandlockAbi(8), true, false, false),
            AssuranceLevel::B
        );
        // ABI v1/v2 → A-
        assert_eq!(
            derive_level(LandlockAbi(2), true, true, false),
            AssuranceLevel::AMinus
        );
        // ABI v3+ → A
        assert_eq!(
            derive_level(LandlockAbi(3), true, true, false),
            AssuranceLevel::A
        );
    }
}
