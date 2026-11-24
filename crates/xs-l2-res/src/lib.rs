// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang L2 资源治理层（cgroup v2 / rlimit / 背压）。
//!
//! M1 为最小骨架占位；完整实现在 M2 落地（见 docs/04-TEST-MATRIX.md：
//! 背压、审计通道独立配额、隔离有效性用例均在 M2 激活为 Required）。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backpressure;
pub mod cgroup;

pub use backpressure::{AuditChannel, AuditOverflow, Backpressure, BoundedQueue, TokenBucket};
pub use cgroup::{CgroupError, CgroupV2};

/// cgroup v2 挂载点探测（仅存在性，不代表可委派，见 SP-G-02）。
#[must_use]
pub fn cgroup_v2_mounted() -> bool {
    std::fs::read_to_string("/proc/mounts").is_ok_and(|m| m.lines().any(|l| l.contains("cgroup2")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_detection_runs() {
        let _ = cgroup_v2_mounted();
    }
}
