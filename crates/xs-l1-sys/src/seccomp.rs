// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! seccomp 安装状态检查。
//!
//! 为 SP-G-02 探测一致性提供实装证据：报告 seccomp 可用前，
//! 必须能读到当前进程的 seccomp 模式（/proc/self/status 的 Seccomp 字段）。
//!
//! 完整的 filter 安装（allowlist、TSYNC、exec 前断言）在 M1 后续迭代落地，
//! 其反向用例原型已固化于 spike/spike2.py（P2a/P2b/P3 全部实测通过）。

use xs_core::{XsError, XsResult};

/// /proc/self/status 中 Seccomp 字段的取值含义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompMode {
    /// 0：未启用 seccomp。
    Disabled,
    /// 1：strict 模式。
    Strict,
    /// 2：filter 模式（BPF 过滤器已安装）。
    Filter,
    /// 无法解析的值。
    Unknown(i32),
}

impl SeccompMode {
    /// 当前是否已有 filter 生效。
    #[must_use]
    pub fn is_filtered(self) -> bool {
        matches!(self, Self::Filter)
    }
}

/// 读取当前进程的 seccomp 模式（/proc/self/status 的 Seccomp 字段）。
///
/// 读取失败返回 IsolatorSetupFailed（探测本身失败必须显式上报，禁止默认放行）。
pub fn current_status() -> XsResult<SeccompMode> {
    let status =
        std::fs::read_to_string("/proc/self/status").map_err(|e| XsError::IsolatorSetupFailed {
            mechanism: "seccomp".to_string(),
            detail: format!("读取 /proc/self/status 失败: {e}"),
        })?;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Seccomp:") {
            let n: i32 = v.trim().parse().map_err(|_| XsError::IsolatorSetupFailed {
                mechanism: "seccomp".to_string(),
                detail: format!("Seccomp 字段无法解析: {}", v.trim()),
            })?;
            return Ok(match n {
                0 => SeccompMode::Disabled,
                1 => SeccompMode::Strict,
                2 => SeccompMode::Filter,
                other => SeccompMode::Unknown(other),
            });
        }
    }
    Err(XsError::IsolatorSetupFailed {
        mechanism: "seccomp".to_string(),
        detail: "/proc/self/status 中不存在 Seccomp 字段".to_string(),
    })
}

/// 当前进程是否已被上层 seccomp 锁定（容器内常见，影响可收紧性判定）。
pub fn is_locked_by_upper() -> XsResult<bool> {
    Ok(current_status()?.is_filtered())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_readable() {
        let mode = current_status().expect("/proc/self/status 应可读");
        // 测试进程未装 filter 时应为 Disabled；在受约束 CI 中可能是 Filter，两者都合法。
        assert!(matches!(
            mode,
            SeccompMode::Disabled | SeccompMode::Filter | SeccompMode::Strict
        ));
    }
}
