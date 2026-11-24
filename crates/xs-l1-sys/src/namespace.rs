// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! Linux namespace 建立与可用性探测。
//!
//! 对应 SP-L1-05（网络默认拒绝由 netns 保证）与保证等级探测中的
//! userns 可用性判定（docs/02-ASSURANCE-LEVELS.md 第 3 节）。

use xs_core::{XsError, XsResult};

/// 沙箱所需的 namespace 组合。
///
/// netns 创建后不配 veth 即无网络，这是网络默认拒绝的实现基座。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsFlags {
    /// `CLONE_NEWUSER：用户命名空间（非特权隔离的前提`）。
    pub user: bool,
    /// `CLONE_NEWNS：挂载命名空间（文件系统视图隔离的前提`）。
    pub mount: bool,
    /// `CLONE_NEWPID：PID` 命名空间（SP-L1-06 init 语义）。
    pub pid: bool,
    /// CLONE_NEWNET：网络命名空间（SP-L1-05 默认拒绝）。
    pub net: bool,
}

impl NsFlags {
    /// 沙箱默认完整组合。
    #[must_use]
    pub fn sandbox_default() -> Self {
        Self {
            user: true,
            mount: true,
            pid: true,
            net: true,
        }
    }

    /// 转换为 libc 的 clone 标志位。
    #[must_use]
    pub fn to_clone_flags(self) -> libc::c_int {
        let mut f = 0;
        if self.user {
            f |= libc::CLONE_NEWUSER;
        }
        if self.mount {
            f |= libc::CLONE_NEWNS;
        }
        if self.pid {
            f |= libc::CLONE_NEWPID;
        }
        if self.net {
            f |= libc::CLONE_NEWNET;
        }
        f
    }
}

/// 探测当前进程是否有能力创建 user namespace。
///
/// 方法：读取 sysctl（快速路径）+ 容器迹象判断由调用方组合。
/// 真实创建动作（unshare 试创建）在隔离域建立流程中执行，失败即 `IsolatorSetupFailed`。
#[must_use]
pub fn userns_sysctl_permits() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map_or(true, |s| s.trim() == "1") // sysctl 不存在时多数发行版默认允许（如未打 Ubuntu 补丁的内核）
}

/// 检测当前是否运行于容器内（/.dockerenv 或 cgroup 含 docker/kubepods 痕迹）。
#[must_use]
pub fn in_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    std::fs::read_to_string("/proc/1/cgroup")
        .is_ok_and(|c| c.contains("docker") || c.contains("kubepods") || c.contains("containerd"))
}

/// 对当前进程应用 unshare（隔离域建立的第一步）。
///
/// 注意：本函数会改变调用进程的 namespace 归属，只允许在 fork 出的
/// 沙箱引导子进程中调用；supervisor 主进程禁止调用。
pub fn unshare_in_child(flags: NsFlags) -> XsResult<()> {
    let bits = flags.to_clone_flags();
    // SAFETY（安全论证）：
    // - unshare(2) 只影响调用进程自身，不影响其他进程；
    // - flags 由 NsFlags 构造，只包含合法的 CLONE_NEW* 位；
    // - 调用契约：必须在 fork 出的子进程中调用（supervisor 主进程调用会破坏自身环境，
    //   该约束由上层 establish() 的流程保证，并在此处文档化）；
    // - 失败返回 -1 + errno，绝不静默成功（fail-closed）。
    let ret = unsafe { libc::unshare(bits) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "namespace".to_string(),
            detail: format!("unshare(flags=0x{bits:x}) 失败: {err}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_compose() {
        let f = NsFlags::sandbox_default().to_clone_flags();
        assert_ne!(f & libc::CLONE_NEWUSER, 0);
        assert_ne!(f & libc::CLONE_NEWNET, 0);
        assert_ne!(f & libc::CLONE_NEWNS, 0);
        assert_ne!(f & libc::CLONE_NEWPID, 0);
    }

    #[test]
    fn container_detection_runs() {
        // 只验证函数可执行不 panic；结果依环境而定。
        let _ = in_container();
        let _ = userns_sysctl_permits();
    }
}
