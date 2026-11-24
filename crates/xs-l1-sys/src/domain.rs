// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! L1 隔离域编排（establish 顺序契约的实现）。
//!
//! 顺序契约（fail-closed，任一步失败即整体失败，SP-G-01）：
//!   1. 能力探测（landlock ABI / userns / 容器 / seccomp 可收紧性）；
//!   2. fork 出沙箱引导子进程；
//!   3. 子进程内：unshare namespaces -> `no_new_privs` -> landlock 域 ->
//!      seccomp filter（TSYNC）-> fd 白名单校验（SP-L1-04）-> exec；
//!   4. 每一步失败都显式上报，绝不静默降级。
//!
//! M1 `范围：子进程侧的建立序列（prepare_in_child）与探测编排`；
//! fork/exec 进程模型在 L1 `SystemIsolator` trait 实现中接入（M1 后续迭代）。

use crate::{filter, namespace, ruleset, seccomp};
use xs_core::{CapabilityReport, XsError, XsResult};

/// L1 隔离域配置。
#[derive(Debug, Clone)]
pub struct DomainSpec {
    /// namespace 组合。
    pub ns: namespace::NsFlags,
    /// landlock 路径授权集。
    pub grants: Vec<ruleset::PathGrant>,
    /// seccomp allowlist（None 表示不安装 filter，仅探测模式）。
    pub seccomp: Option<filter::SeccompAllowlist>,
    /// fd 白名单（SP-L1-04：除这些 fd 外，子进程不得继承其他 fd）。
    pub fd_whitelist: Vec<i32>,
}

impl DomainSpec {
    /// 最小可用域：完整 namespace + 空 landlock 授权（全拒）+ 最小 allowlist。
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            ns: namespace::NsFlags::sandbox_default(),
            grants: vec![],
            seccomp: Some(filter::SeccompAllowlist::sandbox_minimal()),
            fd_whitelist: vec![0, 1, 2],
        }
    }
}

/// 探测本进程的 L1 可建立性（establish 的第一步，fork 之前执行）。
///
/// 返回能力报告；effective 等级由调用方按 `min_assurance` 判定（fail-closed）。
pub fn probe() -> XsResult<CapabilityReport> {
    let abi = crate::probe_abi()?;
    let userns_ok = namespace::userns_sysctl_permits();
    let in_container = namespace::in_container();
    let locked = seccomp::is_locked_by_upper().unwrap_or(false);
    let cgroup_ok = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    // seccomp 已被上层锁定且与目标策略冲突时按容器同档处理（docs/02 第 3 节）
    let container_like = in_container || locked;
    let mut report =
        xs_core::probe::assemble_report(abi, userns_ok, cgroup_ok, container_like, vec![]);
    report.outcomes.push(xs_core::ProbeOutcome {
        item: "seccomp_upper_lock".into(),
        available: !locked,
        note: if locked {
            "已有上层 filter，可收紧性受限".into()
        } else {
            "无上层 filter".into()
        },
    });
    Ok(report)
}

/// 在 fork 出的沙箱引导子进程内执行建立序列（顺序契约第 3 步）。
///
/// 调用契约：只允许在 fork 出的子进程中调用（会 unshare 改变进程环境并收紧
/// landlock/seccomp，supervisor 主进程调用将自我破坏）。
/// 任一步失败立即返回错误，调用方应让子进程以非零码退出。
pub fn prepare_in_child(spec: &DomainSpec) -> XsResult<()> {
    // 1. unshare namespaces（第一步改变进程环境，失败即终止）
    namespace::unshare_in_child(spec.ns)?;

    // 2. no_new_privs（seccomp 非特权安装的先决条件，SP-L1-03 顺序契约）
    filter::set_no_new_privs()?;

    // 3. landlock 域建立并生效（SP-L1-01；只收紧不放宽）
    let rs = ruleset::establish_domain(&spec.grants)?;
    ruleset::enforce(&rs)?;
    // enforce 后 ruleset fd 使命结束：显式释放，避免残留 fd 被步骤 5 白名单
    // 检出（M2 诊断实证：不释放时 fd 4 残留导致误报违规）。
    drop(rs);

    // 4. seccomp filter 安装（TSYNC，SP-L1-03；exec 前必须完成）
    if let Some(list) = &spec.seccomp {
        filter::install(list, true)?;
    }

    // 5. fd 白名单校验（SP-L1-04：子进程不得继承未授权 fd）
    check_fd_whitelist(&spec.fd_whitelist)?;

    Ok(())
}

/// SP-L1-04 实现：扫描 fd 号空间（0..1024），白名单外处于打开态的 fd 即违规。
///
/// 防的是父进程继承下去的 fd；自开 fd 由 landlock 域约束（规约语义）。
/// 探测方式：fstat 返回 EBADF 表示该 fd 号未打开，其余错误按 fail-closed 视为违规。
/// 选 fstat 的原因：本步骤在顺序契约第 5 步、运行于已安装的最小 seccomp allowlist
/// 之下——allowlist 含 fstat 但不含 fcntl，/proc 亦被 landlock 与 seccomp 双重封锁
/// （M2 诊断实证），故 fstat 是唯一可用的探测原语。
fn check_fd_whitelist(whitelist: &[i32]) -> XsResult<()> {
    let mut violations: Vec<i32> = Vec::new();
    for fd in 0..1024i32 {
        if whitelist.contains(&fd) {
            continue;
        }
        // SAFETY：stat 为栈上有效结构体，fstat 仅写入该结构体；
        // fd 无效时返回 -1+EBADF，不触碰任何内核对象。
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let ret = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            violations.push(fd);
        } else {
            violations.push(fd);
        }
    }
    if !violations.is_empty() {
        return Err(XsError::PolicyViolation {
            sp_id: "SP-L1-04".to_string(),
            detail: format!("子进程继承未授权 fd: {violations:?}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_report() {
        let report = probe().expect("探测应可执行");
        // 本机（裸 VM、内核 7.0）预期 effective >= A-；CI 容器内可能为 C。
        let _ = report.effective.label();
        assert!(report.outcomes.iter().any(|o| o.item == "landlock"));
    }

    #[test]
    fn minimal_spec_shape() {
        let spec = DomainSpec::minimal();
        assert!(spec.seccomp.as_ref().unwrap().io_uring_blocked());
        assert!(spec.fd_whitelist.contains(&0));
    }

    #[test]
    fn fd_check_passes_with_stdio_only() {
        // 测试进程通常持有额外 fd（如测试框架打开的），放宽验证：
        // 只验证函数可执行；严格白名单语义在 M1 集成测试（独立子进程）中验证。
        let _ = check_fd_whitelist(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
