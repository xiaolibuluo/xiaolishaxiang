// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M3 对抗逃逸语料：SP-L1-03 `io_uring` 默认关闭（docs/01-SECURITY-PROPERTIES.md）。
//!
//! 威胁背景（docs/00-THREAT-MODEL.md TH-A）：io_uring 的异步提交路径不经过
//! seccomp 对同步 syscall 的常规过滤点，是已知的 seccomp 绕过通道；本沙箱
//! 的对策是 allowlist 默认不含 `io_uring` 三件套（setup/enter/register），
//! 使 ring 根本无法建立（M0 Spike 探针 3 已实测可行，原型 spike/spike2.py）。
//!
//! 本文件在真实子进程中验证：安装最小 allowlist `后，io_uring_setup` /
//! `io_uring_enter` / `io_uring_register` 全部返回 EPERM，且进程存活继续执行
//! （拒绝语义为显式失败而非静默放行或误杀）。

use xs_l1_sys::{install, set_no_new_privs, SeccompAllowlist};

/// 探测环境可建立性；C 档时按规约标记 `not_applicable（禁止手写` skip）。
fn require_isolatable() -> Option<()> {
    let report = xs_l1_sys::probe().ok()?;
    if report.effective == xs_core::AssuranceLevel::C {
        eprintln!("not_applicable: effective=C，跳过 io_uring 阻断用例");
        return None;
    }
    Some(())
}

/// fork 子进程执行闭包并断言其以期望码退出。
fn run_child_expect(child_fn: impl FnOnce() -> i32, expect: i32, what: &str) {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork 失败");
    if pid == 0 {
        let code = child_fn();
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert!(libc::WIFEXITED(status), "{what}: 子进程未正常退出");
    assert_eq!(libc::WEXITSTATUS(status), expect, "{what}");
}

/// SP-L1-03：seccomp 最小 allowlist 下 `io_uring` 三件套全部被 EPERM 拒绝。
///
/// 语义要点：
/// - `io_uring_setup(0`, NULL)：参数本身就非法（entries=0），若返回 EPERM 之外的
///   错误（如 EINVAL）说明请求穿过了过滤器到达内核，即默认关闭失效——只有
///   EPERM 才是过滤器命中的证据；
/// - enter/register 以 fd=-1 空调用：同样只接受 EPERM，避免依赖合法 ring；
/// - 三件套检查通过后子进程继续执行并最终 _exit(0)，证明进程存活（拒绝动作
///   是 EPERM 而非 `SECCOMP_RET_KILL`）。
#[test]
fn sp_l1_03_io_uring_family_blocked_by_seccomp() {
    if require_isolatable().is_none() {
        return;
    }
    run_child_expect(
        || {
            if set_no_new_privs().is_err() {
                return 126;
            }
            let list = SeccompAllowlist::sandbox_minimal();
            if install(&list, false).is_err() {
                return 126;
            }
            let blocked = |nr: libc::c_long, a1: libc::c_long, a2: libc::c_long| -> bool {
                let ret = unsafe { libc::syscall(nr, a1, a2, 0, 0, 0, 0) };
                ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
            };
            // io_uring_setup(entries=0, params=NULL)
            let setup_blocked = blocked(libc::SYS_io_uring_setup, 0, 0);
            // io_uring_enter(fd=-1, to_submit=0)
            let enter_blocked = blocked(libc::SYS_io_uring_enter, -1, 0);
            // io_uring_register(fd=-1, opcode=0)
            let register_blocked = blocked(libc::SYS_io_uring_register, -1, 0);
            i32::from(!(setup_blocked && enter_blocked && register_blocked))
        },
        0,
        "SP-L1-03 失败：io_uring_setup/enter/register 未被 seccomp 默认拒绝（EPERM）",
    );
}

/// SP-L1-03 补充：拒绝后进程仍可对 allowlist 内 syscall 正常工作。
///
/// 验证拒绝动作的精确性——只拒 `io_uring，不误伤最小` allowlist 内的合法调用
/// （getpid 必在 allowlist 中，否则沙箱内进程连基本运行时都无法工作）。
#[test]
fn sp_l1_03_allowlist_survives_after_io_uring_rejection() {
    if require_isolatable().is_none() {
        return;
    }
    run_child_expect(
        || {
            if set_no_new_privs().is_err() {
                return 126;
            }
            let list = SeccompAllowlist::sandbox_minimal();
            if install(&list, false).is_err() {
                return 126;
            }
            // 先触发一次 io_uring_setup（应被 EPERM 拒绝）。
            let ret = unsafe { libc::syscall(libc::SYS_io_uring_setup, 0, 0, 0, 0, 0, 0) };
            let eperm =
                ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            if !eperm {
                return 1;
            }
            // 过滤器命中后进程存活且 allowlist 内调用正常。
            let pid = unsafe { libc::getpid() };
            if pid > 0 {
                0
            } else {
                2
            }
        },
        0,
        "SP-L1-03 失败：io_uring 拒绝后 allowlist 内 syscall 不可用（误伤或误杀）",
    );
}
