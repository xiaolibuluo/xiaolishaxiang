// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! SP-G-02 探测一致性集成测试（docs/01：报告可用的每一项机制必须实测验证）。
//!
//! - seccomp：报 filter 已安装且含 TSYNC——TSYNC 语义实测（既有线程同样受限）；
//! - `landlock：probe()` 报告的可用性与 `probe_abi()` 实测 ABI 一致；
//! - cgroup：真实委派探测由 xs-l2-res 的 `delegation_probe_is_real` 承担（已绿）。

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use xs_l1_sys::{install, probe, probe_abi, set_no_new_privs, SeccompAllowlist};

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

/// SP-G-02：seccomp TSYNC 语义实测——install 之前已存在的线程，
/// 在 TSYNC 安装后调用 ptrace 同样被 EPERM 拒绝。
///
/// 非 TSYNC 安装只约束调用线程（既有线程不受限），TSYNC 则同步全部既有线程；
/// 本用例是 TSYNC 与 `SECCOMP_FILTER_FLAG_TSYNC` 缺位之间的唯一可观测差异点。
///
/// 同步设计避开 futex（不在最小 allowlist）：线程间只用原子量 + `sched_yield` 自旋。
#[test]
fn sp_g_02_seccomp_tsync_covers_existing_threads() {
    run_child_expect(
        || {
            static GO: AtomicBool = AtomicBool::new(false);
            static RESULT: AtomicI32 = AtomicI32::new(0);
            static DONE: AtomicBool = AtomicBool::new(false);

            // 先创建既有线程（install 前），它自旋等待主线程完成 TSYNC 安装。
            let worker = std::thread::spawn(|| {
                while !GO.load(Ordering::Acquire) {
                    unsafe { libc::sched_yield() };
                }
                // install 完成后：既有线程调用 ptrace（不在 allowlist），应被 EPERM。
                let ret = unsafe { libc::syscall(libc::SYS_ptrace, 16, 1, 0, 0, 0, 0) };
                let errno = if ret == -1 {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    0
                };
                RESULT.store(errno, Ordering::Release);
                DONE.store(true, Ordering::Release);
            });
            // worker 句柄不 join（join 会走 futex，不在最小 allowlist）；故意泄漏。
            std::mem::forget(worker);

            if set_no_new_privs().is_err() {
                return 126;
            }
            let list = SeccompAllowlist::sandbox_minimal();
            if install(&list, true).is_err() {
                return 126;
            }
            // 通知既有线程发起 ptrace（TSYNC 生效则 EPERM）。
            GO.store(true, Ordering::Release);
            while !DONE.load(Ordering::Acquire) {
                unsafe { libc::sched_yield() };
            }
            let errno = RESULT.load(Ordering::Acquire);
            i32::from(errno != libc::EPERM)
        },
        0,
        "SP-G-02 失败：TSYNC 安装后既有线程的 ptrace 未被拒绝（TSYNC 未真正生效）",
    );
}

/// SP-G-02：seccomp filter 安装后 /proc/self/status 报告 Seccomp=2（filter 模式）
/// 且 `Seccomp_filters>=1（本用例不建` landlock 域，/proc 可读）。
#[test]
fn sp_g_02_seccomp_status_reports_filter_installed() {
    run_child_expect(
        || {
            if set_no_new_privs().is_err() {
                return 126;
            }
            let list = SeccompAllowlist::sandbox_minimal();
            if install(&list, true).is_err() {
                return 126;
            }
            // minimal allowlist 含 openat/read/close/fstat，/proc/self/status 可读。
            let status = match std::fs::read_to_string("/proc/self/status") {
                Ok(s) => s,
                Err(_) => return 1,
            };
            let seccomp_mode = status
                .lines()
                .find(|l| l.starts_with("Seccomp:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u32>().ok());
            let filters = status
                .lines()
                .find(|l| l.starts_with("Seccomp_filters:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u32>().ok());
            match (seccomp_mode, filters) {
                (Some(2), Some(n)) if n >= 1 => 0,
                _ => 1,
            }
        },
        0,
        "SP-G-02 失败：/proc/self/status 未报告 Seccomp=2 或 Seccomp_filters<1",
    );
}

/// `SP-G-02：probe()` 报告的 landlock 可用性与 `probe_abi()` 实测 ABI 严格一致，
/// 且网络维度声明（ABI>=3）与 `has_network()` 推导一致（禁止布尔化虚报）。
#[test]
fn sp_g_02_landlock_report_matches_measured_abi() {
    let abi = probe_abi().expect("probe_abi 应可执行");
    let report = probe().expect("probe 应返回报告");

    // 报告中的 landlock outcome 必须与实测 ABI 一致。
    let outcome = report
        .outcomes
        .iter()
        .find(|o| o.item == "landlock")
        .expect("报告必须含 landlock 项");
    assert_eq!(
        outcome.available,
        abi.has_fs(),
        "报告可用性与实测 ABI 不一致：abi={} available={}",
        abi.0,
        outcome.available
    );
    // 报告中的 ABI 版本字段必须与实测一致（SP-G-02：报 ABI 版本而非布尔）。
    assert_eq!(report.landlock_abi.0, abi.0, "报告 ABI 版本与实测不一致");
    // 网络维度声明一致性（A 级判定依赖 has_network）。
    assert_eq!(abi.has_network(), abi.0 >= 3);
}
