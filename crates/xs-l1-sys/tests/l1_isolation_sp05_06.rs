// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! L1 隔离有效性集成测试：SP-L1-05（网络默认拒绝）、SP-L1-06（PID namespace 语义）。
//!
//! SP-L1-05 双防线分别验证（docs/01 v5：禁止只验证联合结果导致其中一道从未真正被触发）：
//!   - 防线一 netns：unshare `CLONE_NEWNET` 后新命名空间无任何网络接口，TCP connect 必失败；
//!   - 防线二 landlock-net：ABI v3+ 声明网络权限但不添加 `NET_PORT` 规则，
//!     enforce 后 TCP connect 返回 EACCES（内核 6.2+/ABI>=3 时启用，否则 `not_applicable`）。
//!
//! SP-L1-06：PID namespace 内 init（PID 1）语义——子进程视角 getpid()==1、
//! fork 出的后代为 PID 2、waitpid 回收后无僵尸积累。

use std::net::TcpStream;
use std::os::unix::io::RawFd;
use std::time::Duration;

use xs_l1_sys::{create_ruleset_with_net, enforce, probe_abi, set_no_new_privs};

/// CI 容器环境可能无法执行 unshare(CLONE_NEWNET/CLONE_NEWPID) 等隔离原语。
/// 子进程以本码退出，父进程识别后跳过测试（非失败）。
const NOT_APPLICABLE: i32 = 125;

/// 探测环境可建立性（A 级以下或 landlock 无 FS 维度时按规约标记 `not_applicable`）。
fn require_isolatable() -> Option<()> {
    let report = xs_l1_sys::probe().ok()?;
    if report.effective == xs_core::AssuranceLevel::C {
        eprintln!("not_applicable: effective=C，跳过隔离有效性用例");
        return None;
    }
    let abi = probe_abi().ok()?;
    if !abi.has_fs() {
        eprintln!("not_applicable: landlock ABI 无文件系统维度");
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
    let exit_code = libc::WEXITSTATUS(status);
    if exit_code == NOT_APPLICABLE {
        eprintln!("not_applicable: {what}");
        return;
    }
    assert_eq!(exit_code, expect, "{what}");
}

/// 尝试 TCP 连接 127.0.0.1:9（discard 端口），返回是否连接成功。
///
/// 端口无需真实监听：netns 防线下无网络接口立即失败；
/// landlock-net 防线下内核在 connect 路径返回 EACCES。
fn try_tcp_connect() -> bool {
    TcpStream::connect_timeout(&"127.0.0.1:9".parse().unwrap(), Duration::from_millis(500)).is_ok()
}

// ---------------------------------------------------------------- SP-L1-05

/// SP-L1-05 `防线一：netns（CLONE_NEWNET）单独生效时网络默认拒绝`。
///
/// 只 unshare 网络命名空间（不建 veth），connect 必须失败——
/// 此用例不安装 landlock，证明 netns 防线独立成立。
#[test]
fn sp_l1_05_netns_alone_blocks_tcp_connect() {
    if require_isolatable().is_none() {
        return;
    }
    run_child_expect(
        || {
            // 只 unshare netns：新命名空间无接口，任何 TCP connect 必失败
            let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
            if ret != 0 {
                return NOT_APPLICABLE;
            }
            i32::from(try_tcp_connect())
        },
        0,
        "SP-L1-05 失败：netns 单独生效时 TCP connect 未被拒绝",
    );
}

/// SP_L1-05 防线二：landlock-net（ABI v3+）单独生效时网络默认拒绝。
///
/// 不 unshare netns（保留宿主网络栈），仅 enforce 含网络维度的 ruleset：
/// connect 必须被 landlock 拒绝（EACCES）。ABI<3 时按规约 `not_applicable`。
#[test]
fn sp_l1_05_landlock_net_alone_blocks_tcp_connect() {
    if require_isolatable().is_none() {
        return;
    }
    let abi = probe_abi().expect("ABI 探测失败");
    if !abi.has_network() {
        eprintln!(
            "not_applicable: landlock ABI {} 无网络维度（需 >=3）",
            abi.0
        );
        return;
    }
    run_child_expect(
        || {
            if set_no_new_privs().is_err() {
                return NOT_APPLICABLE;
            }
            // 含网络维度的 ruleset：声明 BIND|CONNECT 但无任何 NET_PORT 授权 → 全拒
            let rs = match create_ruleset_with_net() {
                Ok(r) => r,
                Err(_) => return 126,
            };
            if enforce(&rs).is_err() {
                return NOT_APPLICABLE;
            }
            // landlock 拒绝 connect 时 errno 为 EACCES（Permission denied）
            let blocked = !try_tcp_connect()
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
            i32::from(!blocked)
        },
        0,
        "SP-L1-05 失败：landlock-net 单独生效时 TCP connect 未被拒绝（或 errno 非 EACCES）",
    );
}

// ---------------------------------------------------------------- SP-L1-06

/// SP-L1-06：PID namespace 内 init 语义正确。
///
/// 子进程 `unshare(CLONE_NEWPID)` 后再 fork：孙进程视角 getpid()==1（PID ns init），
/// 孙进程内再 fork 的重孙进程 getpid()==2，waitpid 回收后 /proc/self 无僵尸积累。
#[test]
fn sp_l1_06_pid_ns_init_semantics() {
    if require_isolatable().is_none() {
        return;
    }
    run_child_expect(
        || {
            // unshare PID ns：调用者自身不进入新 ns，其后代才进入（CLONE_NEWPID 语义）
            let ret = unsafe { libc::unshare(libc::CLONE_NEWPID) };
            if ret != 0 {
                return NOT_APPLICABLE;
            }
            let grandchild = unsafe { libc::fork() };
            if grandchild < 0 {
                return NOT_APPLICABLE;
            }
            if grandchild == 0 {
                // 孙进程：新 PID ns 的 init，getpid() 必须为 1
                let my_pid = unsafe { libc::getpid() };
                if my_pid != 1 {
                    unsafe { libc::_exit(1) };
                }
                // init 再 fork：重孙进程 PID 应为 2
                let great = unsafe { libc::fork() };
                if great < 0 {
                    unsafe { libc::_exit(1) };
                }
                if great == 0 {
                    let great_pid = unsafe { libc::getpid() };
                    unsafe { libc::_exit(i32::from(great_pid != 2)) };
                }
                // init 回收重孙进程（waitpid），验证僵尸回收语义
                let mut st = 0;
                let wr = unsafe { libc::waitpid(great, &raw mut st, 0) };
                let reaped = wr == great && libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0;
                unsafe { libc::_exit(i32::from(!reaped)) };
            }
            // 中间层（unshare 调用者的子进程）回收孙进程
            let mut st = 0;
            let wr = unsafe { libc::waitpid(grandchild, &raw mut st, 0) };
            if wr != grandchild || !libc::WIFEXITED(st) {
                return 1;
            }
            libc::WEXITSTATUS(st)
        },
        0,
        "SP-L1-06 失败：PID ns init 语义不正确（getpid!=1 / 后代 PID 异常 / 回收失败）",
    );
}

/// SP-L1-06：PID ns 内信号语义——init 进程对 SIGTERM 默认不退出（需显式安装 handler）。
///
/// PID ns 的 init 受到特殊保护：未安装 handler 的信号被忽略（与系统 init 一致），
/// 这防止沙箱 init 被意外信号击杀导致整个 PID ns 崩溃。
#[test]
fn sp_l1_06_pid_ns_init_signal_protection() {
    if require_isolatable().is_none() {
        return;
    }
    run_child_expect(
        || {
            let ret = unsafe { libc::unshare(libc::CLONE_NEWPID) };
            if ret != 0 {
                return NOT_APPLICABLE;
            }
            let grandchild = unsafe { libc::fork() };
            if grandchild < 0 {
                return NOT_APPLICABLE;
            }
            if grandchild == 0 {
                // 孙进程（PID ns init，PID==1）：未装 handler 时给自己发 SIGTERM 应被忽略
                unsafe { libc::raise(libc::SIGTERM) };
                // 仍存活即通过（被信号杀死则根本不会执行到这里）
                unsafe { libc::_exit(0) };
            }
            let mut st = 0;
            let wr = unsafe { libc::waitpid(grandchild, &raw mut st, 0) };
            if wr != grandchild {
                return 1;
            }
            // init 应正常退出（0）而非被 SIGTERM 杀死（WIFSIGNALED）
            i32::from(!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0))
        },
        0,
        "SP-L1-06 失败：PID ns init 未获得信号保护（被 SIGTERM 击杀）",
    );
}

/// 辅助：保持 `RawFd` 导入被使用（clippy 防 `unused_imports` 抖动）。
#[allow(dead_code)]
fn _assert_rawfd_used(fd: RawFd) -> RawFd {
    fd
}
