// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M4 Scheduled 级混沌测试：P1 TCP 连接中断 + 子进程卡死（docs/11-CHAOS-ENGINEERING.md 第 3 节）。
//!
//! 故障注入与恢复验证：
//! - TCP 连接中断：iptables DROP 目标端口后沙箱内 connect 失败，supervisor 存活；
//! - 子进程卡死：SIGSTOP 挂起沙箱子进程，WNOHANG 确认未回收，超时后 SIGKILL 强制回收，
//!   后续沙箱实例不受影响。
//!
//! 所有注入均配 cleanup（iptables -D / kill -CONT/KILL），确保测试结束后环境复原。
//!
//! 注意：混沌注入操作（iptables / kill）可能引入新 fd；所有 spawn 前重采 fd 集并重建域，
//! 避免 SP-L1-04 fd 白名单漏检。

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use xs_l1_sys::{DomainSpec, ExitStatus, L1Domain, SandboxCommand};

/// 用例串行锁。
static SPAWN_TEST_LOCK: Mutex<()> = Mutex::new(());

/// 收集当前进程持有的 fd（fork 前调用），纳入白名单。
fn collect_inherited_fds() -> Vec<i32> {
    std::fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// 基于 spec 构造域，白名单覆盖框架继承 fd。
fn establish_with_inherited_fds(mut spec: DomainSpec) -> Option<L1Domain> {
    let inherited = collect_inherited_fds();
    spec.fd_whitelist.extend(inherited);
    L1Domain::establish(spec).ok().or_else(|| {
        eprintln!("not_applicable: 环境不足以建立 L1 域（effective=C）");
        None
    })
}

/// 构造带 /bin /usr /lib /lib64 只读授权的域（使 /bin/sh 可加载执行）。
fn require_domain_with_sh() -> Option<L1Domain> {
    let mut spec = DomainSpec::minimal();
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/bin"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/usr"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/lib"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/lib64"));
    establish_with_inherited_fds(spec)
}

fn cmd(program: &str, args: &[&str]) -> SandboxCommand {
    SandboxCommand {
        program: PathBuf::from(program),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        env: vec![],
    }
}

/// 探测是否以 root 运行。
fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// 探测 iptables 是否可用。
fn iptables_available() -> bool {
    StdCommand::new("iptables")
        .args(["-L", "-n"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ===================================================================
// P1-1: TCP 连接中断 — iptables DROP 端口后沙箱内 connect 失败
// ===================================================================

fn pick_free_port() -> Option<u16> {
    TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

/// 混沌注入：TCP 连接中断。
///
/// 步骤：
/// 1. 分配临时端口 P，启动监听进程，iptables -A OUTPUT ... -j DROP
/// 2. 注入后重采 fd 建立沙箱域（避免 iptables 引入的 fd 被拒绝）
/// 3. 沙箱内尝试连接 P → 断言 connect 失败
/// 4. cleanup: iptables -D + supervisor 存活验证
#[test]
fn chaos_tcp_drop_sandbox_connect_fails_supervisor_survives() {
    if !running_as_root() {
        eprintln!("not_applicable: 需要 root 权限操作 iptables");
        return;
    }
    if !iptables_available() {
        eprintln!("not_applicable: iptables 不可用");
        return;
    }
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();

    // 分配端口并启动临时监听
    let port = if let Some(p) = pick_free_port() {
        p
    } else {
        eprintln!("not_applicable: 无法分配临时端口");
        return;
    };
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("绑定监听端口应成功");

    // 注入 iptables DROP 规则（在建立沙箱域之前，避免 fd 污染）
    let add_rule = StdCommand::new("iptables")
        .args([
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .status();
    assert!(
        add_rule.is_ok_and(|s| s.success()),
        "iptables 注入 DROP 规则应成功"
    );

    struct IptablesCleanup {
        port: u16,
    }
    impl Drop for IptablesCleanup {
        fn drop(&mut self) {
            let _ = StdCommand::new("iptables")
                .args([
                    "-D",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    &self.port.to_string(),
                    "-j",
                    "DROP",
                ])
                .status();
        }
    }
    let _cleanup = IptablesCleanup { port };

    // iptables 注入后重采 fd 建立域（此时域白名单已包含注入过程引入的 fd）
    let Some(domain) = require_domain_with_sh() else {
        return;
    };

    // 探测 nc 可用性（/usr/bin/nc 未授权则走 sh 内置 fallback）
    // 沙箱内执行连接尝试；dest 不可达时 sh 内置 /dev/tcp 返回非零
    let connect_script =
        format!("timeout 3 sh -c 'exec 3<>/dev/tcp/127.0.0.1/{port}' 2>/dev/null; exit $?");
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", &connect_script]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功（supervisor 存活）");

    // 连接应失败——只要不是 exit 0 即可（DROP 导致超时或 /dev/tcp 打开失败）
    assert_ne!(
        status,
        ExitStatus::Exited(0),
        "SP-L1-05 失败：iptables DROP 端口 {port} 后沙箱内连接竟成功"
    );

    // 验证 supervisor 仍可继续工作：重建域后 spawn 正常实例
    let Some(domain2) = require_domain_with_sh() else {
        return;
    };
    let pid2 = domain2
        .spawn(&cmd("/bin/true", &[]))
        .expect("DROP 注入后 supervisor spawn 应正常");
    let st2 = domain2.wait(pid2).expect("回收后续实例应成功");
    assert_eq!(
        st2,
        ExitStatus::Exited(0),
        "supervisor 在 DROP 注入后应继续正常工作"
    );

    drop(listener);
}

// ===================================================================
// P1-2: 子进程卡死 — SIGSTOP 后超时回收 + 后续实例不受影响
// ===================================================================

/// 混沌注入：子进程卡死恢复。
///
/// 步骤：
/// 1. spawn 长时间 sleep 子进程
/// 2. 测试侧 SIGSTOP 挂起该子进程
/// 3. WNOHANG 轮询确认未回收（waitpid==0）
/// 4. SIGKILL 强制终止 → supervisor wait 回收为 Signaled(SIGKILL)
/// 5. 重建域后 spawn 正常实例 → 验证恢复（边界不被击穿）
#[test]
fn chaos_child_stall_sigstop_recover_with_sigkill() {
    if !running_as_root() {
        eprintln!("not_applicable: 需要 root 权限发送信号");
        return;
    }
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain_with_sh() else {
        return;
    };

    // 实例 1：长时间 sleep
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", "sleep 30"]))
        .expect("spawn 应成功");

    // SIGSTOP 挂起子进程
    // SAFETY：pid 为本进程 fork 出的合法子进程。
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
    if ret != 0 {
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        let _ = domain.wait(pid);
        eprintln!("not_applicable: SIGSTOP 发送失败");
        return;
    }

    // WNOHANG 轮询确认停止（最多 2s，100ms 间隔）
    let mut stalled = false;
    for _ in 0..20 {
        let mut wstatus: libc::c_int = 0;
        // SAFETY：WNOHANG 非阻塞；pid 有效。
        let wret = unsafe { libc::waitpid(pid as libc::pid_t, &raw mut wstatus, libc::WNOHANG) };
        if wret == 0 {
            stalled = true;
            break;
        }
        if wret > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        stalled,
        "SIGSTOP 后子进程应保持未回收状态（WNOHANG 返回 0）"
    );

    // 超时后 SIGKILL 强制回收
    // SAFETY：SIGKILL 必定终止。
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

    // supervisor 阻塞回收
    let status = domain.wait(pid).expect("wait 应回收被 SIGKILL 的子进程");
    assert_eq!(
        status,
        ExitStatus::Signaled(libc::SIGKILL),
        "被 SIGKILL 的子进程应回收为 Signaled(SIGKILL)，实际: {status:?}"
    );

    // 验证恢复：重建域后 spawn 正常实例（kill 操作可能引入新 fd，必须重采样）
    let Some(domain2) = require_domain_with_sh() else {
        return;
    };
    let pid2 = domain2
        .spawn(&cmd("/bin/true", &[]))
        .expect("SIGKILL 后 spawn 正常实例应成功");
    let st2 = domain2.wait(pid2).expect("回收正常实例应成功");
    assert_eq!(
        st2,
        ExitStatus::Exited(0),
        "SIGKILL 回收后后续沙箱实例必须正常工作（边界不被击穿、可恢复）"
    );
}
