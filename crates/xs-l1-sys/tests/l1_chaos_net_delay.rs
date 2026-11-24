// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M4 Scheduled 级混沌测试：P2 网络延迟注入（docs/11-CHAOS-ENGINEERING.md 第 2.2 节）。
//!
//! 故障注入与恢复验证：
//! - nsenter 进入沙箱子进程的 netns，tc netem 注入 lo delay 200ms；
//! - nsenter tc qdisc show 确认 netem 规则存在；
//! - supervisor 不受影响，后续沙箱实例正常工作；
//! - cleanup: tc qdisc del 或子进程终止自动释放 netns 资源。

use std::path::PathBuf;
use std::process::Command as StdCommand;
use std::sync::Mutex;

use xs_l1_sys::{DomainSpec, ExitStatus, L1Domain, SandboxCommand};

static SPAWN_TEST_LOCK: Mutex<()> = Mutex::new(());

fn collect_inherited_fds() -> Vec<i32> {
    std::fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn establish_with_inherited_fds(mut spec: DomainSpec) -> Option<L1Domain> {
    let inherited = collect_inherited_fds();
    spec.fd_whitelist.extend(inherited);
    L1Domain::establish(spec).ok().or_else(|| {
        eprintln!("not_applicable: 环境不足以建立 L1 域（effective=C）");
        None
    })
}

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

fn running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn nsenter_exec(pid: u64, args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut cmd = StdCommand::new("nsenter");
    cmd.args(["-t", &pid.to_string(), "-n", "--"]);
    cmd.args(args);
    cmd.output()
}

#[test]
fn chaos_net_delay_tc_injected_supervisor_survives() {
    if !running_as_root() {
        eprintln!("not_applicable: 需要 root 权限操作 nsenter / tc");
        return;
    }
    let _guard = SPAWN_TEST_LOCK.lock().unwrap();
    let Some(domain) = require_domain_with_sh() else {
        return;
    };

    // spawn 沙箱子进程（sleep 保持 netns 存活）
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", "sleep 30"]))
        .expect("spawn 应成功");

    // 注：沙箱 netns 内 lo 默认无 qdisc，注入前确认
    let before = nsenter_exec(pid, &["tc", "qdisc", "show", "dev", "lo"])
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // 注入 tc netem delay 200ms 到沙箱 lo
    let injected = nsenter_exec(
        pid,
        &[
            "tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "200ms",
        ],
    )
    .is_ok_and(|o| o.status.success());

    if !injected {
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        let _ = domain.wait(pid);
        eprintln!("not_applicable: 内核不支持 tc netem（module 未加载）");
        return;
    }

    // 验证注入生效：tc qdisc show 输出含 "netem" 与 "delay"
    let after = nsenter_exec(pid, &["tc", "qdisc", "show", "dev", "lo"])
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    assert!(
        after.contains("netem") && after.contains("delay"),
        "tc netem delay 注入后 qdisc show 应含 netem+delay；注入前: {before}，注入后: {after}"
    );

    // cleanup：删除 tc 规则 + 终止子进程
    let _ = nsenter_exec(pid, &["tc", "qdisc", "del", "dev", "lo", "root"]);
    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    let _ = domain.wait(pid);

    // 验证 supervisor 恢复：重建域后正常 spawn
    let Some(domain2) = require_domain_with_sh() else {
        return;
    };
    let pid2 = domain2
        .spawn(&cmd("/bin/true", &[]))
        .expect("tc netem 注入后 supervisor spawn 应正常");
    let st2 = domain2.wait(pid2).expect("回收后续实例应成功");
    assert_eq!(
        st2,
        ExitStatus::Exited(0),
        "supervisor 在 tc netem 注入清理后应继续正常工作"
    );
}
