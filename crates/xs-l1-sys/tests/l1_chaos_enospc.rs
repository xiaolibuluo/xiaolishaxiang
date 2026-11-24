// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M4 Scheduled 级混沌测试：P2 ENOSPC 磁盘满注入（docs/11-CHAOS-ENGINEERING.md 第 2.1 节）。
//!
//! 故障注入与恢复验证：
//! - 创建小型 loop 设备（10MB ext4），挂载到临时目录后填满；
//! - 沙箱域授权该目录，沙箱内进程写入 → ENOSPC（errno 28）；
//! - supervisor 不受影响，后续沙箱实例正常工作；
//! - 所有注入均配 cleanup（umount + losetup -d），确保测试结束后环境复原。

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

fn require_domain_with_workspace(workspace: &str) -> Option<L1Domain> {
    let mut spec = DomainSpec::minimal();
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/bin"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/usr"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/lib"));
    spec.grants.push(xs_l1_sys::PathGrant::read_only("/lib64"));
    spec.grants
        .push(xs_l1_sys::PathGrant::read_write(workspace));
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

fn find_free_loop() -> Option<String> {
    for i in 3..=7 {
        let path = format!("/dev/loop{i}");
        let output = StdCommand::new("losetup")
            .args([path.as_str()])
            .output()
            .ok()?;
        if !output.status.success() {
            return Some(path);
        }
    }
    None
}

struct EnospcCleanup {
    mount_point: String,
    loop_device: String,
    image_file: String,
}

impl Drop for EnospcCleanup {
    fn drop(&mut self) {
        let _ = StdCommand::new("umount").arg(&self.mount_point).status();
        let _ = StdCommand::new("losetup")
            .args(["-d", &self.loop_device])
            .status();
        let _ = std::fs::remove_dir_all(&self.mount_point);
        let _ = std::fs::remove_file(&self.image_file);
    }
}

#[test]
fn chaos_enospc_sandbox_write_returns_enospc_supervisor_survives() {
    if !running_as_root() {
        eprintln!("not_applicable: 需要 root 权限操作 loop 设备与 mount");
        return;
    }

    let loop_dev = if let Some(d) = find_free_loop() {
        d
    } else {
        eprintln!("not_applicable: 无可用 loop 设备");
        return;
    };

    let _guard = SPAWN_TEST_LOCK.lock().unwrap();

    let mount_point = "/tmp/xs_chaos_enospc_mnt";
    let image_file = "/tmp/xs_chaos_enospc.img";
    let _ = std::fs::create_dir_all(mount_point);

    let dd = StdCommand::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={image_file}"),
            "bs=1M",
            "count=10",
        ])
        .status();
    assert!(dd.is_ok_and(|s| s.success()), "dd 创建磁盘镜像应成功");

    let mkfs = StdCommand::new("mkfs.ext4")
        .args(["-F", image_file])
        .status();
    assert!(mkfs.is_ok_and(|s| s.success()), "mkfs.ext4 应成功");

    let lo = StdCommand::new("losetup")
        .args([loop_dev.as_str(), image_file])
        .status();
    assert!(lo.is_ok_and(|s| s.success()), "losetup 应成功");

    let mnt = StdCommand::new("mount")
        .args([&loop_dev, mount_point])
        .status();
    assert!(mnt.is_ok_and(|s| s.success()), "mount 应成功");

    let _cleanup = EnospcCleanup {
        mount_point: mount_point.to_string(),
        loop_device: loop_dev.clone(),
        image_file: image_file.to_string(),
    };

    let mut filled = false;
    for i in 0..20 {
        let fill = StdCommand::new("dd")
            .args([
                "if=/dev/zero",
                &format!("of={mount_point}/fill_{i:02}.dat"),
                "bs=1M",
                "count=1",
            ])
            .output();
        if let Ok(out) = fill {
            if !out.status.success() {
                filled = true;
                break;
            }
        }
    }
    assert!(filled, "loop 设备应在 20 个 1MB 块内填满");

    let df = StdCommand::new("df").args([mount_point]).output().unwrap();
    let df_out = String::from_utf8_lossy(&df.stdout);
    assert!(
        df_out.contains("100%") || df_out.contains(" 0 "),
        "loop 设备应已满，df 输出: {df_out}"
    );

    let Some(domain) = require_domain_with_workspace(mount_point) else {
        return;
    };

    let write_script =
        format!("dd if=/dev/zero of={mount_point}/sw.dat bs=1K count=8 2>/dev/null; exit $?");
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", &write_script]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功（supervisor 存活）");

    assert_ne!(
        status,
        ExitStatus::Exited(0),
        "SP-G-01 失败：磁盘满后沙箱内写入竟成功（应返回 ENOSPC 且显式失败）"
    );

    let Some(domain2) = require_domain_with_workspace(mount_point) else {
        return;
    };
    let pid2 = domain2
        .spawn(&cmd("/bin/true", &[]))
        .expect("ENOSPC 注入后 supervisor spawn 应正常");
    let st2 = domain2.wait(pid2).expect("回收后续实例应成功");
    assert_eq!(
        st2,
        ExitStatus::Exited(0),
        "supervisor 在 ENOSPC 注入后应继续正常工作"
    );
}
