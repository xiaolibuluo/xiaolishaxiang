// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! L1 隔离有效性集成测试（端到端）。
//!
//! 验证 SP-L1-01（路径隔离）与 SP-L1-03（io_uring 阻断）在真实 fork 出的
//! 子进程中生效。这些用例在裸 VM（保证等级 A / A-）上预期通过；
//! 在容器等 C 档环境按 `capabilities()` 推导标记 `not_applicable` 而非失败。

use xs_l1_sys::{
    create_ruleset, enforce, install, probe, probe_abi, set_no_new_privs, DomainSpec, PathGrant,
    SeccompAllowlist,
};

/// 探测环境等级；C 档（容器/userns 不可用）时返回 None，用例标记不适用。
fn require_isolatable() -> Option<()> {
    let report = probe().ok()?;
    if report.effective == xs_core::AssuranceLevel::C {
        eprintln!(
            "not_applicable: 当前环境 effective=C（容器或 userns 不可用），跳过隔离有效性用例"
        );
        return None;
    }
    // landlock 必须具备文件系统维度，否则 SP-L1-01 无从谈起
    let abi = probe_abi().ok()?;
    if !abi.has_fs() {
        eprintln!("not_applicable: landlock ABI 不支持文件系统维度");
        return None;
    }
    Some(())
}

#[test]
fn sp_l1_01_unauthorized_path_read_blocked() {
    if require_isolatable().is_none() {
        return;
    }
    // 子进程：建立 landlock 域（只授权 /tmp），随后尝试读 /etc/hostname（未授权）。
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork 失败");
    if pid == 0 {
        let rs = match create_ruleset() {
            Ok(r) => r,
            Err(_) => unsafe { libc::_exit(126) },
        };
        let grant = PathGrant::read_write("/tmp");
        if xs_l1_sys::add_path_grant(&rs, &grant).is_err() {
            unsafe { libc::_exit(126) };
        }
        if enforce(&rs).is_err() {
            unsafe { libc::_exit(126) };
        }
        // 授权路径应可读
        let tmp_ok = std::fs::read_dir("/tmp").is_ok();
        // 未授权路径应被拒绝（landlock 返回 EACCES）
        let etc_blocked = std::fs::read_to_string("/etc/hostname").is_err();
        let code = i32::from(!(tmp_ok && etc_blocked));
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert!(libc::WIFEXITED(status), "子进程未正常退出");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "SP-L1-01 失败：未授权路径未被隔离或授权路径不可读"
    );
}

#[test]
fn sp_l1_03_io_uring_blocked_by_default() {
    if require_isolatable().is_none() {
        return;
    }
    // 子进程：安装最小 allowlist（不含 io_uring），调用 io_uring_setup 必须被拒。
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork 失败");
    if pid == 0 {
        if set_no_new_privs().is_err() {
            unsafe { libc::_exit(126) };
        }
        let list = SeccompAllowlist::sandbox_minimal();
        assert!(list.io_uring_blocked());
        if install(&list, false).is_err() {
            unsafe { libc::_exit(126) };
        }
        // io_uring_setup(425) 必须被 EPERM 拒绝（进程存活）
        const SYS_IO_URING_SETUP: libc::c_long = 425;
        let ret = unsafe { libc::syscall(SYS_IO_URING_SETUP, 8u32, std::ptr::null::<u8>()) };
        let blocked =
            ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
        unsafe { libc::_exit(i32::from(!blocked)) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert!(libc::WIFEXITED(status), "子进程未正常退出");
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "SP-L1-03 失败：io_uring_setup 未被默认阻断"
    );
}

#[test]
fn sp_l1_01_authorized_path_accessible() {
    if require_isolatable().is_none() {
        return;
    }
    // 授权 /tmp 读写：子进程内应能在 /tmp 下创建并读取文件。
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork 失败");
    if pid == 0 {
        let rs = match create_ruleset() {
            Ok(r) => r,
            Err(_) => unsafe { libc::_exit(126) },
        };
        let grant = PathGrant::read_write("/tmp");
        if xs_l1_sys::add_path_grant(&rs, &grant).is_err() {
            unsafe { libc::_exit(126) };
        }
        if enforce(&rs).is_err() {
            unsafe { libc::_exit(126) };
        }
        let test_file = "/tmp/xs_l1_test_authorized.tmp";
        let w = std::fs::write(test_file, b"xs");
        let r = std::fs::read_to_string(test_file);
        let _ = std::fs::remove_file(test_file);
        let ok = w.is_ok() && matches!(r.as_deref(), Ok("xs"));
        unsafe { libc::_exit(i32::from(!ok)) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert_eq!(libc::WEXITSTATUS(status), 0, "授权路径 /tmp 应可读写");
}

#[test]
fn env_probe_report_is_available() {
    // 探测报告本身必须可用（SP-G-02 一致性的一端）。
    let report = probe().expect("probe 应返回报告");
    assert_ne!(report.kernel, "");
    assert!(report.outcomes.iter().any(|o| o.item == "landlock"));
    let spec = DomainSpec::minimal();
    assert!(spec.seccomp.as_ref().unwrap().io_uring_blocked());
}
