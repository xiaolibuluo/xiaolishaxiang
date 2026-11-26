// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M4 Required 冲突测试（docs/04-TEST-MATRIX.md 第 2 级）：资源争用 /
//! 端口与路径冲突场景——隔离正确、无串扰、冲突失败路径 fail-closed。
//!
//! 覆盖三类冲突：
//!   1. 路径冲突：两个沙箱实例的 landlock 域各自授权不同目录，
//!      授权互不影响、互不泄漏（A 能写的 B 不能写，反之亦然）；
//!   2. 端口冲突（同命名空间）：同 netns 内重复 bind 同端口必须显式
//!      EADDRINUSE 失败，首个监听不受影响（不静默抢端口）；
//!   3. 端口冲突（跨命名空间）：不同 netns 中 bind 同端口号互不冲突，
//!      证明网络命名空间提供真正的端口资源隔离。

use std::net::TcpListener;

use xs_l1_sys::{add_path_grant, create_ruleset, enforce, probe, probe_abi, PathGrant};

/// CI 容器环境可能无法执行 landlock/unshare（缺 CAP_SYS_ADMIN 或被 seccomp profile 拦截）。
/// 子进程以本码退出，父进程识别后跳过测试（非失败）。
const NOT_APPLICABLE: i32 = 125;

/// 探测环境可建立性；C 档或 landlock 无 FS 维度时按规约标记 `not_applicable`。
fn require_isolatable() -> Option<()> {
    let report = probe().ok()?;
    if report.effective == xs_core::AssuranceLevel::C {
        eprintln!("not_applicable: effective=C，跳过冲突测试");
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

// ------------------------------------------------------- 路径冲突

/// 路径冲突：两个沙箱（两个子进程）各自的 landlock 域只授权自己的目录。
///
/// 隔离正确性断言：
/// - 沙箱 A 授权 /`tmp/xs_m4_sa，能写自己目录，不能写` /`tmp/xs_m4_sb（即使该`
///   目录对沙箱 B 是授权的）——landlock 域按进程独立生效，B 的授权不构成
///   A 的授权；
/// - 沙箱 B 对称验证；
/// - 两沙箱并发（先后 fork 并同时存活）时域建立互不影响。
#[test]
fn m4_path_grants_isolated_between_concurrent_sandboxes() {
    if require_isolatable().is_none() {
        return;
    }
    let dir_a = "/tmp/xs_m4_sa";
    let dir_b = "/tmp/xs_m4_sb";
    std::fs::create_dir_all(dir_a).expect("创建 dir_a");
    std::fs::create_dir_all(dir_b).expect("创建 dir_b");

    /// 子进程逻辑：建立只授权 own 的域，随后 own 可写、other 不可写。
    fn child(own: &'static str, other: &'static str) -> i32 {
        let rs = match create_ruleset() {
            Ok(r) => r,
            Err(_) => return NOT_APPLICABLE,
        };
        if add_path_grant(&rs, &PathGrant::read_write(own)).is_err() {
            return NOT_APPLICABLE;
        }
        if enforce(&rs).is_err() {
            return NOT_APPLICABLE;
        }
        let own_file = format!("{own}/owned.tmp");
        let other_file = format!("{other}/intrude.tmp");
        let own_ok = std::fs::write(&own_file, b"xs").is_ok();
        // 越权写对方授权目录必须被 landlock 拒绝（EACCES）。
        let other_blocked = std::fs::write(&other_file, b"xs").is_err();
        let _ = std::fs::remove_file(&own_file);
        let _ = std::fs::remove_file(&other_file);
        i32::from(!(own_ok && other_blocked))
    }

    // 两个子进程同时存活（父进程先 fork 两个再统一 wait），验证域并发独立。
    let pid_a = unsafe { libc::fork() };
    assert!(pid_a >= 0, "fork A 失败");
    if pid_a == 0 {
        unsafe { libc::_exit(child(dir_a, dir_b)) };
    }
    let pid_b = unsafe { libc::fork() };
    assert!(pid_b >= 0, "fork B 失败");
    if pid_b == 0 {
        unsafe { libc::_exit(child(dir_b, dir_a)) };
    }
    for (pid, name) in [(pid_a, "沙箱A"), (pid_b, "沙箱B")] {
        let mut status = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert!(libc::WIFEXITED(status), "{name}: 未正常退出");
        let exit_code = libc::WEXITSTATUS(status);
        if exit_code == NOT_APPLICABLE {
            eprintln!("not_applicable: {name} 环境不支持 landlock，跳过测试");
            continue;
        }
        assert_eq!(
            exit_code, 0,
            "M4 路径冲突失败：{name} 的授权目录不可写或越权写对方目录未被拦截"
        );
    }
    let _ = std::fs::remove_dir_all(dir_a);
    let _ = std::fs::remove_dir_all(dir_b);
}

// ------------------------------------------------------- 端口冲突（同命名空间）

/// 同 netns 内端口冲突：重复 bind 同端口必须显式 EADDRINUSE，
/// 且首个监听 socket 不受影响（冲突失败不串扰、不静默抢占）。
#[test]
fn m4_port_rebind_same_netns_fails_explicitly() {
    run_child_expect(
        || {
            let first = match TcpListener::bind("127.0.0.1:0") {
                Ok(l) => l,
                Err(_) => return NOT_APPLICABLE,
            };
            let port = match first.local_addr() {
                Ok(a) => a.port(),
                Err(_) => return NOT_APPLICABLE,
            };
            // 同命名空间重复 bind 同端口：必须失败。
            let second = TcpListener::bind(("127.0.0.1", port));
            let conflict_explicit = match &second {
                Err(e) => e.kind() == std::io::ErrorKind::AddrInUse,
                Ok(_) => false,
            };
            // 首个监听仍可用（冲突未造成串扰）。
            let first_alive = first.local_addr().is_ok();
            i32::from(!(conflict_explicit && first_alive))
        },
        0,
        "M4 端口冲突失败：同 netns 重复 bind 未显式 EADDRINUSE 或首个监听被串扰",
    );
}

// ------------------------------------------------------- 端口冲突（跨命名空间）

/// 跨 netns 端口隔离：父进程（宿主 netns）与子进程（新 netns）bind 同一
/// 端口号互不影响——网络命名空间提供真正的端口资源隔离（无串扰）。
///
/// 绑定地址用 0.0.0.0：新 netns 的 lo 默认 down，127.0.0.1 可能不可绑定，
/// 0.0.0.0 通配绑定不依赖具体接口状态。
#[test]
fn m4_port_same_number_bindable_across_netns() {
    if require_isolatable().is_none() {
        return;
    }
    // 父进程先在宿主 netns 绑定一个端口并保持监听。
    let parent_listener = TcpListener::bind("0.0.0.0:0").expect("父进程 bind 失败");
    let port = parent_listener.local_addr().expect("local_addr").port();

    run_child_expect(
        move || {
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return NOT_APPLICABLE;
            }
            // 新 netns 中 bind 同一端口号：命名空间隔离下必须成功（不冲突）。
            match TcpListener::bind(("0.0.0.0", port)) {
                Ok(_l) => 0,
                Err(_) => 1,
            }
        },
        0,
        "M4 端口隔离失败：新 netns 中 bind 同端口号被宿主监听串扰",
    );
    // 父进程监听在整个过程中保持有效（隔离不反向影响宿主）。
    assert!(parent_listener.local_addr().is_ok());
}
