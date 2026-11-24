// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M4 Scheduled 级混沌测试：P3 fanotify 文件访问拒绝注入（docs/11-CHAOS-ENGINEERING.md 第 2.1 节）。
//!
//! 故障注入与恢复验证：
//! - `fanotify_init` + `fanotify_mark` 对沙箱工作目录注入 `FAN_DENY`；
//! - 沙箱内进程读/写受管控文件 → EACCES（errno 13）；
//! - supervisor 不受影响，后续沙箱实例正常工作；
//! - 测试结束后关闭 fanotify fd 自动清理 marks，确保环境复原。

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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

struct FanotifyCleanup {
    fd: Option<OwnedFd>,
    workspace: String,
}

impl FanotifyCleanup {
    fn new(workspace: &str) -> Self {
        FanotifyCleanup {
            fd: None,
            workspace: workspace.to_string(),
        }
    }

    fn set_fd(&mut self, fd: OwnedFd) {
        self.fd = Some(fd);
    }
}

impl Drop for FanotifyCleanup {
    fn drop(&mut self) {
        drop(self.fd.take());
        thread::sleep(Duration::from_millis(50));
        let _ = fs::remove_dir_all(&self.workspace);
    }
}

fn fanotify_deny_loop(raw_fd: i32, stop_flag: Arc<AtomicBool>) {
    let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut buf = vec![0u8; meta_size + 256];

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };

        if n <= 0 {
            thread::sleep(Duration::from_millis(10));
            continue;
        }

        let mut offset = 0usize;
        while offset + meta_size <= n as usize {
            let meta: &libc::fanotify_event_metadata = unsafe {
                &*buf
                    .as_ptr()
                    .add(offset)
                    .cast::<libc::fanotify_event_metadata>()
            };

            if meta.mask & (libc::FAN_OPEN_PERM) != 0 || meta.mask & (libc::FAN_ACCESS_PERM) != 0 {
                let resp = libc::fanotify_response {
                    fd: meta.fd,
                    response: libc::FAN_DENY,
                };
                unsafe {
                    libc::write(
                        raw_fd,
                        (&raw const resp).cast::<libc::c_void>(),
                        std::mem::size_of::<libc::fanotify_response>(),
                    );
                }
            }

            if meta.event_len == 0 {
                break;
            }
            offset += meta.event_len as usize;
        }
    }
}

#[test]
fn chaos_fanotify_eacces_sandbox_open_denied_supervisor_survives() {
    if !running_as_root() {
        eprintln!("not_applicable: 需要 root 权限操作 fanotify（CAP_SYS_ADMIN）");
        return;
    }

    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_REPORT_FID,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if fd < 0 {
        let err = unsafe { *libc::__errno_location() };
        eprintln!("not_applicable: fanotify_init 失败 (errno={err})");
        return;
    }
    let _drop_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let _guard = SPAWN_TEST_LOCK.lock().unwrap();

    let workspace = "/tmp/xs_chaos_fanotify_mnt";
    let _ = fs::remove_dir_all(workspace);
    fs::create_dir_all(workspace).expect("创建 fanotify 测试工作目录应成功");

    let test_file = format!("{workspace}/test.dat");
    fs::write(&test_file, b"hello fanotify chaos test").expect("写入测试文件应成功");

    let mut cleanup = FanotifyCleanup::new(workspace);

    let fan_fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_REPORT_FID,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    assert!(fan_fd >= 0, "fanotify_init 应成功");
    let fan_owned = unsafe { OwnedFd::from_raw_fd(fan_fd) };
    let fan_raw = fan_owned.as_raw_fd();
    cleanup.set_fd(fan_owned);

    let workspace_c = std::ffi::CString::new(workspace).expect("CString");
    let mark_ret = unsafe {
        libc::fanotify_mark(
            fan_raw,
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
            libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM,
            libc::AT_FDCWD,
            workspace_c.as_ptr(),
        )
    };
    assert_eq!(mark_ret, 0, "fanotify_mark 应成功");

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let handler = thread::spawn(move || fanotify_deny_loop(fan_raw, stop_clone));
    thread::sleep(Duration::from_millis(100));

    let Some(domain) = require_domain_with_workspace(workspace) else {
        stop_flag.store(true, Ordering::Relaxed);
        let _ = handler.join();
        return;
    };

    let cat_cmd = format!("cat {test_file} 2>/dev/null; exit $?");
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", &cat_cmd]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功");

    assert_ne!(
        status,
        ExitStatus::Exited(0),
        "SP-G-01 失败：fanotify DENY 注入后沙箱内 cat 竟成功"
    );

    let Some(domain2) = require_domain_with_workspace(workspace) else {
        stop_flag.store(true, Ordering::Relaxed);
        let _ = handler.join();
        return;
    };
    let pid2 = domain2.spawn(&cmd("/bin/true", &[])).expect("spawn 应正常");
    let st2 = domain2.wait(pid2).expect("回收应成功");
    assert_eq!(st2, ExitStatus::Exited(0), "supervisor 在注入后应正常工作");

    stop_flag.store(true, Ordering::Relaxed);
    let _ = handler.join();
}

#[test]
fn chaos_fanotify_eacces_supervisor_survives_after_fd_close() {
    if !running_as_root() {
        eprintln!("not_applicable: 需要 root 权限操作 fanotify（CAP_SYS_ADMIN）");
        return;
    }

    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_REPORT_FID,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if fd < 0 {
        let err = unsafe { *libc::__errno_location() };
        eprintln!("not_applicable: fanotify_init 失败 (errno={err})");
        return;
    }
    let _drop_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let _guard = SPAWN_TEST_LOCK.lock().unwrap();

    let workspace = "/tmp/xs_chaos_fanotify_mnt2";
    let _ = fs::remove_dir_all(workspace);
    fs::create_dir_all(workspace).expect("创建工作目录应成功");

    let test_file = format!("{workspace}/test.dat");
    fs::write(&test_file, b"hello").expect("写入测试文件应成功");

    let _cleanup = FanotifyCleanup::new(workspace);

    let fan_fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_REPORT_FID,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    assert!(fan_fd >= 0, "fanotify_init 应成功");
    let fan_owned = unsafe { OwnedFd::from_raw_fd(fan_fd) };
    let fan_raw = fan_owned.as_raw_fd();

    let workspace_c = std::ffi::CString::new(workspace).expect("CString");
    let mark_ret = unsafe {
        libc::fanotify_mark(
            fan_raw,
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
            libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM,
            libc::AT_FDCWD,
            workspace_c.as_ptr(),
        )
    };
    assert_eq!(mark_ret, 0, "fanotify_mark 应成功");

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let handler = thread::spawn(move || fanotify_deny_loop(fan_raw, stop_clone));
    thread::sleep(Duration::from_millis(100));

    let Some(domain) = require_domain_with_workspace(workspace) else {
        stop_flag.store(true, Ordering::Relaxed);
        let _ = handler.join();
        return;
    };

    let cat_cmd = format!("cat {test_file} 2>/dev/null; exit $?");
    let pid = domain
        .spawn(&cmd("/bin/sh", &["-c", &cat_cmd]))
        .expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功");
    assert_ne!(status, ExitStatus::Exited(0), "fanotify DENY 应使 cat 失败");

    stop_flag.store(true, Ordering::Relaxed);
    let _ = handler.join();
    drop(fan_owned);
    thread::sleep(Duration::from_millis(100));

    let Some(domain2) = require_domain_with_workspace(workspace) else {
        return;
    };
    let pid2 = domain2
        .spawn(&cmd("/bin/true", &[]))
        .expect("fd 关闭后 spawn 应正常");
    let st2 = domain2.wait(pid2).expect("回收应成功");
    assert_eq!(
        st2,
        ExitStatus::Exited(0),
        "fd 关闭后 supervisor 应恢复正常"
    );
}
