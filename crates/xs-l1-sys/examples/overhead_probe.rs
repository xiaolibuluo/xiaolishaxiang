// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 隔离开销预算实测工具（docs/04-TEST-MATRIX.md 性能基线前置，M2 实测回填 X/Y）。
//!
//! 测量口径：
//! - 基线路径：裸 fork -> execve(/bin/true) -> waitpid（无任何隔离层）；
//! - L1 `沙箱路径：L1Domain::spawn` -> `prepare_in_child` 五步顺序契约
//!   （unshare -> `no_new_privs` -> landlock -> seccomp TSYNC -> fd 白名单）
//!   -> execve -> waitpid；
//! - warmup 10 次 + 正式 100 次，取均值/中位数/P95；
//! - Y = 沙箱中位数 - 基线中位数（单次调用延迟增加，ms）；
//! - X = (1 - 沙箱吞吐/基线吞吐) * 100（吞吐损失，%）。
//!
//! 运行：cargo run --release -p xs-l1-sys --example `overhead_probe`

use std::path::PathBuf;
use std::time::{Duration, Instant};

use xs_l1_sys::{DomainSpec, L1Domain, PathGrant, SandboxCommand};

const WARMUP: usize = 10;
const ROUNDS: usize = 100;

/// 基线：裸 fork+execve+waitpid 一次（不经任何隔离层）。
fn baseline_once() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork 失败");
    if pid == 0 {
        let prog = std::ffi::CString::new("/bin/true").unwrap();
        let arg0 = prog.clone();
        let argv = [arg0.as_ptr(), std::ptr::null()];
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        // SAFETY：prog/argv 在调用期间存活；execve 成功不返回，失败由 _exit 兜底。
        unsafe {
            libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
}

/// 沙箱：L1Domain spawn+wait 一次（含完整五步顺序契约）。
fn sandbox_once(domain: &L1Domain) {
    let cmd = SandboxCommand {
        program: PathBuf::from("/bin/true"),
        args: vec![],
        env: vec![],
    };
    let pid = domain.spawn(&cmd).expect("spawn 应成功");
    let status = domain.wait(pid).expect("wait 应成功");
    assert!(status.is_success());
}

/// 采集 ROUNDS 次耗时样本（先跑 WARMUP 次预热）。
fn sample(mut f: impl FnMut()) -> Vec<Duration> {
    for _ in 0..WARMUP {
        f();
    }
    (0..ROUNDS)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect()
}

/// 统计：均值 / 中位数 / P95。
fn stats(samples: &[Duration]) -> (Duration, Duration, Duration) {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let mean = sorted.iter().sum::<Duration>() / sorted.len() as u32;
    let median = sorted[sorted.len() / 2];
    let p95 = sorted[sorted.len() * 95 / 100];
    (mean, median, p95)
}

fn main() {
    // 沙箱域：/bin /usr /lib /lib64 只读授权（/bin/true 动态链接自举所需）；
    // fd 白名单纳入本进程当前持有的 fd（SP-L1-04 合规形态，等效真实 supervisor
    // 在 fork 前收紧后的最小 fd 集）。
    let mut spec = DomainSpec::minimal();
    spec.grants.push(PathGrant::read_only("/bin"));
    spec.grants.push(PathGrant::read_only("/usr"));
    spec.grants.push(PathGrant::read_only("/lib"));
    spec.grants.push(PathGrant::read_only("/lib64"));
    let inherited: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map(|rd| {
            rd.filter_map(std::result::Result::ok)
                .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
                .collect()
        })
        .unwrap_or_default();
    spec.fd_whitelist.extend(inherited);
    let domain = L1Domain::establish(spec).expect("本机应可建立 L1 域");

    let base = sample(baseline_once);
    let sand = sample(|| sandbox_once(&domain));

    let (b_mean, b_med, b_p95) = stats(&base);
    let (s_mean, s_med, s_p95) = stats(&sand);

    // Y：单次调用延迟增加（中位数差，ms）；X：吞吐损失（%，按中位数次/秒换算）。
    let y_ms = s_med.as_secs_f64() * 1e3 - b_med.as_secs_f64() * 1e3;
    let b_ops = 1.0 / b_med.as_secs_f64();
    let s_ops = 1.0 / s_med.as_secs_f64();
    let x_pct = (1.0 - s_ops / b_ops) * 100.0;

    println!("==== 隔离开销实测（warmup={WARMUP} rounds={ROUNDS}）====");
    println!(
        "kernel: {}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    println!(
        "baseline : mean={:8.3}ms median={:8.3}ms p95={:8.3}ms  ({:.1} ops/s)",
        b_mean.as_secs_f64() * 1e3,
        b_med.as_secs_f64() * 1e3,
        b_p95.as_secs_f64() * 1e3,
        b_ops
    );
    println!(
        "sandbox  : mean={:8.3}ms median={:8.3}ms p95={:8.3}ms  ({:.1} ops/s)",
        s_mean.as_secs_f64() * 1e3,
        s_med.as_secs_f64() * 1e3,
        s_p95.as_secs_f64() * 1e3,
        s_ops
    );
    println!("---- 预算回填值 ----");
    println!("Y (单次调用延迟增加, 中位数) = {y_ms:.3} ms");
    println!("X (吞吐损失, 中位数口径)     = {x_pct:.1} %");
    println!(
        "P95 口径: 延迟增加 {:.3} ms",
        s_p95.as_secs_f64() * 1e3 - b_p95.as_secs_f64() * 1e3
    );
}
