// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! soak 持久稳定测试核心（docs/04-TEST-MATRIX.md 第 3 级 Scheduled：≥24h，
//! 无泄漏、无性能漂移，不阻断 PR、阻断发布）。
//!
//! 运行方式：
//!   `XS_SOAK_DURATION_SECS=86400` `XS_SOAK_OUT=/path/soak.jsonl` \
//!     cargo run --release -p xs-l1-sys --example `soak_probe`
//!
//! 行为：
//! - 持续循环 spawn/wait 沙箱实例（/bin/true，含完整五步顺序契约）；
//! - 每 60 秒向 `XS_SOAK_OUT` 追加一行 JSONL 快照（增量落盘：进程被杀仍有数据）；
//! - 结束（到时或被信号终止）时写 `soak_verdict.json` 漂移判定：
//!   RSS 增长 > 10% 或延迟中位数漂移 > 15% 即 fail（发布阻断信号）。

use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use xs_l1_sys::{DomainSpec, L1Domain, PathGrant, SandboxCommand};

/// 快照间隔（秒）。
const SNAPSHOT_INTERVAL_SECS: u64 = 60;
/// RSS 增长告警阈值（相对首个快照）。
const RSS_GROWTH_LIMIT: f64 = 0.10;
/// 延迟中位数漂移告警阈值（首段 vs 末段）。
const LATENCY_DRIFT_LIMIT: f64 = 0.15;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 本进程 VmRSS（KB），取自 /proc/self/status（soak 主体未受 landlock 限制）。
fn self_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn median(sorted: &[u64]) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[sorted.len() / 2]
}

fn p95(sorted: &[u64]) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[sorted.len() * 95 / 100]
}

fn main() {
    let duration_secs: u64 = std::env::var("XS_SOAK_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(86400);
    let out_path = std::env::var("XS_SOAK_OUT")
        .unwrap_or_else(|_| "/root/xiaolishaxiang/artifacts/soak/soak.jsonl".to_string());
    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent).expect("创建输出目录失败");
    }

    // 沙箱域（与 overhead_probe 同口径：动态链接自举所需路径 + 当前 fd 白名单）。
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
    let cmd = SandboxCommand {
        program: PathBuf::from("/bin/true"),
        args: vec![],
        env: vec![],
    };

    let start = Instant::now();
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&out_path)
        .expect("打开输出文件失败");

    let mut iterations: u64 = 0;
    let mut failures: u64 = 0;
    let mut window_us: Vec<u64> = Vec::new();
    let mut last_snapshot = Instant::now();
    let mut first_med_us: Option<u64> = None;
    let mut first_rss_kb: Option<u64> = None;
    let mut last_med_us: u64 = 0;
    let mut last_rss_kb: u64 = 0;

    eprintln!("[soak] start: duration={duration_secs}s out={out_path}");
    while start.elapsed().as_secs() < duration_secs {
        let t = Instant::now();
        match domain.spawn(&cmd) {
            Ok(pid) => match domain.wait(pid) {
                Ok(st) if st.is_success() => {}
                _ => failures += 1,
            },
            Err(_) => failures += 1,
        }
        window_us.push(t.elapsed().as_micros() as u64);
        iterations += 1;

        if last_snapshot.elapsed().as_secs() >= SNAPSHOT_INTERVAL_SECS {
            window_us.sort_unstable();
            let med = median(&window_us);
            let p95v = p95(&window_us);
            let rss = self_rss_kb();
            if first_med_us.is_none() {
                first_med_us = Some(med);
                first_rss_kb = Some(rss);
            }
            last_med_us = med;
            last_rss_kb = rss;
            let line = format!(
                "{{\"ts\":{},\"elapsed\":{},\"iters\":{},\"fail\":{},\"rss_kb\":{},\"lat_med_us\":{},\"lat_p95_us\":{}}}\n",
                now_unix(),
                start.elapsed().as_secs(),
                iterations,
                failures,
                rss,
                med,
                p95v
            );
            let _ = out.write_all(line.as_bytes());
            let _ = out.flush();
            window_us.clear();
            last_snapshot = Instant::now();
        }
    }

    // 漂移判定：首段 vs 末段。
    let (first_med, first_rss) = (first_med_us.unwrap_or(1), first_rss_kb.unwrap_or(1));
    let lat_drift = if last_med_us > first_med {
        (last_med_us - first_med) as f64 / first_med.max(1) as f64
    } else {
        0.0
    };
    let rss_growth = if last_rss_kb > first_rss {
        (last_rss_kb - first_rss) as f64 / first_rss.max(1) as f64
    } else {
        0.0
    };
    let pass = failures == 0 && lat_drift <= LATENCY_DRIFT_LIMIT && rss_growth <= RSS_GROWTH_LIMIT;
    let verdict = format!(
        "{{\"verdict\":\"{}\",\"iterations\":{},\"failures\":{},\"first_med_us\":{},\"last_med_us\":{},\"latency_drift\":{:.4},\"first_rss_kb\":{},\"last_rss_kb\":{},\"rss_growth\":{:.4},\"duration_secs\":{}}}",
        if pass { "pass" } else { "fail" },
        iterations,
        failures,
        first_med,
        last_med_us,
        lat_drift,
        first_rss,
        last_rss_kb,
        rss_growth,
        start.elapsed().as_secs()
    );
    let verdict_path = format!("{out_path}.verdict.json");
    std::fs::write(&verdict_path, format!("{verdict}\n")).expect("写判定文件失败");
    eprintln!("[soak] done: {verdict}");
    if !pass {
        std::process::exit(1);
    }
}
