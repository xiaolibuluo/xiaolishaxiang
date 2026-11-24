// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 沙箱可观察性健康检查端点。
//!
//! `health()` 执行一次完整的隔离生命周期探针并返回结构化指标，
//! 可用于 Prometheus exporter、CLI 诊断或 /health HTTP 端点。
//! 输出格式对齐 soak_probe verdict.json（`docs/04-TEST-MATRIX.md` 第 3 级）。

use std::path::PathBuf;
use std::time::Instant;

use serde::Serialize;

use xs_l1_sys::{DomainSpec, L1Domain, PathGrant, SandboxCommand};

/// 健康检查指标快照。
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    /// 版本号（对齐 Cargo.toml workspace version）
    pub version: &'static str,
    /// 探针是否通过（隔离可用、/bin/true exit 0）
    pub sandbox_ok: bool,
    /// 单次 spawn+wait 延迟（微秒）
    pub latency_us: u64,
    /// 当前进程 VmRSS（KB）
    pub rss_kb: u64,
}

/// 执行一次健康探针：建立域 → spawn /bin/true → wait → 采集指标。
///
/// 失败时返回 `{sandbox_ok: false, latency_us: 0, ...}`，不 panic。
#[must_use]
pub fn health() -> HealthReport {
    let rss = self_rss_kb();
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

    let domain = match L1Domain::establish(spec) {
        Ok(d) => d,
        Err(_) => {
            return HealthReport {
                version: env!("CARGO_PKG_VERSION"),
                sandbox_ok: false,
                latency_us: 0,
                rss_kb: rss,
            };
        }
    };
    let cmd = SandboxCommand {
        program: PathBuf::from("/bin/true"),
        args: vec![],
        env: vec![],
    };
    let t0 = Instant::now();
    let ok = match domain.spawn(&cmd) {
        Ok(pid) => domain.wait(pid).map(|s| s.is_success()).unwrap_or(false),
        Err(_) => false,
    };
    let latency = t0.elapsed().as_micros() as u64;

    HealthReport {
        version: env!("CARGO_PKG_VERSION"),
        sandbox_ok: ok,
        latency_us: latency,
        rss_kb: rss,
    }
}

/// 从 /proc/self/status 读取 VmRSS（KB）。
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
