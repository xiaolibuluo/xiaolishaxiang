// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xs-api 编排层：SandboxConfig -> L1 `DomainSpec` -> `L1Domain` 的装配链路。
//!
//! 顺序（fail-closed 全链路，SP-G-01）：
//!   1. `配置校验（SandboxConfig::validate`）；
//!   2. L1 环境探测（probe -> `CapabilityReport`）；
//!   3. `min_assurance` 判定（effective < `min_assurance` 即拒绝）；
//!   4. 配置映射为 DomainSpec（namespace/landlock/seccomp/fd 白名单）；
//!   5. `L1Domain::establish` 建立域描述；
//!   6. `run()` 在域内启动命令并回收退出状态。

use xs_core::{AuditSink, CapabilityReport, SandboxConfig, XsError, XsResult};
use xs_l1_sys::{
    DomainSpec, ExitStatus, L1Domain, NsFlags, PathGrant, SandboxCommand, SeccompAllowlist,
};

/// 装配完成的沙箱（可运行）。
pub struct Sandbox {
    domain: L1Domain,
    report: CapabilityReport,
}

impl Sandbox {
    /// 探测时的能力报告（供审计与上层决策）。
    #[must_use]
    pub fn report(&self) -> &CapabilityReport {
        &self.report
    }

    /// 在沙箱内运行命令并等待退出，返回退出状态。
    ///
    /// D2 修复（SP-G-01）：执行前判定审计通道可用性，不可用即拒绝执行
    /// （no-record => no-execute 从接口声明变为执行语义）。
    pub fn run(&self, cmd: SandboxCommand) -> XsResult<ExitStatus> {
        let sink = xs_core::TracingAuditSink;
        if !sink.is_available() {
            return Err(XsError::AuditUnavailable {
                reason: "tracing subscriber 未初始化（INFO 级不可达），审计事件将丢失".to_string(),
            });
        }
        // 记录执行事件（审计通道可用性已判定）
        let event = xs_core::AuditEvent::new(
            xs_core::AuditKind::CapabilityRequest,
            None,
            "sandbox",
            format!("run {}", cmd.program.display()),
        );
        let _ = sink.record(&event)?;
        let pid = self.domain.spawn(&cmd)?;
        self.domain.wait(pid)
    }

    /// 域配置（只读）。
    #[must_use]
    pub fn domain(&self) -> &L1Domain {
        &self.domain
    }
}

/// 从 `SandboxConfig` 映射 L1 DomainSpec（配置 -> 隔离机制的翻译层）。
///
/// 映射规则：
/// - namespace 一律采用沙箱默认完整组合（userns/mount/pid/net）；
/// - landlock 授权：/tmp 读写（沙箱工作区）+ /usr、/lib、/lib64 只读（运行时库）；
/// - seccomp：最小 `allowlist；allow_io_uring=true` 时显式追加 `io_uring` 三件套
///   （SP-L1-03：默认关闭，开启即接受文档警示）；
/// - fd 白名单：stdio 三件套。
fn map_spec(config: &SandboxConfig) -> DomainSpec {
    let mut seccomp = SeccompAllowlist::sandbox_minimal();
    if config.allow_io_uring {
        seccomp = seccomp.allow(425).allow(426).allow(427);
    }
    DomainSpec {
        ns: NsFlags::sandbox_default(),
        grants: vec![
            PathGrant::read_write("/tmp"),
            PathGrant::read_only("/usr"),
            PathGrant::read_only("/lib"),
            PathGrant::read_only("/lib64"),
        ],
        seccomp: Some(seccomp),
        fd_whitelist: vec![0, 1, 2],
    }
}

/// 装配入口：配置 -> 探测 -> 判定 -> 建域。
///
/// 任一环节 fail-closed：配置非法、探测等级不足、建域失败都返回错误。
pub fn build(config: &SandboxConfig) -> XsResult<Sandbox> {
    // 1. 配置校验
    config.validate()?;

    // 2. 探测（只读，无副作用）
    let report = xs_l1_sys::probe()?;

    // 3. min_assurance 判定（SP-G-01：低于要求即拒绝）
    report.enforce(config.min_assurance)?;

    // 4. 映射 DomainSpec（D1 修复：fd 白名单严格为 stdio 三件套，SP-L1-04）
    // 验证报告 D1 实证：此前无条件并入 /proc/self/fd 全部继承 fd，使
    // 「白名单外不得继承 fd」退化为「宿主有什么就允许什么」，安全属性失效。
    // 修复后白名单固定为 [0,1,2]；白名单外的继承 fd 由 prepare_in_child
    // 第 5 步 check_fd_whitelist 检出并以 126 拒绝（fail-closed）。
    // 调用方（CLI/嵌入方）若持有额外 fd，应在 build 前自行关闭或重定向。
    //
    // D4 修复：landlock 不可用（ABI 无 FS 能力）时 grants 置空（B 级降级路径）。
    // 验证报告 D4 实证：无 landlock 内核上无条件注入路径授权导致必然执行失败。
    // 降级语义：无文件路径隔离，namespace/seccomp/netns 仍全生效；
    // min_assurance 判定（第 3 步）已保证降级仅在 B 级及以下配置时可达。
    let mut spec = map_spec(config);
    if !report.landlock_abi.has_fs() {
        spec.grants = vec![];
    }

    // 5. 建立域
    let domain = L1Domain::establish(spec)?;

    Ok(Sandbox { domain, report })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xs_core::{AssuranceLevel, CapabilitySet};

    fn cfg(level: AssuranceLevel) -> SandboxConfig {
        SandboxConfig {
            min_assurance: level,
            capabilities: CapabilitySet::new(),
            quota: None,
            allow_io_uring: false,
            network_allow: vec![],
        }
    }

    #[test]
    fn build_respects_min_assurance() {
        // 本机裸 VM（A 级）：min_assurance=A- 应成功，A 也应成功；
        // C 档环境（容器）则高等级必然失败——两种情况都必须 fail-closed 而非 panic。
        let report = xs_l1_sys::probe().expect("probe 可用");
        let try_build = |lvl| build(&cfg(lvl));
        match report.effective {
            AssuranceLevel::A => {
                assert!(try_build(AssuranceLevel::A).is_ok());
                assert!(try_build(AssuranceLevel::AMinus).is_ok());
                assert!(try_build(AssuranceLevel::B).is_ok());
            }
            AssuranceLevel::AMinus => {
                assert!(try_build(AssuranceLevel::A).is_err());
                assert!(try_build(AssuranceLevel::AMinus).is_ok());
            }
            AssuranceLevel::B => {
                assert!(try_build(AssuranceLevel::AMinus).is_err());
                assert!(try_build(AssuranceLevel::B).is_ok());
            }
            AssuranceLevel::C => {
                // C 档：L1Domain::establish 或 enforce 之一必须拒绝
                assert!(try_build(AssuranceLevel::B).is_err());
            }
        }
    }

    #[test]
    fn map_spec_defaults() {
        let spec = map_spec(&cfg(AssuranceLevel::AMinus));
        assert!(spec.seccomp.as_ref().unwrap().io_uring_blocked());
        assert_eq!(spec.fd_whitelist, vec![0, 1, 2]);
        assert!(spec.grants.len() >= 2);
    }

    #[test]
    fn map_spec_io_uring_optin() {
        let mut c = cfg(AssuranceLevel::AMinus);
        c.allow_io_uring = true;
        let spec = map_spec(&c);
        assert!(!spec.seccomp.as_ref().unwrap().io_uring_blocked());
    }
}
