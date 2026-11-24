// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 三层隔离的统一 trait 定义。
//!
//! 三层各自实现统一接口，逐层收紧、可独立启用、可组合叠加；
//! 层间只通过窄接口通信，单层失效不波及其他层。
//! 抽象保留是为测试替身与未来 VM 后端留口，不做跨操作系统抽象（仅 Linux）。

use crate::assurance::{AssuranceLevel, CapabilityReport};
use crate::error::XsResult;

/// 隔离层通用出口：运行时探测后的能力报告与有效保证等级。
///
/// 返回值必须是探测后的有效值（effective），禁止静态承诺。
pub trait AssuranceProbe {
    /// 探测并返回能力报告（SP-G-02：报告可用 = 实测通过）。
    fn capabilities(&self) -> XsResult<CapabilityReport>;

    /// 返回探测导出的有效保证等级。
    fn assurance_level(&self) -> AssuranceLevel;
}

/// L1 系统隔离层 trait。
///
/// 职责：文件系统视图、系统调用、进程边界、网络边界隔离。
/// 实现必须 fail-closed：任一安装步骤顺序错误或部分失败即拒绝启动。
pub trait SystemIsolator: AssuranceProbe {
    /// 沙箱内进程的可执行命令与参数。
    type Command;
    /// L1 隔离域句柄（建立后只收紧不放宽）。
    type Domain;

    /// 建立隔离域（在 fork 子进程之前调用，见 SP-L1-04）。
    ///
    /// 失败必须返回 IsolatorSetupFailed，禁止部分生效后静默继续。
    fn establish(&self) -> XsResult<Self::Domain>;

    /// 在已建立的隔离域内启动受控命令。
    fn spawn(&self, domain: &Self::Domain, cmd: Self::Command) -> XsResult<u64>;

    /// 拆除隔离域并回收资源（含 PID namespace 内僵尸回收语义）。
    fn teardown(&self, domain: Self::Domain) -> XsResult<()>;
}

/// L2 资源治理层 trait。
///
/// 职责：CPU / 内存 / IO / 网络配额、限流与背压。
pub trait ResourceGovernor: AssuranceProbe {
    /// 资源配额描述。
    type Quota;
    /// 背压信号。
    type Backpressure;

    /// 应用配额到指定隔离域/进程组（须真实委派，SP-G-02）。
    fn apply_quota(&self, subject: u64, quota: &Self::Quota) -> XsResult<()>;

    /// 查询当前背压状态（用于审计与上层调度）。
    fn backpressure(&self, subject: u64) -> XsResult<Self::Backpressure>;
}

/// L3 运行时隔离层 trait。
///
/// 职责：内存安全执行、能力（capability）最小授权。
pub trait RuntimeSandbox: AssuranceProbe {
    /// 运行时实例句柄。
    type Instance;
    /// 能力句柄（伪造/复用/越权必须失败，SP-L3-01）。
    type Capability;

    /// 加载受控模块并创建实例。
    fn instantiate(&self, module: &[u8]) -> XsResult<Self::Instance>;

    /// 为实例授予声明过的能力。
    fn grant(&self, instance: &Self::Instance, cap: Self::Capability) -> XsResult<()>;

    /// 调用实例入口。
    fn invoke(&self, instance: &mut Self::Instance) -> XsResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 编译期验证 trait 可被正常实现与静态分发。
    #[test]
    fn traits_are_implementable() {
        struct Dummy;
        impl AssuranceProbe for Dummy {
            fn capabilities(&self) -> XsResult<CapabilityReport> {
                Ok(CapabilityReport {
                    kernel: "test".into(),
                    landlock_abi: crate::assurance::LandlockAbi::UNSUPPORTED,
                    outcomes: vec![],
                    effective: AssuranceLevel::C,
                })
            }
            fn assurance_level(&self) -> AssuranceLevel {
                AssuranceLevel::C
            }
        }
        let d = Dummy;
        assert_eq!(d.assurance_level(), AssuranceLevel::C);
        assert!(d.capabilities().is_ok());
    }
}
