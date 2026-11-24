// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 对外门面 API。
//!
//! 上层（CLI / 嵌入方）只依赖本 crate，不直接依赖各层实现。
//! M1 提供配置装配的最小骨架；三层组合编排在后续里程碑完成。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod health;
pub mod sandbox;

pub use health::{health, HealthReport};
pub use sandbox::{build, Sandbox};
pub use xs_core::{
    AssuranceLevel, CapabilityReport, CapabilitySet, LandlockAbi, ResourceQuota, SandboxConfig,
    XsError, XsResult,
};
pub use xs_l1_sys::{probe, ExitStatus, SandboxCommand};

/// 沙箱装配器：从配置出发，经探测与 fail-closed 校验后产出可运行沙箱。
///
/// M1 仅完成配置校验与能力探测装配；隔离域建立在 xs-l1-sys 完成后接入。
pub struct SandboxBuilder {
    config: SandboxConfig,
}

impl SandboxBuilder {
    /// 从配置创建装配器；配置先经 `validate()` 校验（fail-closed）。
    pub fn new(config: SandboxConfig) -> XsResult<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// 读取配置（只读）。
    #[must_use]
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_invalid_config() {
        let cfg = SandboxConfig {
            min_assurance: AssuranceLevel::C,
            capabilities: CapabilitySet::new(),
            quota: None,
            allow_io_uring: false,
            network_allow: vec![],
        };
        assert!(SandboxBuilder::new(cfg).is_err());
    }

    #[test]
    fn builder_accepts_valid_config() {
        let cfg = SandboxConfig {
            min_assurance: AssuranceLevel::AMinus,
            capabilities: CapabilitySet::new(),
            quota: None,
            allow_io_uring: false,
            network_allow: vec![],
        };
        assert!(SandboxBuilder::new(cfg).is_ok());
    }
}
