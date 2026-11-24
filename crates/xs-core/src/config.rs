// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 沙箱配置模型。
//!
//! fail-closed（SP-G-01）：配置解析失败或包含无法识别的项即拒绝启动，
//! 禁止『忽略未知字段继续跑』。反序列化一律使用 `deny_unknown_fields`。

use crate::assurance::AssuranceLevel;
use crate::capability::CapabilitySet;
use serde::{Deserialize, Serialize};

/// L2 资源配额描述。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceQuota {
    /// 内存上限（字节），对应 cgroup memory.max。
    pub memory_max: Option<u64>,
    /// CPU 带宽上限（百分比，1-100）。
    pub cpu_percent: Option<u32>,
    /// IO 读带宽上限（字节/秒）。
    pub io_read_bps: Option<u64>,
    /// IO 写带宽上限（字节/秒）。
    pub io_write_bps: Option<u64>,
}

/// 单个沙箱实例的完整配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// 要求的最低保证等级（探测低于此值即拒绝启动）。
    pub min_assurance: AssuranceLevel,
    /// 显式声明允许的能力集（默认空 = 拒绝一切）。
    #[serde(default)]
    pub capabilities: CapabilitySet,
    /// L2 资源配额。
    #[serde(default)]
    pub quota: Option<ResourceQuota>,
    /// `io_uring` 显式开关（SP-L1-03：默认关闭，开启即接受文档警示）。
    #[serde(default)]
    pub allow_io_uring: bool,
    /// 网络放行清单（默认空 = 网络默认拒绝，SP-L1-05）。
    #[serde(default)]
    pub network_allow: Vec<String>,
}

impl SandboxConfig {
    /// 从 TOML 文本解析配置；解析失败即 Config 错误（fail-closed）。
    pub fn from_toml(text: &str) -> crate::error::XsResult<Self> {
        toml::from_str(text).map_err(|e| crate::error::XsError::Config {
            detail: format!("TOML 解析失败: {e}"),
        })
    }

    /// `基础校验：min_assurance` 不允许设为 C（C 意为无有效隔离）。
    pub fn validate(&self) -> crate::error::XsResult<()> {
        if self.min_assurance == AssuranceLevel::C {
            return Err(crate::error::XsError::Config {
                detail: "min_assurance 不允许设为 C（无有效系统级隔离）".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields() {
        let bad = "min_assurance = \"A\"\nunknown_key = 1\n";
        assert!(SandboxConfig::from_toml(bad).is_err());
    }

    #[test]
    fn rejects_min_assurance_c() {
        let cfg = SandboxConfig {
            min_assurance: AssuranceLevel::C,
            capabilities: CapabilitySet::new(),
            quota: None,
            allow_io_uring: false,
            network_allow: vec![],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn io_uring_defaults_off() {
        let text = "min_assurance = \"A-\"\n";
        let cfg = SandboxConfig::from_toml(text).unwrap();
        assert!(!cfg.allow_io_uring);
        assert_eq!(cfg.network_allow, [] as [std::string::String; 0]);
    }
}
