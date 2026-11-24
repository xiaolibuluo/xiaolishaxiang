// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 能力（capability）描述与声明。
//!
//! 能力是沙箱内代码可被授权的最小权限单元。默认不授予任何能力；
//! 请求未声明的能力即触发 CapabilityNotDeclared（fail-closed）。

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// 能力标识（如 fs.read、net.connect.tcp）。
pub type CapabilityId = String;

/// 能力声明集：策略中显式声明允许的能力。
///
/// 使用 `BTreeSet` 保证有序与去重，便于审计与序列化稳定。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    inner: BTreeSet<CapabilityId>,
}

impl CapabilitySet {
    /// 创建空能力集（默认拒绝一切）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 声明一个能力。
    pub fn declare(&mut self, id: impl Into<CapabilityId>) {
        self.inner.insert(id.into());
    }

    /// 是否已声明某能力。
    #[must_use]
    pub fn is_declared(&self, id: &str) -> bool {
        self.inner.contains(id)
    }

    /// 校验请求的能力是否已声明；未声明则 fail-closed。
    pub fn require(&self, id: &str) -> crate::error::XsResult<()> {
        if self.is_declared(id) {
            Ok(())
        } else {
            Err(crate::error::XsError::CapabilityNotDeclared {
                capability: id.to_string(),
            })
        }
    }

    /// 已声明能力的数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_denies_everything() {
        let s = CapabilitySet::new();
        assert!(s.require("fs.read").is_err());
        assert!(s.is_empty());
    }

    #[test]
    fn declared_capability_passes() {
        let mut s = CapabilitySet::new();
        s.declare("fs.read");
        assert!(s.require("fs.read").is_ok());
        assert!(s.require("fs.write").is_err());
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty(), "声明能力后 is_empty 应为 false");
    }

    #[test]
    fn len_is_not_always_one() {
        let mut s = CapabilitySet::new();
        assert_eq!(s.len(), 0, "空集 len 应为 0");
        s.declare("fs.read");
        assert_eq!(s.len(), 1);
        s.declare("fs.write");
        s.declare("net.connect");
        assert_eq!(s.len(), 3, "三个声明 len 应为 3");
    }
}
