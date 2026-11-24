// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 能力句柄（Capability Handle）数据模型。
//!
//! SP-L3-01：能力句柄的伪造、复用（跨会话/跨实例重放）、越权使用必须失败。
//! 设计要点：
//! - 句柄 ID 为 128 位随机值（不可枚举、不可伪造）；
//! - 句柄绑定 generation（实例代数），跨实例复用会因代数不匹配被拒绝；
//! - 句柄携带授权范围（scope），越权调用在使用点校验。

use xs_core::{CapabilityId, XsError, XsResult};

/// 128 位随机句柄标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandleId(pub u128);

impl HandleId {
    /// 生成新的随机句柄 ID（使用系统随机源）。
    #[must_use]
    pub fn generate() -> Self {
        Self(u128::from_ne_bytes(random_u128()))
    }
}

/// 从 /dev/urandom 读取 16 字节（避免引入额外随机数依赖的最小实现）。
fn random_u128() -> [u8; 16] {
    use std::io::Read;
    let mut buf = [0u8; 16];
    match std::fs::File::open("/dev/urandom") {
        Ok(mut f) => {
            if f.read_exact(&mut buf).is_err() {
                // /dev/urandom 读取失败：回退到时间戳+进程ID混合（仅骨架期，M3 前必须替换）
                fallback_fill(&mut buf);
            }
        }
        Err(_) => fallback_fill(&mut buf),
    }
    buf
}

fn fallback_fill(buf: &mut [u8; 16]) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let pid = u128::from(std::process::id());
    let v = nanos ^ (pid << 64);
    *buf = v.to_ne_bytes();
}

/// 能力句柄：一次授权的最小单元。
#[derive(Debug, Clone)]
pub struct CapabilityHandle {
    /// 随机句柄 ID。
    id: HandleId,
    /// 实例代数（创建该句柄的运行时实例标识）。
    generation: u64,
    /// 授权的能力标识（如 fs.read）。
    capability: CapabilityId,
    /// 授权范围说明（如授权路径前缀，供使用点校验）。
    scope: String,
    /// 是否已吊销。
    revoked: bool,
}

impl CapabilityHandle {
    /// 签发一个新句柄。
    pub fn issue(generation: u64, capability: CapabilityId, scope: impl Into<String>) -> Self {
        Self {
            id: HandleId::generate(),
            generation,
            capability,
            scope: scope.into(),
            revoked: false,
        }
    }

    /// 吊销句柄（吊销后任何使用都失败）。
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// 使用点校验：实例代数匹配、未吊销、能力一致、请求范围在授权范围内。
    ///
    /// 任一不满足即 PolicyViolation（SP-L3-01）。
    pub fn check_use(
        &self,
        generation: u64,
        capability: &str,
        requested_scope: &str,
    ) -> XsResult<()> {
        if self.revoked {
            return Err(XsError::PolicyViolation {
                sp_id: "SP-L3-01".to_string(),
                detail: "句柄已吊销".to_string(),
            });
        }
        if self.generation != generation {
            return Err(XsError::PolicyViolation {
                sp_id: "SP-L3-01".to_string(),
                detail: format!(
                    "句柄跨实例复用: 句柄代数={} 当前代数={}",
                    self.generation, generation
                ),
            });
        }
        if self.capability != capability {
            return Err(XsError::PolicyViolation {
                sp_id: "SP-L3-01".to_string(),
                detail: format!("能力越权: 句柄={} 请求={}", self.capability, capability),
            });
        }
        // 范围校验（SP-L3-01 fail-closed，M3 对抗语料驱动加固）：
        // - 空范围一律拒绝；
        // - 含 .. 分量的一律拒绝（路径穿越对抗输入，如 /data/../etc/passwd）；
        // - 前缀匹配按路径分量边界：请求须等于授权范围，或以『授权范围 + /』
        //   开头（/data 授权放行 /data/x，拒绝共享字符串前缀的 /database）。
        if requested_scope.is_empty() || requested_scope.split('/').any(|c| c == "..") {
            return Err(XsError::PolicyViolation {
                sp_id: "SP-L3-01".to_string(),
                detail: format!("范围含非法分量: 请求={requested_scope}"),
            });
        }
        let in_scope = requested_scope == self.scope
            || requested_scope
                .strip_prefix(self.scope.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if !in_scope {
            return Err(XsError::PolicyViolation {
                sp_id: "SP-L3-01".to_string(),
                detail: format!("范围越权: 授权={} 请求={}", self.scope, requested_scope),
            });
        }
        Ok(())
    }

    /// 句柄 ID（只读）。
    #[must_use]
    pub fn id(&self) -> HandleId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        assert_ne!(HandleId::generate(), HandleId::generate());
    }

    #[test]
    fn forgery_and_reuse_fail() {
        let h = CapabilityHandle::issue(1, "fs.read".to_string(), "/data");
        // 正常使用通过
        assert!(h.check_use(1, "fs.read", "/data/a.txt").is_ok());
        // 跨实例复用失败
        assert!(h.check_use(2, "fs.read", "/data/a.txt").is_err());
        // 能力越权失败
        assert!(h.check_use(1, "fs.write", "/data/a.txt").is_err());
        // 范围越权失败
        assert!(h.check_use(1, "fs.read", "/etc/passwd").is_err());
    }

    #[test]
    fn revoked_handle_fails() {
        let mut h = CapabilityHandle::issue(1, "fs.read".to_string(), "/data");
        h.revoke();
        assert!(h.check_use(1, "fs.read", "/data/a.txt").is_err());
    }
}
