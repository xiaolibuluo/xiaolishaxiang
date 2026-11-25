// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 节点注册表：节点信息、健康状态、心跳超时管理。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::scheduler_proto::NodeLoad;

/// 心跳超时：超过此值未收到心跳的节点视为不健康（摘除/不参与调度）。
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);

/// 注册表中的单个节点信息。
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: String,
    pub address: String,
    pub version: String,
    /// 节点声明的最大沙箱容量（0 = 不限制）。
    pub max_sandboxes: u32,
    /// 最近一次心跳上报的负载。
    pub load: NodeLoad,
    pub registered_at: SystemTime,
    pub last_heartbeat: SystemTime,
}

impl NodeInfo {
    /// 是否健康：最近一次心跳在超时窗口内。
    pub fn is_healthy(&self) -> bool {
        self.last_heartbeat
            .elapsed()
            .is_ok_and(|e| e < HEARTBEAT_TIMEOUT)
    }

    /// 当前使用率%（在 0~100 内）。
    pub fn usage_ratio(&self) -> f64 {
        if self.max_sandboxes == 0 {
            // 无限制节点：仅基于 CPU/内存
            return 0.0;
        }
        (self.load.active_sandboxes as f64 / self.max_sandboxes as f64).clamp(0.0, 1.0)
    }
}

/// 节点注册表：存储全部已注册节点，支持并发安全的 CRUD 与健康过滤。
#[derive(Clone)]
pub struct NodeRegistry {
    inner: Arc<RwLock<HashMap<String, NodeInfo>>>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 注册新节点（id 已存在时拒绝）。
    pub async fn register(&self, info: NodeInfo) -> Result<(), String> {
        let mut inner = self.inner.write().await;
        if inner.contains_key(&info.id) {
            return Err(format!("节点 {} 已注册", info.id));
        }
        info!(
            node_id = %info.id,
            address = %info.address,
            version = %info.version,
            max_sandboxes = info.max_sandboxes,
            "节点注册"
        );
        inner.insert(info.id.clone(), info);
        Ok(())
    }

    /// 更新节点心跳时间与负载。
    pub async fn heartbeat(&self, node_id: &str, load: NodeLoad) -> Result<(), String> {
        let mut inner = self.inner.write().await;
        let info = inner
            .get_mut(node_id)
            .ok_or_else(|| format!("节点 {} 未注册", node_id))?;
        info.load = load;
        info.last_heartbeat = SystemTime::now();
        Ok(())
    }

    /// 注销节点。
    pub async fn deregister(&self, node_id: &str) -> Result<NodeInfo, String> {
        let mut inner = self.inner.write().await;
        let info = inner
            .remove(node_id)
            .ok_or_else(|| format!("节点 {} 未注册", node_id))?;
        info!(node_id = %info.id, "节点注销");
        Ok(info)
    }

    /// 列出所有健康节点（心跳在超时窗口内）。
    pub async fn list_healthy(&self) -> Vec<NodeInfo> {
        let inner = self.inner.read().await;
        inner
            .values()
            .filter(|info| info.is_healthy())
            .cloned()
            .collect()
    }

    /// GC：清理超时无心跳的节点。
    pub async fn gc_stale(&self) -> usize {
        let mut inner = self.inner.write().await;
        let before = inner.len();
        inner.retain(|id, info| {
            let healthy = info.is_healthy();
            if !healthy {
                warn!(node_id = %id, "节点心跳超时，自动摘除");
            }
            healthy
        });
        let removed = before - inner.len();
        if removed > 0 {
            info!("GC 摘除 {removed} 个超时节点");
        }
        removed
    }

    /// 节点总数（含不健康）。
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// 是否无已注册节点。
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    /// 查询单个节点。
    pub async fn get(&self, node_id: &str) -> Option<NodeInfo> {
        self.inner.read().await.get(node_id).cloned()
    }

    /// 设置指定节点的最后心跳时间（仅用于集成测试/故障注入）。
    ///
    /// 节点不存在时静默忽略。
    #[doc(hidden)]
    pub async fn set_last_heartbeat_for_test(&self, node_id: &str, time: SystemTime) {
        let mut inner = self.inner.write().await;
        if let Some(info) = inner.get_mut(node_id) {
            info.last_heartbeat = time;
        }
    }
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_load() -> NodeLoad {
        NodeLoad {
            cpu_percent: 10.0,
            mem_percent: 30.0,
            active_sandboxes: 2,
            idle_sandboxes: 4,
            uptime_secs: 3600,
        }
    }

    fn dummy_node(id: &str) -> NodeInfo {
        NodeInfo {
            id: id.to_string(),
            address: format!("127.0.0.1:{}", 50050 + id.len() as u32),
            version: "1.0.11-dev".to_string(),
            max_sandboxes: 16,
            load: dummy_load(),
            registered_at: SystemTime::now(),
            last_heartbeat: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn register_and_heartbeat() {
        let registry = NodeRegistry::new();
        registry.register(dummy_node("node-1")).await.unwrap();
        assert_eq!(registry.len().await, 1);

        registry.heartbeat("node-1", dummy_load()).await.unwrap();
        assert_eq!(registry.list_healthy().await.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_register_rejected() {
        let registry = NodeRegistry::new();
        registry.register(dummy_node("node-1")).await.unwrap();
        assert!(registry.register(dummy_node("node-1")).await.is_err());
    }

    #[tokio::test]
    async fn deregister_and_gc() {
        let registry = NodeRegistry::new();
        registry.register(dummy_node("node-a")).await.unwrap();
        registry.register(dummy_node("node-b")).await.unwrap();

        registry.deregister("node-a").await.unwrap();
        assert_eq!(registry.len().await, 1);

        // 手动将 node-b 心跳设旧以触发 GC
        {
            let mut inner = registry.inner.write().await;
            if let Some(info) = inner.get_mut("node-b") {
                info.last_heartbeat = SystemTime::now() - Duration::from_secs(20);
            }
        }
        let removed = registry.gc_stale().await;
        assert_eq!(removed, 1);
        assert_eq!(registry.len().await, 0);
    }

    #[tokio::test]
    async fn heartbeat_unknown_node_fails() {
        let registry = NodeRegistry::new();
        assert!(registry.heartbeat("ghost", dummy_load()).await.is_err());
    }

    #[tokio::test]
    async fn list_healthy_filters_stale() {
        let registry = NodeRegistry::new();
        registry.register(dummy_node("fresh")).await.unwrap();

        let mut stale = dummy_node("stale");
        stale.last_heartbeat = SystemTime::now() - Duration::from_secs(20);
        registry.register(stale).await.unwrap();

        let healthy = registry.list_healthy().await;
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].id, "fresh");
    }
}
