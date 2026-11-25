// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! 沙箱分配：加权负载评分选择最优节点。
//!
//! 调度器只负责选节点，返回节点地址；沙箱创建由客户端直连 daemon。

use crate::node::NodeInfo;

/// 计算节点的加权负载评分（越高越优先）。
///
/// 公式：CPU 余量分 + 内存余量分 + 容量余量分。
/// 每项归一化到 0..1 后求和，总分范围 0..3。
#[must_use]
pub fn score_node(node: &NodeInfo) -> f64 {
    let cpu_free = 1.0 - (node.load.cpu_percent / 100.0).clamp(0.0, 1.0);
    let mem_free = 1.0 - (node.load.mem_percent / 100.0).clamp(0.0, 1.0);

    let capacity_score = if node.max_sandboxes == 0 {
        1.0
    } else {
        let used = node.load.active_sandboxes as f64 / node.max_sandboxes as f64;
        (1.0 - used).clamp(0.0, 1.0)
    };

    cpu_free + mem_free + capacity_score
}

/// 从健康节点列表中选取评分最高的节点。
/// 若列表为空返回 None。
#[must_use]
pub fn select_best_node(nodes: &[NodeInfo]) -> Option<NodeInfo> {
    nodes
        .iter()
        .max_by(|a, b| {
            score_node(a)
                .partial_cmp(&score_node(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler_proto::NodeLoad;
    use std::time::SystemTime;

    fn node(id: &str, cpu: f64, mem: f64, active: u32, max: u32) -> NodeInfo {
        NodeInfo {
            id: id.to_string(),
            address: format!("{id}:50051"),
            version: "1.0.11-dev".to_string(),
            max_sandboxes: max,
            load: NodeLoad {
                cpu_percent: cpu,
                mem_percent: mem,
                active_sandboxes: active,
                idle_sandboxes: 0,
                uptime_secs: 0,
            },
            registered_at: SystemTime::now(),
            last_heartbeat: SystemTime::now(),
        }
    }

    #[test]
    fn low_load_scores_higher() {
        let a = node("a", 10.0, 20.0, 2, 16);
        let b = node("b", 90.0, 80.0, 15, 16);
        assert!(score_node(&a) > score_node(&b));
    }

    #[test]
    fn select_best_returns_highest_score() {
        let nodes = vec![
            node("hot", 95.0, 90.0, 14, 16),
            node("warm", 50.0, 50.0, 8, 16),
            node("cool", 10.0, 15.0, 1, 16),
        ];
        let best = select_best_node(&nodes).unwrap();
        assert_eq!(best.id, "cool");
    }

    #[test]
    fn unlimited_capacity_full_score() {
        let n = node("infinite", 50.0, 50.0, 100, 0);
        let s = score_node(&n);
        // cpu_free=0.5 + mem_free=0.5 + capacity=1.0 = 2.0
        assert!((s - 2.0).abs() < 0.01);
    }

    #[test]
    fn empty_list_returns_none() {
        assert!(select_best_node(&[]).is_none());
    }
}
