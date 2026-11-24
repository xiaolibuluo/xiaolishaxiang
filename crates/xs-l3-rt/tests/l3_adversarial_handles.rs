// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M3 对抗逃逸语料：SP-L3-01 能力句柄不可伪造（docs/01-SECURITY-PROPERTIES.md）。
//!
//! 威胁背景（docs/00-THREAT-MODEL.md）：攻击者完全控制沙箱内代码，会尝试
//! 伪造句柄、跨会话/跨实例重放句柄、以越权能力或越权范围使用句柄。
//! `本文件以对抗输入驱动使用点校验（check_use），全部必须失败并产生`
//! PolicyViolation（SP-L3-01），不允许任何静默放行。

use xs_l3_rt::CapabilityHandle;

/// 断言校验结果为 SP-L3-01 的 PolicyViolation（而非其他错误或误放行）。
fn assert_policy_violation(res: Result<(), xs_core::XsError>, what: &str) {
    match res {
        Err(xs_core::XsError::PolicyViolation { sp_id, .. }) => {
            assert_eq!(sp_id, "SP-L3-01", "{what}: sp_id 不匹配");
        }
        other => panic!("{what}: 期望 SP-L3-01 PolicyViolation，实际 {other:?}"),
    }
}

/// 对抗类 1：跨实例/跨会话重放。
///
/// 句柄绑定 generation；以任意其他代数（含边界值 0 与 `u64::MAX）重放必须失败`。
#[test]
fn sp_l3_01_cross_instance_replay_rejected() {
    let h = CapabilityHandle::issue(7, "fs.read".to_string(), "/data");
    // 合法基线：同代数、同能力、范围内路径可用。
    assert!(h.check_use(7, "fs.read", "/data/a.txt").is_ok());
    // 相邻代数重放。
    assert_policy_violation(h.check_use(6, "fs.read", "/data/a.txt"), "代数-1 重放");
    assert_policy_violation(h.check_use(8, "fs.read", "/data/a.txt"), "代数+1 重放");
    // 边界代数重放。
    assert_policy_violation(h.check_use(0, "fs.read", "/data/a.txt"), "代数 0 重放");
    assert_policy_violation(
        h.check_use(u64::MAX, "fs.read", "/data/a.txt"),
        "代数 u64::MAX 重放",
    );
}

/// 对抗类 2：能力越权。
///
/// 持 fs.read 句柄请求写、执行、网络与通配能力，全部必须失败。
#[test]
fn sp_l3_01_capability_escalation_rejected() {
    let h = CapabilityHandle::issue(1, "fs.read".to_string(), "/data");
    for cap in ["fs.write", "fs.exec", "net.connect", "*", "fs.read\0x"] {
        assert_policy_violation(h.check_use(1, cap, "/data/a.txt"), "能力越权未拒绝");
    }
}

/// 对抗类 3：范围越权——直接越出授权前缀。
#[test]
fn sp_l3_01_scope_escape_rejected() {
    let h = CapabilityHandle::issue(1, "fs.read".to_string(), "/data");
    assert_policy_violation(h.check_use(1, "fs.read", "/etc/passwd"), "绝对路径越权");
    assert_policy_violation(h.check_use(1, "fs.read", "/"), "根路径越权");
    assert_policy_violation(h.check_use(1, "fs.read", ""), "空范围越权");
}

/// 对抗类 4：范围越权——授权前缀内的路径穿越。
///
/// 对抗输入以授权前缀开头但含 .. 组件，朴素 `starts_with` 会误判放行；
/// 按 SP-L3-01 必须拒绝（fail-closed：范围串必须是规范形式且不含穿越）。
#[test]
fn sp_l3_01_scope_traversal_rejected() {
    let h = CapabilityHandle::issue(1, "fs.read".to_string(), "/data");
    assert_policy_violation(
        h.check_use(1, "fs.read", "/data/../etc/passwd"),
        ".. 穿越越权",
    );
    assert_policy_violation(
        h.check_use(1, "fs.read", "/data/./../secret"),
        "/./.. 组合穿越",
    );
    assert_policy_violation(
        h.check_use(1, "fs.read", "/data/sub/../../etc/shadow"),
        "深层穿越",
    );
}

/// 对抗类 5：范围越权——前缀混淆（共享字符串前缀但不同路径分量）。
///
/// 授权 /data 时，/database 与 /data-evil 共享字符串前缀但不是其下层；
/// 分量边界的校验必须拒绝此类混淆输入。
#[test]
fn sp_l3_01_scope_prefix_confusion_rejected() {
    let h = CapabilityHandle::issue(1, "fs.read".to_string(), "/data");
    assert_policy_violation(
        h.check_use(1, "fs.read", "/database/x.db"),
        "前缀混淆 /database",
    );
    assert_policy_violation(
        h.check_use(1, "fs.read", "/data-evil/x"),
        "前缀混淆 /data-evil",
    );
}

/// 对抗类 6：吊销后重放——吊销句柄在任何代数/能力/范围下都不可用。
#[test]
fn sp_l3_01_revoked_handle_replay_rejected() {
    let mut h = CapabilityHandle::issue(3, "fs.read".to_string(), "/data");
    h.revoke();
    assert_policy_violation(h.check_use(3, "fs.read", "/data/a.txt"), "吊销后原样重放");
    assert_policy_violation(h.check_use(3, "fs.read", "/data"), "吊销后边界范围");
}

/// 对抗类 7：伪造不可行性的结构证据。
///
/// 句柄字段私有、ID 只能经 `HandleId::generate` 取自 /dev/urandom 的 128 位
/// 随机值；攻击者无法构造指定 ID 的句柄（无公开构造器），批量生成不产生
/// 碰撞（碰撞即意味着可枚举性）。
#[test]
fn sp_l3_01_handle_ids_unpredictable_and_unique() {
    use std::collections::HashSet;
    let ids: HashSet<_> = (0..1024)
        .map(|_| CapabilityHandle::issue(1, "c".to_string(), "s").id())
        .collect();
    assert_eq!(ids.len(), 1024, "1024 个句柄 ID 出现碰撞（可枚举性证据）");
}
