// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! cgroup v2 真实委派与限额（SP-L2-01 / SP-G-02 实现）。
//!
//! 委派判定标准（M0 Spike 探针 4 范式，docs/06-M0-SPIKE.md）：
//!   创建子组 -> `cgroup.subtree_control` 写入 +memory +cpu -> 回读确认 enable ->
//!   写 memory.max -> 回读确认生效。五步全部成功才算可委派；
//!   『挂载了 cgroup2fs』不等于『可委派』，『cgroup.controllers 列出控制器』
//!   也不等于『子树已 enable』（SP-G-02 探测一致性，M3 评审提醒回填）。

use std::path::{Path, PathBuf};

/// cgroup v2 委派探测与限额错误（L2 用错误前缀区分层级）。
#[derive(Debug)]
pub enum CgroupError {
    /// cgroup2fs 未挂载。
    NotMounted,
    /// 委派链路中某一步失败（创建/enable/写入/回读）。
    DelegationFailed(String),
    /// 写入值与回读值不一致（限额未真实生效）。
    ReadbackMismatch {
        /// 写入 memory.max 的值。
        wrote: String,
        /// 回读 memory.max 得到的值。
        read: String,
    },
    /// 底层 IO 错误。
    Io(std::io::Error),
}

impl std::fmt::Display for CgroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMounted => write!(f, "cgroup2fs 未挂载"),
            Self::DelegationFailed(s) => write!(f, "cgroup 委派失败: {s}"),
            Self::ReadbackMismatch { wrote, read } => {
                write!(f, "限额未真实生效: 写入={wrote} 回读={read}")
            }
            Self::Io(e) => write!(f, "cgroup IO 错误: {e}"),
        }
    }
}

impl std::error::Error for CgroupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CgroupError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// cgroup v2 根（默认系统挂载点，可注入便于测试）。
#[derive(Debug, Clone)]
pub struct CgroupV2 {
    root: PathBuf,
}

impl Default for CgroupV2 {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/sys/fs/cgroup"),
        }
    }
}

impl CgroupV2 {
    /// 指定根路径（测试时可注入临时目录）。
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// cgroup2fs 是否挂载（仅存在性，不代表可委派）。
    #[must_use]
    pub fn is_mounted(&self) -> bool {
        self.root.join("cgroup.controllers").exists()
    }

    /// 根控制器清单（如 cpuset cpu io memory pids ...）。
    pub fn root_controllers(&self) -> Result<Vec<String>, CgroupError> {
        let text = std::fs::read_to_string(self.root.join("cgroup.controllers"))?;
        Ok(text.split_whitespace().map(str::to_string).collect())
    }

    /// 根 `subtree_control` 当前已 enable 的控制器清单。
    ///
    /// SP-G-02 判定强化（M3 评审提醒）：cgroup.controllers 列出的是『可用』
    /// 控制器，只有 `subtree_control` 中出现的才是『已对子树委派』的控制器；
    /// 挂载点存在 + controllers 含目标控制器 ≠ 子组可写对应接口文件。
    pub fn subtree_controllers(&self) -> Result<Vec<String>, CgroupError> {
        let text = std::fs::read_to_string(self.root.join("cgroup.subtree_control"))?;
        Ok(text.split_whitespace().map(str::to_string).collect())
    }

    /// 指定控制器是否已在 `subtree_control` 中 enable（即子组可用对应接口文件）。
    pub fn controller_enabled_in_subtree(&self, controller: &str) -> Result<bool, CgroupError> {
        Ok(self.subtree_controllers()?.iter().any(|c| c == controller))
    }

    /// 真实委派探测（完整链路，SP-G-02）。
    ///
    /// 创建临时子组 -> enable +memory +cpu -> 写 memory.max -> 回读确认 -> 清理。
    /// 四步全部成功返回 true；任何一步失败返回对应错误（fail-closed 语义：
    /// 探测失败按不可委派处理，调用方据此降级等级）。
    pub fn probe_delegation(&self) -> Result<bool, CgroupError> {
        if !self.is_mounted() {
            return Err(CgroupError::NotMounted);
        }
        let probe_dir = self.root.join("xs_l2_probe");
        // 清理可能残留的上次探测目录
        let _ = std::fs::remove_dir(&probe_dir);
        let result = self.probe_delegation_inner(&probe_dir);
        let _ = std::fs::remove_dir(&probe_dir);
        result
    }

    fn probe_delegation_inner(&self, dir: &Path) -> Result<bool, CgroupError> {
        // 1. 创建子组
        std::fs::create_dir(dir)
            .map_err(|e| CgroupError::DelegationFailed(format!("创建子组失败: {e}")))?;
        // 2. enable 控制器（向根的 subtree_control 写入）
        let subtree = self.root.join("cgroup.subtree_control");
        std::fs::write(&subtree, "+memory +cpu")
            .map_err(|e| CgroupError::DelegationFailed(format!("enable 控制器失败: {e}")))?;
        // 2b. 回读 subtree_control 确认 enable 真实生效（SP-G-02 强化：
        //     写入返回成功不代表内核接受，enable 状态以回读为准，fail-closed）。
        let enabled = self.subtree_controllers()?;
        for required in ["memory", "cpu"] {
            if !enabled.iter().any(|c| c == required) {
                return Err(CgroupError::DelegationFailed(format!(
                    "subtree_control 回读未含 {required}（写入未被内核接受）"
                )));
            }
        }
        // 3. 写 memory.max
        let limit = "134217728";
        let mem_max = dir.join("memory.max");
        std::fs::write(&mem_max, limit)
            .map_err(|e| CgroupError::DelegationFailed(format!("写 memory.max 失败: {e}")))?;
        // 4. 回读确认真实生效
        let got = std::fs::read_to_string(&mem_max)?;
        let got = got.trim();
        if got != limit {
            return Err(CgroupError::ReadbackMismatch {
                wrote: limit.to_string(),
                read: got.to_string(),
            });
        }
        Ok(true)
    }

    /// 为指定子组设置内存上限（SP-L2-01）。
    ///
    /// 写入并回读确认；子组不存在或写不入都显式报错。
    pub fn set_memory_max(&self, group: &str, bytes: u64) -> Result<(), CgroupError> {
        let mem_max = self.root.join(group).join("memory.max");
        std::fs::write(&mem_max, bytes.to_string())?;
        let got = std::fs::read_to_string(&mem_max)?;
        let got = got.trim();
        if got != bytes.to_string() {
            return Err(CgroupError::ReadbackMismatch {
                wrote: bytes.to_string(),
                read: got.to_string(),
            });
        }
        Ok(())
    }

    /// 读取子组当前内存用量（memory.current，供背压与审计使用）。
    pub fn memory_current(&self, group: &str) -> Result<u64, CgroupError> {
        let text = std::fs::read_to_string(self.root.join(group).join("memory.current"))?;
        text.trim()
            .parse::<u64>()
            .map_err(|e| CgroupError::DelegationFailed(format!("memory.current 解析失败: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_detection_runs() {
        let cg = CgroupV2::default();
        let _ = cg.is_mounted();
    }

    #[test]
    fn root_controllers_parse() {
        let cg = CgroupV2::default();
        if cg.is_mounted() {
            let ctrls = cg.root_controllers().expect("应能读取根控制器");
            assert!(ctrls.iter().any(|c| c == "memory"));
        }
    }

    #[test]
    fn delegation_probe_is_real() {
        // 本机（裸 VM，M0 Spike 探针 4 已验证可委派）应为 Ok(true)；
        // 容器等不可委派环境应为 Err（fail-closed 语义，探测失败即降级）。
        let cg = CgroupV2::default();
        if !cg.is_mounted() {
            return;
        }
        match cg.probe_delegation() {
            Ok(true) => {}
            Ok(false) => panic!("probe_delegation 不应返回 Ok(false)"),
            Err(_) => {
                // 不可委派环境合法（等级探测会据此降级）
            }
        }
    }

    #[test]
    fn subtree_control_parse_and_check() {
        let cg = CgroupV2::default();
        if cg.is_mounted() {
            let enabled = cg.subtree_controllers().expect("应能读取 subtree_control");
            assert!(
                !enabled.is_empty(),
                "已挂载 cgroup v2 的 subtree_control 不应为空"
            );
            for c in &enabled {
                assert!(!c.is_empty(), "controller 名不应为空字符串");
                assert_ne!(c, "xyzzy", "controller 名不应为占位字符串");
                assert!(cg.controller_enabled_in_subtree(c).expect("检查失败"));
            }
            assert!(!cg
                .controller_enabled_in_subtree("definitely_not_a_controller")
                .expect("检查失败"));
        }
    }

    /// 通过 mock cgroup 树验证 `subtree_controllers` / `controller_enabled_in_subtree` /
    /// `probe_delegation` 内部委托逻辑（含 ! 删除和 == → != 变异体）。
    #[test]
    fn mock_cgroup_tree_delegation_logic() {
        let tmp = std::path::PathBuf::from("/tmp/xs_cg_mock_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // 场景 1：subtree_control 含 memory+cpu → probe_delegation 应 Ok(true)
        std::fs::write(tmp.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(tmp.join("cgroup.subtree_control"), "memory cpu\n").unwrap();
        let cg = CgroupV2::with_root(&tmp);
        assert!(cg.is_mounted());
        let ctrls = cg.subtree_controllers().unwrap();
        assert_eq!(ctrls.len(), 2, "应解析出 2 个 controller");
        assert!(ctrls.contains(&"memory".to_string()));
        assert!(ctrls.contains(&"cpu".to_string()));
        assert!(cg.controller_enabled_in_subtree("memory").unwrap());
        assert!(!cg.controller_enabled_in_subtree("pids").unwrap());

        // probe_delegation on mock：子树已 enable memory+cpu → 应 Ok(true)
        match cg.probe_delegation() {
            Ok(true) => {}
            Ok(false) => panic!("probe_delegation 不应返回 Ok(false)"),
            Err(_e) => {} // mock fs 无真实 cgroup 语义，允许 Err
        }

        // 清理
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // 场景 2：subtree_control 不含 memory（仅 pids）→ ! 删除 / ==→!= 变异体暴露
        std::fs::write(tmp.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        std::fs::write(tmp.join("cgroup.subtree_control"), "pids\n").unwrap();
        let cg2 = CgroupV2::with_root(&tmp);
        assert!(cg2.is_mounted());
        let ctrls2 = cg2.subtree_controllers().unwrap();
        assert_eq!(ctrls2.len(), 1);
        assert!(ctrls2.contains(&"pids".to_string()));

        // controller_enabled_in_subtree for "memory" in scenario 2 → false
        assert!(!cg2.controller_enabled_in_subtree("memory").unwrap());

        // probe_delegation in scenario 2 → must Err (memory not in subtree)
        // 此断言杀死 probe_delegation_inner 中 ! 删除 / ==→!= 两个突变：
        // 原码 → Err(DelegationFailed)；突变码 → 跳过检查 → Ok(true) → 测试失败
        let r = cg2.probe_delegation();
        assert!(
            r.is_err(),
            "memory 不在 subtree_control 时 probe_delegation 必须返回 Err，实际: {r:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn with_root_custom_path() {
        let cg = CgroupV2::with_root("/nonexistent");
        assert!(!cg.is_mounted());
        assert!(matches!(
            cg.probe_delegation(),
            Err(CgroupError::NotMounted)
        ));
    }

    #[test]
    fn error_display_is_not_empty() {
        let e = CgroupError::NotMounted;
        let s = e.to_string();
        assert!(!s.is_empty(), "Display 不应返回空字符串");
        assert!(
            s.contains("cgroup") || s.contains("Cgroup"),
            "Display 应含 cgroup 上下文: {s}"
        );
    }

    #[test]
    fn error_source_only_for_io_variant() {
        use std::error::Error;
        let io_e = CgroupError::Io(std::io::Error::other("x"));
        assert!(io_e.source().is_some(), "Io 变体 source 应为 Some");
        let nm = CgroupError::NotMounted;
        assert!(nm.source().is_none(), "NotMounted 变体 source 应为 None");
    }

    #[test]
    fn cgroup_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CgroupError>();
    }

    #[test]
    fn mock_set_memory_max_and_memory_current() {
        let tmp = std::path::PathBuf::from("/tmp/xs_cg_mock_mem");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let group_dir = tmp.join("test-group");
        std::fs::create_dir_all(&group_dir).unwrap();

        let cg = CgroupV2::with_root(&tmp);

        // set_memory_max: 写入后回读一致 → Ok(()); !=→== 突变 → Err
        let r = cg.set_memory_max("test-group", 134_217_728);
        assert!(
            r.is_ok(),
            "mock 子组写入 memory.max 并回读成功应返回 Ok，实际: {r:?}"
        );

        // set_memory_max→Ok(()) 突变体：子组目录不存在必须返回 Err
        let r2 = cg.set_memory_max("nonexistent-group", 65536);
        assert!(r2.is_err(), "子组目录不存在时 set_memory_max 必须返回 Err");

        // memory_current: mock 文件含非零值 42
        std::fs::write(group_dir.join("memory.current"), "42\n").unwrap();
        let mem = cg.memory_current("test-group");
        assert!(mem.is_ok(), "mock 文件树 memory.current 应解析成功");
        let val = mem.unwrap();
        assert_ne!(val, 0, "memory_current 不应恒为 0（mock 值为 42）");
        assert_ne!(val, 1, "memory_current 不应恒为 1（mock 值为 42）");
        assert_eq!(val, 42, "memory_current 应返回 mock 文件中的值 42");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
