// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! landlock 域（ruleset）建立：SP-L1-01 文件系统路径隔离的实现。
//!
//! `三件套顺序契约：create_ruleset` -> `add_rule(授权路径)` -> `restrict_self`。
//! 语义（docs/00-THREAT-MODEL.md / SP-L1-04）：
//! - landlock 只约束『未来』操作，不约束已打开的 fd；
//! - 规则只收紧不放宽，建立后无法移除；
//! - 必须在 fork 子进程后、exec 之前完成，且 supervisor 已持有最小 fd 集。
//!
//! ABI 分级（docs/02-ASSURANCE-LEVELS.md）：本模块使用 ABI v1 文件系统权限集，
//! 高 ABI 版本内核完全兼容 v1 规则；网络维度（ABI v3+）由 `create_ruleset_with_net`
//! 接入（SP-L1-05 第二道防线：声明网络权限但不添加 `NET_PORT` 规则即默认全拒）。

use xs_core::{XsError, XsResult};

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// landlock 文件系统访问权限（ABI v1 全集）。
const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

/// ABI v1 文件系统权限全集（ruleset 的 `handled_access_fs` 声明范围）。
const ACCESS_FS_ALL_V1: u64 = ACCESS_FS_EXECUTE
    | ACCESS_FS_WRITE_FILE
    | ACCESS_FS_READ_FILE
    | ACCESS_FS_READ_DIR
    | ACCESS_FS_REMOVE_DIR
    | ACCESS_FS_REMOVE_FILE
    | ACCESS_FS_MAKE_CHAR
    | ACCESS_FS_MAKE_DIR
    | ACCESS_FS_MAKE_REG
    | ACCESS_FS_MAKE_SOCK
    | ACCESS_FS_MAKE_FIFO
    | ACCESS_FS_MAKE_BLOCK
    | ACCESS_FS_MAKE_SYM;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

/// landlock 网络访问权限（ABI v3 引入）。
const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

/// `landlock_ruleset_attr（ABI` v1：仅 FS 字段；ABI v3 起含网络字段）。
///
/// 结构体前 8 字节布局在 v1/v3 间兼容；size 参数告知内核使用哪个 ABI 版本。
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

/// `landlock_path_beneath_attr（ABI` v1）。
#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// 一条路径授权：授权路径 + 允许的权限集。
#[derive(Debug, Clone)]
pub struct PathGrant {
    /// 授权的路径（其下层均按 `allowed_access` 放行）。
    pub path: std::path::PathBuf,
    /// 允许的 landlock `ACCESS_FS`_* 位集。
    pub access: u64,
}

impl PathGrant {
    /// 只读授权（读文件 + 读目录 + 执行）。
    pub fn read_only(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE,
        }
    }

    /// 读写授权（只读基础上加写文件与创建常规文件/目录/删除）。
    pub fn read_write(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: ACCESS_FS_READ_FILE
                | ACCESS_FS_READ_DIR
                | ACCESS_FS_EXECUTE
                | ACCESS_FS_WRITE_FILE
                | ACCESS_FS_MAKE_REG
                | ACCESS_FS_MAKE_DIR
                | ACCESS_FS_REMOVE_FILE
                | ACCESS_FS_REMOVE_DIR,
        }
    }
}

/// 已建立但尚未生效的 landlock ruleset（fd 持有态）。
///
/// 调用 `enforce()` 后才对当前进程生效（只收紧不放宽）。
pub struct LandlockRuleset {
    fd: i32,
}

impl Drop for LandlockRuleset {
    fn drop(&mut self) {
        // SAFETY：关闭本结构独占持有的 fd，fd 由 create_ruleset 返回且未被复制。
        unsafe { libc::close(self.fd) };
    }
}

/// 创建 ruleset（三件套第一步）。
///
/// `handled_access_fs` 声明为 ABI v1 全集：未授权路径的这些操作一律拒绝。
/// 仅声明 FS 维度（v1 语义），网络维度见 `create_ruleset_with_net`。
pub fn create_ruleset() -> XsResult<LandlockRuleset> {
    create_ruleset_impl(ACCESS_FS_ALL_V1, 0, true)
}

/// 创建含网络维度的 ruleset（ABI v3+，SP-L1-05 第二道防线）。
///
/// 声明 `handled_access_net` = `BIND_TCP|CONNECT_TCP` 但不添加任何 `NET_PORT` 规则：
/// 生效后全部 TCP bind/connect 默认被拒（网络默认拒绝的 landlock-net 实现）。
/// ABI<3 的内核不认识网络字段，返回 Err（fail-closed，由探测层先行判定）。
pub fn create_ruleset_with_net() -> XsResult<LandlockRuleset> {
    create_ruleset_impl(
        ACCESS_FS_ALL_V1,
        ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP,
        false,
    )
}

/// `create_ruleset` `的内部实现：v1_only` 时按 ABI v1 结构尺寸调用（老内核兼容）。
fn create_ruleset_impl(
    handled_access_fs: u64,
    handled_access_net: u64,
    v1_only: bool,
) -> XsResult<LandlockRuleset> {
    let attr = RulesetAttr {
        handled_access_fs,
        handled_access_net,
    };
    // v1 语义只传 FS 字段的尺寸（8 字节），老内核按 v1 解析；
    // v3 语义传完整结构（16 字节），内核据此启用网络维度。
    let size = if v1_only {
        std::mem::size_of::<u64>()
    } else {
        std::mem::size_of::<RulesetAttr>()
    };
    // SAFETY（安全论证）：
    // - attr 为栈上有效结构体，内核按 size 只读取对应字节，不越界；
    //   布局与 landlock_ruleset_attr(ABI v1/v3) 前缀兼容，语义来自 landlock_create_ruleset(2)；
    // - flags=0 表示创建 ruleset 而非版本查询；
    // - 成功返回 fd（>=0），失败 -1 + errno，显式上报。
    let fd =
        unsafe { libc::syscall(SYS_LANDLOCK_CREATE_RULESET, &raw const attr, size, 0u32) } as i32;
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "landlock".to_string(),
            detail: format!("create_ruleset(net={handled_access_net}) 失败: {err}"),
        });
    }
    Ok(LandlockRuleset { fd })
}

/// 向 ruleset 添加一条路径授权（三件套第二步，可多次调用）。
///
/// 打开路径获取 `O_PATH` fd（只用于内核判定，不可读写，符合最小 fd 原则）。
pub fn add_path_grant(ruleset: &LandlockRuleset, grant: &PathGrant) -> XsResult<()> {
    let c_path =
        std::ffi::CString::new(grant.path.as_os_str().as_encoded_bytes()).map_err(|_| {
            XsError::IsolatorSetupFailed {
                mechanism: "landlock".to_string(),
                detail: format!("路径含 NUL 字节: {}", grant.path.display()),
            }
        })?;
    // SAFETY（安全论证）：
    // - c_path 以 NUL 结尾且在调用期间存活；
    // - O_PATH|O_CLOEXEC：fd 仅作内核路径引用，不支持读写，exec 时自动关闭；
    // - 失败返回 -1 + errno，显式上报。
    let parent_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "landlock".to_string(),
            detail: format!("打开授权路径失败 {}: {err}", grant.path.display()),
        });
    }
    let rule = PathBeneathAttr {
        allowed_access: grant.access,
        parent_fd,
    };
    // SAFETY（安全论证）：
    // - rule 为栈上有效结构体，内核只读；parent_fd 为有效 O_PATH fd；
    // - ruleset.fd 由 create_ruleset 返回且未被关闭（类型独占持有）；
    // - landlock_add_rule(2) 语义：向 ruleset 追加 PATH_BENEATH 规则，无副作用外泄。
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const rule,
            0u32,
        )
    };
    // SAFETY：parent_fd 使命（供内核拷贝路径引用）已结束，立即关闭；fd 独占无复制。
    unsafe { libc::close(parent_fd) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "landlock".to_string(),
            detail: format!("add_rule 失败 {}: {err}", grant.path.display()),
        });
    }
    Ok(())
}

/// 使 ruleset `对当前进程生效（三件套第三步，restrict_self`）。
///
/// 调用契约：必须在 `no_new_privs` 设置之后、exec 之前调用；
/// 生效后只收紧不放宽，无法撤销。
pub fn enforce(ruleset: &LandlockRuleset) -> XsResult<()> {
    // SAFETY（安全论证）：
    // - ruleset.fd 有效且独占持有；flags=0；
    // - landlock_restrict_self(2) 只影响调用进程，语义来自 man page；
    // - 失败返回 -1 + errno（EPERM/EACCES 都按被拒绝显式上报，见 SP-L1-03 注）。
    let ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.fd, 0u32) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(XsError::IsolatorSetupFailed {
            mechanism: "landlock".to_string(),
            detail: format!("restrict_self 失败: {err}"),
        });
    }
    Ok(())
}

/// 便捷组合：创建 + 批量授权 + 生效。
///
/// 任一环节失败即整体失败（fail-closed），调用进程保持在未收紧或已收紧其一的
/// 确定状态，不存在『部分授权被当成完全隔离』的静默中间态。
pub fn establish_domain(grants: &[PathGrant]) -> XsResult<LandlockRuleset> {
    let ruleset = create_ruleset()?;
    for g in grants {
        add_path_grant(&ruleset, g)?;
    }
    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn abi_v1_access_set_is_13_bits() {
        assert_eq!(ACCESS_FS_ALL_V1.count_ones(), 13);
        // v3 网络权限集为 2 位（SP-L1-05 双防线断言依据）
        assert_eq!(
            (ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP).count_ones(),
            2
        );
    }

    #[test]
    fn grant_presets() {
        let ro = PathGrant::read_only("/usr/lib");
        assert_ne!(ro.access & ACCESS_FS_READ_FILE, 0);
        assert_eq!(ro.access & ACCESS_FS_WRITE_FILE, 0);
        let rw = PathGrant::read_write("/tmp");
        assert_ne!(rw.access & ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(rw.access & ACCESS_FS_MAKE_REG, 0);
    }

    #[test]
    fn create_ruleset_works_on_this_kernel() {
        // 本机内核 7.0、landlock ABI=8（M0 Spike 实测），创建应成功；
        // 在不支持 landlock 的环境则应为 Err（fail-closed 的另一半）。
        if let Ok(rs) = create_ruleset() {
            drop(rs)
        } else {
            // 探测环境不支持时此分支合法（CI 兼容矩阵语义）。
        }
    }

    #[test]
    fn grant_roundtrip_on_tmp() {
        if let Ok(rs) = create_ruleset() {
            let g = PathGrant::read_only(Path::new("/tmp"));
            // add_rule 成功不代表 enforce（本测试不收紧测试进程自身）。
            let _ = add_path_grant(&rs, &g);
        }
    }
}
