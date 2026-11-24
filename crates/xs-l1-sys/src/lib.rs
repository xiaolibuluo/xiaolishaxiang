// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang L1 系统隔离层（Linux 专用）。
//!
//! 本 crate 是唯一允许 unsafe 的业务 crate（syscall / libc 交互）。
//! 每条 unsafe 块必须附安全论证注释（不变量、为什么安全、调用契约）。
//!
//! M1 最小可用范围：landlock ABI 探测、seccomp 安装状态检查。
//! 完整隔离域建立（namespace + landlock 域 + filter 安装）在 M1 后续迭代落地。

#![warn(missing_docs)]

pub mod domain;
pub mod filter;
pub mod landlock;
pub mod namespace;
pub mod ruleset;
pub mod seccomp;
pub mod supervisor;

pub use domain::{prepare_in_child, probe, DomainSpec};
pub use filter::{install, set_no_new_privs, SeccompAllowlist};
pub use landlock::probe_abi;
pub use namespace::{in_container, userns_sysctl_permits, NsFlags};
pub use ruleset::{
    add_path_grant, create_ruleset, create_ruleset_with_net, enforce, establish_domain,
    LandlockRuleset, PathGrant,
};
pub use seccomp::{current_status, is_locked_by_upper, SeccompMode};
pub use supervisor::{ExitStatus, L1Domain, SandboxCommand};
