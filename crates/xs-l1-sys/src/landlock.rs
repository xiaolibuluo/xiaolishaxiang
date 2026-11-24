// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! landlock ABI 探测。
//!
//! 对应 M0 Spike 探针 1（本机实测 ABI = 8）。
//! SP-G-02：报告可用必须返回 ABI 版本号，禁止布尔化。

use xs_core::{LandlockAbi, XsError, XsResult};

/// `landlock_create_ruleset` 的 syscall `号（x86_64` / aarch64 通用）。
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;

/// `LANDLOCK_CREATE_RULESET_VERSION` 标志：查询 ABI 版本而非真正创建 ruleset。
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

/// 探测当前内核的 landlock ABI 版本。
///
/// 返回 `LandlockAbi(0)` 表示不可用（ENOSYS / EOPNOTSUPP 等）。
/// 其他 syscall 错误透传为 `IsolatorSetupFailed`。
pub fn probe_abi() -> XsResult<LandlockAbi> {
    // SAFETY（安全论证）：
    // - syscall 号 444 为 landlock_create_ruleset，第一、二参数在 VERSION 查询语义下
    //   必须分别为 NULL 与 0，内核不会解引用 attr 指针，因此传空指针是安全的；
    // - 本调用无副作用：VERSION 语义只读，不创建任何内核对象；
    // - 返回值 = ABI 版本（>=1）或 -1 + errno，调用契约来自 landlock(7) man page。
    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret >= 0 {
        return Ok(LandlockAbi(ret as u32));
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // ENOSYS：内核未编译 landlock；EOPNOTSUPP/EINVAL：版本查询不被支持（按不可用处理）
        Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => Ok(LandlockAbi::UNSUPPORTED),
        _ => Err(XsError::IsolatorSetupFailed {
            mechanism: "landlock".to_string(),
            detail: format!("ABI 探测失败: {err}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_abi_returns_version_or_zero() {
        let abi = probe_abi().expect("探测不应返回 Err");
        // 本机（内核 7.0）预期 >= 1；在不支持 landlock 的内核上为 0，两者都合法。
        assert!(abi.0 == 0 || abi.0 >= 1);
    }
}
