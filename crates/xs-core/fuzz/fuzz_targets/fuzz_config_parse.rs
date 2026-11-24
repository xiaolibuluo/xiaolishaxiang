// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! fuzz 冒烟目标：配置解析器（docs/04-TEST-MATRIX.md 第 2 级 Required，M3）。
//!
//! 不变量（SP-G-01 fail-closed）：
//! - from_toml 对任意字节输入不得 panic / abort——解析失败只能返回 Err；
//! - 解析成功的配置必须能通过 validate() 复检（解析成功但校验拒绝属合法
//!   fail-closed 路径；两者都不允许崩溃）。

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 任意字节 -> UTF-8 尝试（lossy 转换本身不 panic）。
    let text = String::from_utf8_lossy(data);
    // 解析：任意输入不得 panic；Err 为合法 fail-closed 路径。
    if let Ok(cfg) = xs_core::SandboxConfig::from_toml(&text) {
        // 解析成功必须能经受 validate 复检（同样只允许 Err，不允许 panic）。
        let _ = cfg.validate();
    }
});
