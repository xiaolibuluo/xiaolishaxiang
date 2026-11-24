// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang L3 运行时隔离层（WASM 沙箱与能力句柄表）。
//!
//! wasmtime 51 已正式引入（M4 落地），提供 WASM 模块加载与安全执行能力。
//! 版本升级需独立审查并复跑对抗逃逸语料（docs/05-SUPPLY-CHAIN.md 第 2 节）。

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod handle;
pub mod wasm;

pub use handle::CapabilityHandle;
pub use wasm::{WasmEngine, WasmError, WasmModule};
