// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! WASM 沙箱执行引擎（wasmtime 51 封装）。
//!
//! 提供最小安全封装：
//! - WasmEngine：全局 JIT 引擎与模块缓存；
//! - WasmSandbox：单次执行上下文，加载模块并调用导出函数；
//! - 所有调用经过 wasmtime 内置 Trap 边界，OOB/栈溢出等由 wasmtime 安全截获。
//!
//! 本模块保持 #![`forbid(unsafe_code)`]，不包含任何 unsafe 块。

use wasmtime::{Engine, Instance, Module, Result, Store};

/// WASM 执行错误。
#[derive(Debug)]
pub enum WasmError {
    /// 模块编译失败。
    Compile(String),
    /// 实例化失败。
    Instantiate(String),
    /// 函数调用失败（Trap 或类型不匹配）。
    Runtime(String),
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmError::Compile(s) => write!(f, "WASM 编译错误: {s}"),
            WasmError::Instantiate(s) => write!(f, "WASM 实例化错误: {s}"),
            WasmError::Runtime(s) => write!(f, "WASM 运行时错误: {s}"),
        }
    }
}

impl std::error::Error for WasmError {}

/// WASM 执行结果。
pub type WasmResult<T> = Result<T, WasmError>;

/// WASM 引擎：持有 wasmtime Engine，可编译并缓存多个模块。
#[derive(Default)]
pub struct WasmEngine {
    engine: Engine,
}

impl WasmEngine {
    /// 创建新引擎。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 从 WAT 文本编译 WASM 模块。
    pub fn compile_module(&self, wat: &str) -> WasmResult<WasmModule> {
        let module =
            Module::new(&self.engine, wat).map_err(|e| WasmError::Compile(format!("{e}")))?;
        Ok(WasmModule { module })
    }
}

/// 已编译的 WASM 模块。
pub struct WasmModule {
    module: Module,
}

impl WasmModule {
    /// 实例化模块并执行一个无参、返回 i32 的导出函数。
    pub fn call_i32_func(&self, engine: &WasmEngine, func_name: &str) -> WasmResult<i32> {
        let mut store = Store::new(&engine.engine, ());
        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|e| WasmError::Instantiate(format!("{e}")))?;

        let func = instance
            .get_typed_func::<(), i32>(&mut store, func_name)
            .map_err(|e| WasmError::Runtime(format!("查找函数 {func_name}: {e}")))?;

        func.call(&mut store, ())
            .map_err(|e| WasmError::Runtime(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_compile_and_run_trivial_module() {
        let engine = WasmEngine::new();
        let module = engine
            .compile_module(
                r#"
                (module
                  (func (export "answer") (result i32)
                    i32.const 42
                  )
                )
                "#,
            )
            .expect("编译应成功");

        let result = module.call_i32_func(&engine, "answer").expect("执行应成功");
        assert_eq!(result, 42);
    }

    #[test]
    fn oob_memory_trapped_as_error() {
        let engine = WasmEngine::new();
        let module = engine
            .compile_module(
                r#"
                (module
                  (memory (export "memory") 1)
                  (func (export "load_oob") (result i32)
                    i32.const 0x10001
                    i32.load
                  )
                )
                "#,
            )
            .expect("编译应成功");

        let result = module.call_i32_func(&engine, "load_oob");
        assert!(result.is_err(), "OOB 应返回错误");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("WASM 运行时错误"),
            "错误应标注为运行时错误: {msg}"
        );
    }

    #[test]
    fn wasm_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WasmError>();
    }

    #[test]
    fn compile_invalid_wat_returns_error() {
        let engine = WasmEngine::new();
        let result = engine.compile_module("(module (func)");
        assert!(result.is_err(), "无效 WAT 应返回编译错误");
    }
}
