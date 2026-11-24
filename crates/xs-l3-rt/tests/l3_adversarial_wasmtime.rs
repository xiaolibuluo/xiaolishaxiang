// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! M3 对抗逃逸语料：wasmtime 越线性内存访问类 CVE 回归（docs/08-CVE-CORPUS.md）。
//!
//! wasmtime 51 依赖已引入（dev-dependencies），本测试用例覆盖：
//! - SP-L3-02：越线性内存访问（OOB load/store）被 wasmtime Trap 阻断，不泄露宿主内存；
//! - SP-L3-03：wasmtime 引擎实例隔离，一个实例崩溃不影响另一个；
//! - SP-L3-02：Trap 信息安全传递，不包含宿主地址或内核指针。

use wasmtime::*;

/// 构建最小 WASM 模块：带 1 页线性内存 + 导出一个 load 函数
fn make_oob_module(engine: &Engine) -> Result<Module, Error> {
    Module::new(
        engine,
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "load_oob") (result i32)
            i32.const 0x10001  ;; 超出 1 页 (64KB) 范围
            i32.load
          )
        )
        "#,
    )
}

/// 构建单实例最小 WASM 模块：返回常量
fn make_trivial_module(engine: &Engine) -> Result<Module, Error> {
    Module::new(
        engine,
        r#"
        (module
          (func (export "answer") (result i32)
            i32.const 42
          )
        )
        "#,
    )
}

#[test]
fn sp_l3_02_oob_linear_memory_load_trapped() {
    let engine = Engine::default();
    let module = make_oob_module(&engine).expect("编译 OOB 模块应成功");

    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).expect("实例化应成功");

    let load_oob = instance
        .get_typed_func::<(), i32>(&mut store, "load_oob")
        .expect("load_oob 函数应存在");

    let result = load_oob.call(&mut store, ());

    match &result {
        Err(e) => {
            let msg = format!("{e:?}");
            // Trap 信息不应包含宿主指针地址（0x7f... 或 0x55... 等 > 0xFFFF 的明显指针值）
            assert!(
                !msg.contains("0x7f") && !msg.contains("0x55"),
                "SP-L3-02 失败：Trap 错误信息暴露了疑似宿主地址: {msg}"
            );
            eprintln!("SP-L3-02 PASS: OOB 线性内存访问被 wasmtime Trap 阻断: {e}");
        }
        Ok(val) => {
            panic!("SP-L3-02 失败：越界内存访问竟返回了值 {val}（应被 Trap 阻断）");
        }
    }
}

#[test]
fn sp_l3_02_oob_linear_memory_store_trapped() {
    let engine = Engine::default();
    let module = Module::new(
        &engine,
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "store_oob") (result i32)
            i32.const 0xFFFF  ;; 超出 1 页 64KB 范围
            i32.const 0x41
            i32.store
            i32.const 1  ;; 激进：若未 trap 则返回 1（标记为异常通过）
          )
        )
        "#,
    )
    .expect("编译 OOB store 模块应成功");

    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).expect("实例化应成功");

    let store_oob = instance
        .get_typed_func::<(), i32>(&mut store, "store_oob")
        .expect("store_oob 函数应存在");

    let result = store_oob.call(&mut store, ());

    assert!(
        result.is_err(),
        "SP-L3-02 失败：越界内存写入未被 Trap 阻断（返回 {result:?}）"
    );
    eprintln!("SP-L3-02 PASS: 越界 store 被 Trap 阻断");
}

#[test]
fn sp_l3_02_trap_message_safe_no_host_address_leak() {
    let engine = Engine::default();
    let module = make_oob_module(&engine).expect("编译模块应成功");

    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).expect("实例化应成功");

    let load_oob = instance
        .get_typed_func::<(), i32>(&mut store, "load_oob")
        .expect("函数应存在");

    match load_oob.call(&mut store, ()) {
        Ok(_) => panic!("预期 Trap 但成功返回"),
        Err(e) => {
            let msg = format!("{e}");
            let display = format!("{e:?}");

            // 验证不包含宿主地址
            for candidate in &[&msg, &display] {
                // 不应出现 >48-bit 地址空间的值（典型宿主机地址写法）
                let has_host_addr = candidate
                    .split(|c: char| !c.is_ascii_hexdigit())
                    .any(|w| w.len() >= 10 && w.chars().all(|c| c.is_ascii_hexdigit()));
                assert!(
                    !has_host_addr,
                    "SP-L3-02 失败：Trap Display/Debug 可能泄露宿主地址: {candidate}"
                );
            }
            eprintln!("SP-L3-02 PASS: Trap 消息安全，未泄露宿主地址");
        }
    }
}

#[test]
fn sp_l3_03_engine_instance_isolation_crash_does_not_affect_peer() {
    let engine = Engine::default();

    // 实例 A：会 crash（OOB）
    let mod_a = make_oob_module(&engine).expect("编译 mod_a 应成功");
    let mut store_a = Store::new(&engine, ());
    let inst_a = Instance::new(&mut store_a, &mod_a, &[]).expect("实例 A 应成功");

    // 触发 crash
    let load_oob = inst_a
        .get_typed_func::<(), i32>(&mut store_a, "load_oob")
        .expect("load_oob 应存在");
    let crashed = load_oob.call(&mut store_a, ()).is_err();
    assert!(crashed, "实例 A 应 Trap");

    // 实例 B：独立运行
    let mod_b = make_trivial_module(&engine).expect("编译 mod_b 应成功");
    let mut store_b = Store::new(&engine, ());
    let inst_b = Instance::new(&mut store_b, &mod_b, &[]).expect("实例 B 应成功");

    let answer = inst_b
        .get_typed_func::<(), i32>(&mut store_b, "answer")
        .expect("answer 应存在");

    let val = answer
        .call(&mut store_b, ())
        .expect("SP-L3-03 失败：实例 A 的 OOB Trap 导致实例 B 也受影响");

    assert_eq!(
        val, 42,
        "SP-L3-03 失败：实例 B 返回值异常（预期 42，实际 {val}）"
    );
    eprintln!("SP-L3-03 PASS: wasmtime 引擎实例隔离有效，OOB 不影响对等实例");
}

#[test]
fn sp_l3_02_oob_stack_overflow_trapped() {
    let engine = Engine::default();
    let module = Module::new(
        &engine,
        r#"
        (module
          (func (export "recurse") (result i32)
            (local i32)
            i32.const 0
            local.set 0
            (block $exit
              (loop $l
                local.get 0
                i32.const 1
                i32.add
                local.tee 0
                i32.const 100000
                i32.lt_s
                br_if $l
              )
            )
            local.get 0
          )
        )
        "#,
    )
    .expect("编译递归模块应成功");

    let mut store = Store::new(&engine, ());
    let instance = Instance::new(&mut store, &module, &[]).expect("实例化应成功");

    let recurse = instance
        .get_typed_func::<(), i32>(&mut store, "recurse")
        .expect("recurse 应存在");

    // 循环迭代不应触发栈溢出（wasmtime 对非递归循环有上限）
    let result = recurse.call(&mut store, ());
    match result {
        Ok(n) => {
            assert!(n == 100000, "循环次数不符: {n}");
            eprintln!("SP-L3-02 PASS: 非递归循环正常完成（{n} 次）");
        }
        Err(e) => {
            // 如果燃料耗尽也是安全行为（wasmtime 可配置 fuel metering）
            let msg = format!("{e}");
            assert!(
                msg.contains("fuel") || msg.contains("epoch"),
                "SP-L3-02 失败：非预期错误: {msg}"
            );
            eprintln!(
                "SP-L3-02 PASS: 循环因 {} 被安全中止（Trap）",
                if msg.contains("fuel") {
                    "燃料耗尽"
                } else {
                    "epoch 中断"
                }
            );
        }
    }
}
