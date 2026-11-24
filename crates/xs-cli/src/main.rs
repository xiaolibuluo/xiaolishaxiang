// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 命令行前端。
//!
//! 子命令：
//!   xs-cli check <config.toml>          解析并验证配置，输出能力探测结果。
//!   xs-cli run <config.toml> <cmd...>   在沙箱内运行命令。
//!   xs-cli health                        沙箱健康检查探针（输出 JSON）。
//!
//! 退出码遵循 fail-closed：任何失败都以非零码退出。

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use xs_api::{self, build, ExitStatus, Sandbox, SandboxBuilder, SandboxCommand};
use xs_core::SandboxConfig;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "用法: {} <check|run|health> [config.toml] [cmd...]",
            args[0]
        );
        return ExitCode::from(2);
    }

    let sub = &args[1];

    // health 子命令不需要配置文件
    if sub == "health" {
        return cmd_health();
    }

    if args.len() < 3 {
        eprintln!("用法: {} <check|run> <config.toml> [cmd...]", args[0]);
        return ExitCode::from(2);
    }

    let config_path = &args[2];

    let text = match std::fs::read_to_string(config_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("读取配置失败 ({config_path}): {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = match SandboxConfig::from_toml(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    match sub.as_str() {
        "check" => cmd_check(&cfg),
        "run" => {
            if args.len() < 4 {
                eprintln!("run 子命令需要指定要执行的命令");
                eprintln!("用法: {} run <config.toml> <program> [args...]", args[0]);
                return ExitCode::from(2);
            }
            cmd_run(&cfg, &args[3..])
        }
        other => {
            eprintln!("未知子命令: {other}");
            eprintln!(
                "用法: {} <check|run|health> [config.toml] [cmd...]",
                args[0]
            );
            ExitCode::from(2)
        }
    }
}

fn cmd_check(cfg: &SandboxConfig) -> ExitCode {
    if let Err(e) = cfg.validate() {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }

    let _builder = match SandboxBuilder::new(cfg.clone()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    println!("配置验证通过: min_assurance={:?}", cfg.min_assurance);
    println!("内核: {}", xs_core::probe::kernel_release());

    if let Ok(report) = xs_api::probe() {
        println!("内核: {}", report.kernel);
        println!("有效保证等级: {:?}", report.effective);
        println!("landlock ABI: {:?}", report.landlock_abi);
        for outcome in &report.outcomes {
            println!("  {}: {}", outcome.item, outcome.available);
        }
        if let Err(e) = report.enforce(cfg.min_assurance) {
            eprintln!("警告: 当前环境不满足 min_assurance 要求: {e}");
        }
    }

    ExitCode::SUCCESS
}

fn cmd_run(cfg: &SandboxConfig, cmd_args: &[String]) -> ExitCode {
    let _builder = match SandboxBuilder::new(cfg.clone()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("配置无效: {e}");
            return ExitCode::FAILURE;
        }
    };

    let sandbox: Sandbox = match build(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("沙箱装配失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    let program = PathBuf::from(&cmd_args[0]);
    let sargs: Vec<String> = cmd_args[1..].to_vec();

    let sc = SandboxCommand {
        program,
        args: sargs,
        env: vec![],
    };

    match sandbox.run(sc) {
        Ok(ExitStatus::Exited(0)) => ExitCode::SUCCESS,
        Ok(ExitStatus::Exited(code)) => {
            let code_u8: u8 = (code as u32).try_into().unwrap_or(1);
            ExitCode::from(code_u8)
        }
        Ok(ExitStatus::Signaled(sig)) => {
            eprintln!("沙箱内进程被信号 {sig} 终止");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("沙箱执行失败: {e}");
            ExitCode::FAILURE
        }
    }
}

/// 沙箱健康检查探针：执行一次完整的隔离生命周期并输出 JSON 指标。
/// 退出码：0 = sandbox_ok，1 = 沙箱不可用。
fn cmd_health() -> ExitCode {
    let report = xs_api::health();
    let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
    println!("{json}");
    if report.sandbox_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
