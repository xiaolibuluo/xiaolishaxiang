// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本文件属于 xiaolishaxiang 项目，本版权头任何人不得更改/删除。

//! xiaolishaxiang 命令行前端。
//!
//! 子命令：
//!   xs-cli check <config.toml>                   解析并验证配置，输出能力探测结果。
//!   xs-cli run <config.toml> <cmd...>            在沙箱内运行命令。
//!   xs-cli health                                 沙箱健康检查探针（输出 JSON）。
//!   xs-cli create <config.toml> [选项]            通过调度器分配节点并创建远程沙箱。
//!   xs-cli scheduler_demo [选项]                  调度器集成验证（分配→创建→销毁）。
//!   xs-cli list --daemon <addr>                    列出节点上所有活跃沙箱。
//!   xs-cli destroy --daemon <addr> --sandbox-id <id> [--token <token>]  销毁指定沙箱。
//!
//! 退出码遵循 fail-closed：任何失败都以非零码退出。

#![forbid(unsafe_code)]

// allow-file-length: CLI 多子命令入口聚合，参数解析与子命令分发保持单文件内聚
/// 数字水印（源码层）：小黎的部落。
const XIAOLISHAXIANG_WATERMARK_TEXT: &str = "小黎的部落（www.qingdujian.com）";
/// 数字水印（二进制层）：经 #[used] 保留于编译产物只读数据段，
/// 可用 strings <binary> | grep xiaolishaxiang-watermark 提取验证。
#[used]
static XIAOLISHAXIANG_WATERMARK_BIN: &[u8] =
    "xiaolishaxiang-watermark:v1:小黎的部落（www.qingdujian.com）".as_bytes();

mod scheduler_client;

#[allow(clippy::result_large_err)]
mod scheduler_proto {
    tonic::include_proto!("xiaolishaxiang.v1");
}

use std::path::PathBuf;
use std::process::ExitCode;
use xs_api::{self, build, ExitStatus, Sandbox, SandboxBuilder, SandboxCommand};
use xs_core::SandboxConfig;

/// 默认调度器 gRPC 地址
const DEFAULT_SCHEDULER_ADDR: &str = "0.0.0.0:50052";
/// 默认租户标识
const DEFAULT_TENANT_ID: &str = "default";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "用法: {} <check|run|health|create|scheduler_demo|list|destroy> [config.toml] [cmd...]",
            args[0]
        );
        return ExitCode::from(2);
    }

    let sub = args[1].as_str();
    if sub == "--version" || sub == "-V" {
        println!(
            "xs-cli {} | 数字水印: {}",
            env!("CARGO_PKG_VERSION"),
            XIAOLISHAXIANG_WATERMARK_TEXT
        );
        return ExitCode::SUCCESS;
    }

    // health / scheduler_demo / list / destroy 子命令不需要配置文件
    match sub {
        "health" => return cmd_health(),
        "scheduler_demo" => return cmd_scheduler_demo(&args).await,
        "list" => return cmd_list(&args).await,
        "destroy" => return cmd_destroy(&args).await,
        _ => {}
    }

    // 其余子命令需要配置文件
    if args.len() < 3 {
        eprintln!(
            "用法: {} <check|run|create> <config.toml> [cmd...]",
            args[0]
        );
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

    match sub {
        "check" => cmd_check(&cfg),
        "create" => cmd_create(&cfg, &text, &args[3..]).await,
        "list" | "destroy" => unreachable!(),
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
                "用法: {} <check|run|health|create|scheduler_demo|list|destroy> [config.toml] [cmd...]",
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

// ── create 子命令：通过调度器分配节点并创建远程沙箱 ──

/// 解析 create 子命令的额外参数。
struct CreateOptions {
    scheduler_addr: String,
    tenant_id: String,
    ttl_secs: u64,
    max_commands: u64,
    token: String,
}

fn parse_create_options(extra_args: &[String]) -> CreateOptions {
    let mut scheduler_addr = DEFAULT_SCHEDULER_ADDR.to_string();
    let mut tenant_id = DEFAULT_TENANT_ID.to_string();
    let mut ttl_secs: u64 = 0;
    let mut max_commands: u64 = 0;
    let mut token = String::new();

    let mut i = 0;
    while i < extra_args.len() {
        match extra_args[i].as_str() {
            "--scheduler" => {
                i += 1;
                if i < extra_args.len() {
                    scheduler_addr = extra_args[i].clone();
                }
            }
            "--tenant" => {
                i += 1;
                if i < extra_args.len() {
                    tenant_id = extra_args[i].clone();
                }
            }
            "--token" => {
                i += 1;
                if i < extra_args.len() {
                    token = extra_args[i].clone();
                }
            }
            "--ttl" => {
                i += 1;
                if i < extra_args.len() {
                    ttl_secs = extra_args[i].parse().unwrap_or(0);
                }
            }
            "--max-commands" => {
                i += 1;
                if i < extra_args.len() {
                    max_commands = extra_args[i].parse().unwrap_or(0);
                }
            }
            _ => {}
        }
        i += 1;
    }

    CreateOptions {
        scheduler_addr,
        tenant_id,
        ttl_secs,
        max_commands,
        token,
    }
}

async fn cmd_create(_cfg: &SandboxConfig, toml_text: &str, extra_args: &[String]) -> ExitCode {
    let opts = parse_create_options(extra_args);

    // Step 1: 向调度器请求分配最优节点
    let alloc = match scheduler_client::allocate_sandbox(
        &opts.scheduler_addr,
        &opts.tenant_id,
        toml_text,
        opts.ttl_secs,
        opts.max_commands,
    )
    .await
    {
        Ok(a) => {
            eprintln!(
                "调度结果: node_id={} node_address={} sandbox_id={}",
                a.node_id, a.node_address, a.sandbox_id
            );
            a
        }
        Err(e) => {
            eprintln!("调度失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    // 如果调度器已在节点上创建了沙箱，直接输出结果
    if !alloc.sandbox_id.is_empty() {
        println!("sandbox_id={}", alloc.sandbox_id);
        println!("node_id={}", alloc.node_id);
        println!("node_address={}", alloc.node_address);
        println!("created_at={}", alloc.created_at);
        return ExitCode::SUCCESS;
    }

    // Step 2: 直连 daemon 节点创建沙箱
    let create_resp = match scheduler_client::create_sandbox_on_node(
        &alloc.node_address,
        &opts.tenant_id,
        toml_text,
        opts.ttl_secs,
        opts.max_commands,
        &opts.token,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("创建沙箱失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("sandbox_id={}", create_resp.sandbox_id);
    println!("node_id={}", alloc.node_id);
    println!("node_address={}", alloc.node_address);
    println!("created_at={}", create_resp.created_at);
    ExitCode::SUCCESS
}

// ── scheduler_demo 子命令：调度器集成验证回路 ──

async fn cmd_scheduler_demo(args: &[String]) -> ExitCode {
    let mut scheduler_addr = DEFAULT_SCHEDULER_ADDR.to_string();
    let mut tenant_id = DEFAULT_TENANT_ID.to_string();
    let mut config_path: Option<String> = None;
    let mut token = String::new();

    let mut i = 2; // 跳过程序名和子命令名
    while i < args.len() {
        match args[i].as_str() {
            "--scheduler" => {
                i += 1;
                if i < args.len() {
                    scheduler_addr = args[i].clone();
                }
            }
            "--tenant" => {
                i += 1;
                if i < args.len() {
                    tenant_id = args[i].clone();
                }
            }
            "--config" => {
                i += 1;
                if i < args.len() {
                    config_path = Some(args[i].clone());
                }
            }
            "--token" => {
                i += 1;
                if i < args.len() {
                    token = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("scheduler_demo 需要 --config <config.toml>");
            return ExitCode::from(2);
        }
    };

    let config_toml = match std::fs::read_to_string(&config_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("读取配置失败 ({config_path}): {e}");
            return ExitCode::FAILURE;
        }
    };

    // 验证配置
    if let Err(e) = SandboxConfig::from_toml(&config_toml) {
        eprintln!("配置无效: {e}");
        return ExitCode::FAILURE;
    }

    eprintln!("=== 调度器集成验证 ===");
    eprintln!("调度器: {scheduler_addr}");
    eprintln!("租户:   {tenant_id}");
    eprintln!("配置:   {config_path}");
    eprintln!();

    // [1/3] 分配
    eprintln!("[1/3] 请求调度分配...");
    let alloc =
        match scheduler_client::allocate_sandbox(&scheduler_addr, &tenant_id, &config_toml, 0, 0)
            .await
        {
            Ok(a) => {
                eprintln!("  ✓ 节点: {} ({})", a.node_id, a.node_address);
                a
            }
            Err(e) => {
                eprintln!("  ✗ 分配失败: {e}");
                return ExitCode::FAILURE;
            }
        };

    // [2/3] 创建
    eprintln!("[2/3] 在节点上创建沙箱...");
    let create_resp = match scheduler_client::create_sandbox_on_node(
        &alloc.node_address,
        &tenant_id,
        &config_toml,
        0,
        0,
        &token,
    )
    .await
    {
        Ok(c) => {
            eprintln!("  ✓ sandbox_id: {}", c.sandbox_id);
            c
        }
        Err(e) => {
            eprintln!("  ✗ 创建失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    // [3/3] 销毁
    eprintln!("[3/3] 销毁沙箱...");
    match scheduler_client::destroy_sandbox_on_node(
        &alloc.node_address,
        &create_resp.sandbox_id,
        &token,
    )
    .await
    {
        Ok(()) => {
            eprintln!("  ✓ 已销毁 {}", create_resp.sandbox_id);
        }
        Err(e) => {
            eprintln!("  ✗ 销毁失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!();
    eprintln!("=== 集成验证通过 ===");
    ExitCode::SUCCESS
}

// ── list 子命令：列出节点上所有活跃沙箱 ──

async fn cmd_list(args: &[String]) -> ExitCode {
    let mut daemon_addr = "127.0.0.1:50051".to_string();

    let mut i = 2;
    while i < args.len() {
        if args[i] == "--daemon" {
            i += 1;
            if i < args.len() {
                daemon_addr = args[i].clone();
            }
        }
        i += 1;
    }

    let sandboxes = match scheduler_client::list_sandboxes_on_node(&daemon_addr).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("列表失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    if sandboxes.is_empty() {
        println!("(无活跃沙箱)");
    } else {
        for s in &sandboxes {
            println!(
                "{}\t{}\t{}\t{}\t{}",
                s.sandbox_id, s.tenant_id, s.state, s.command_count, s.created_at
            );
        }
    }

    eprintln!("共 {} 个活跃沙箱", sandboxes.len());
    ExitCode::SUCCESS
}

// ── destroy 子命令：销毁指定沙箱 ──

async fn cmd_destroy(args: &[String]) -> ExitCode {
    let mut daemon_addr = "127.0.0.1:50051".to_string();
    let mut sandbox_id = String::new();
    let mut token = String::new();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--daemon" => {
                i += 1;
                if i < args.len() {
                    daemon_addr = args[i].clone();
                }
            }
            "--sandbox-id" => {
                i += 1;
                if i < args.len() {
                    sandbox_id = args[i].clone();
                }
            }
            "--token" => {
                i += 1;
                if i < args.len() {
                    token = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }

    if sandbox_id.is_empty() {
        eprintln!("destroy 需要 --sandbox-id <sandbox_id>");
        return ExitCode::from(2);
    }

    match scheduler_client::destroy_sandbox_on_node(&daemon_addr, &sandbox_id, &token).await {
        Ok(()) => {
            println!("沙箱已销毁: {sandbox_id}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("销毁失败: {e}");
            ExitCode::FAILURE
        }
    }
}
