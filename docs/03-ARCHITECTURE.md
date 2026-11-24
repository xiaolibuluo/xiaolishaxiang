<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 架构与代码组织

## 1. 三层隔离架构

| 层 | 名称 | 职责 | 机制 |
|---|---|---|---|
| L1 | 系统隔离层 | 文件系统视图、系统调用、进程边界、网络边界隔离 | namespace + seccomp（allowlist，io_uring 默认关闭）+ landlock + no_new_privs + ptrace 限制 + network namespace |
| L2 | 资源治理层 | CPU / 内存 / IO / 网络配额、限流与背压 | cgroup v2 + rlimit + 令牌桶限速器 |
| L3 | 运行时隔离层 | 内存安全执行、能力（capability）最小授权 | WASM 沙箱（wasmtime）+ capability 句柄表 |

设计原则：

- 三层各自实现统一 trait（SystemIsolator / ResourceGovernor / RuntimeSandbox），逐层收紧、可独立启用、可组合叠加；
- 层间只通过窄接口通信，单层失效不波及其他层；
- trait 抽象保留是为测试替身与未来 VM 后端留口，不做跨操作系统抽象（本项目仅 Linux）；
- trait 暴露 capabilities() / assurance_level()，返回运行时探测后的有效值（见 docs/02-ASSURANCE-LEVELS.md）。

## 2. workspace 代码组织

M1 实际落地状态（2026-11-24）：

```text
xiaolishaxiang/
├── Cargo.toml            # workspace 根（6 个成员 crate）
├── rust-toolchain.toml   # 贡献者/CI 工具链锁定 1.100.0
├── LICENSE               # AGPL-3.0 全文（665 行含版权头）
├── README.md / SECURITY.md / deny.toml
├── docs/                 # M0 全部规约文档（00~06）
├── crates/
│   ├── xs-core/          # 7 模块：error / assurance / audit / capability /
│   │                     #   config / isolator(trait) / probe（14 测试，forbid unsafe）
│   ├── xs-l1-sys/        # 7 模块：landlock(ABI 探测) / seccomp(状态) / namespace /
│   │                     #   filter(BPF) / ruleset(landlock 域) / domain(编排) /
│   │                     #   supervisor(fork+exec) + tests/l1_isolation.rs 集成测试
│   │                     #   （17 单测 + 4 集成测试；唯一允许 unsafe 的 crate）
│   ├── xs-l2-res/        # M1 占位骨架（M2 完整实现 cgroup v2 治理）
│   ├── xs-l3-rt/         # handle.rs 能力句柄数据模型（3 测试；wasmtime 于 M3 引入）
│   ├── xs-api/           # lib + sandbox.rs 编排层（build: 校验→探测→判定→建域，5 测试）
│   └── xs-cli/           # main.rs：xs-cli check <config.toml> 配置验证
├── ci/
│   ├── check_copyright.sh   # Blocker 1：版权头扫描（reuse 迁移前最小实现）
│   ├── check_file_length.sh # Blocker 2：单文件 500 行上限 + 豁免机制
│   └── run_blocker.sh       # Blocker 总入口（7 道门禁一键执行）
├── spike/                # M0 探针代码与日志（spike1/spike2，探针原型固化）
└── docs/06-M0-SPIKE.md   # 探针实测结果（landlock ABI=8 等）
```

M1 验证基线：30 个测试全绿（debug+release 双模式）、零编译警告、
Blocker 门禁 7 道全部通过。fuzz/ 与 benches/ 按里程碑在 M3/M2 建立。

## 3. 工程纪律（CI 强制）

- 一类一文件：一个结构体 / trait / 单一职责模块一个文件；
- 单文件不超过 500 行；允许文件内显式豁免标记（必须附理由），CI 报告列出豁免清单，而非无条件 fail；
- 版权头：每个源文件必须含 SPDX 标识与『Copyright (C) 小黎的部落（www.qingdujian.com）』，由 reuse 工具校验，覆盖 .rs 及 toml / yml / sh / Dockerfile 等全部文件类型；禁止自写正则校验（避免 shebang、模块文档、属性顺序误伤）。

## 4. unsafe 策略

- unsafe 只允许出现在 xs-l1-sys 及必要 FFI 层；
- 其余 crate 一律 #![forbid(unsafe_code)]；
- unsafe 审查清单：每条 unsafe 块必须附安全论证注释（不变量、为什么安全、调用契约），M3 起作为 Required 门禁的人工核查项。

## 5. 可观测性（xs-core，M1 交付）

- 结构化审计日志：能力请求、拒绝事件、资源超限事件必落审计；
- no-record → no-execute：审计不可用则不得执行（SP-G-01）；
- 审计通道独立配额与丢弃策略（SP-L2-04）：溢出降级为『标记事件丢失』而非静默丢弃；
- 指标与追踪：tracing + OpenTelemetry。

## 6. 工具链与 MSRV

- rust-toolchain.toml 锁定 channel = 1.100.0，components = [clippy, rustfmt, rust-src]，这是贡献者与 CI 环境；
- Cargo.toml 的 rust-version 字段是对外承诺的 MSRV，M1 第一个 commit 即写入；两个数字语义不同，文档分开表述，下游集成方无需安装 1.100.0；
- 本机预装 1.99.1 仅用于 M0 Spike 探针编译，不代表项目工具链；M1 起由 rustup 安装 1.100.0；
- nightly（1.102.0）仅用于 Miri / TSan 等检查辅助，其结论只作趋势参考：nightly 编译产物与 stable 发布产物非同一编译器，不作为发布判据。

## 7. 依赖治理要点

- wasmtime / tokio / libc 版本策略、cargo-deny advisory 白名单、vendoring 决策见 docs/05-SUPPLY-CHAIN.md；
- wasmtime 攻击面纳入审计范围，版本升级需独立审查。

## 8. fail-closed 语义

配置解析失败、能力未识别、内核特性不支持、探测低于 min_assurance、审计不可用、隔离机制安装顺序错误——一律拒绝启动 / 拒绝执行，禁止降级放行（SP-G-01 完整清单见 docs/01-SECURITY-PROPERTIES.md）。
