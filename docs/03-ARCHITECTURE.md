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
| L3 | 运行时隔离层 | 内存安全执行、能力（capability）最小授权 | WASM 沙箱（wasmtime 51）+ capability 句柄表 |

设计原则：

- 三层各自实现统一 trait（SystemIsolator / ResourceGovernor / RuntimeSandbox），逐层收紧、可独立启用、可组合叠加；
- 层间只通过窄接口通信，单层失效不波及其他层；
- trait 抽象保留是为测试替身与未来 VM 后端留口，不做跨操作系统抽象（本项目仅 Linux）；
- trait 暴露 capabilities() / assurance_level()，返回运行时探测后的有效值（见 docs/02-ASSURANCE-LEVELS.md）。

## 2. workspace 代码组织

当前 workspace 共 9 个成员 crate（Cargo.toml version 1.0.11）：

```text
xiaolishaxiang/
├── Cargo.toml            # workspace 根（9 个成员 crate）
├── rust-toolchain.toml   # 贡献者/CI 工具链锁定 1.100.0
├── LICENSE               # AGPL-3.0 全文
├── README.md / SECURITY.md / deny.toml / supply-chain/
├── docs/                 # 规约与实测文档（00~14）
├── proto/xiaolishaxiang/v1/  # sandbox.proto（6 RPC）+ scheduler.proto（4 RPC）
├── crates/
│   ├── xs-core/          # error / assurance / audit / capability / config /
│   │                     #   isolator(trait) / probe（14 测试，forbid unsafe）
│   ├── xs-l1-sys/        # landlock(ABI 探测) / seccomp / namespace / filter(BPF) /
│   │                     #   ruleset / domain / supervisor（17 单测 + 4 集成；
│   │                     #   唯一允许 unsafe 的 crate）
│   ├── xs-l2-res/        # cgroup v2 治理 / 背压 / 审计通道
│   ├── xs-l3-rt/         # wasmtime 51 运行时 + capability 句柄表
│   ├── xs-api/           # 编排层（build：校验→探测→判定→建域，5 测试）
│   ├── xs-cli/           # xs-cli check <config.toml> 配置验证
│   ├── xs-daemon/        # 单机多租户守护：gRPC 50051 + HTTP 3000，
│   │                     #   沙箱池 pool.rs（max_size 默认 128）/ 租户 / 审计
│   ├── xs-policy/        # 策略模型
│   └── xs-scheduler/     # 集群调度：gRPC 50052，节点管理 / 分配
├── ci/
│   ├── check_copyright.sh   # 版权头扫描（reuse lint + 持有者行检查）
│   ├── check_file_length.sh # 单文件 500 行上限 + 豁免机制
│   ├── run_blocker.sh       # Blocker 总入口
│   ├── run_fuzz_smoke.sh    # fuzz 冒烟（默认 60s）
│   ├── run_soak.sh          # soak 长跑
│   ├── run_sbom.sh          # SBOM 生成
│   └── systemd/             # fuzz / soak timer 单元
└── spike/                # M0 探针代码与日志
```

质量基线：workspace 36 个测试套件全部通过、0 失败（`cargo test --workspace --locked`，2026-11-25）；本机 172 用例全绿（内核 7.0.0-42，2026-11-24）。

## 3. 工程纪律（CI 强制）

- 一类一文件：一个结构体 / trait / 单一职责模块一个文件；
- 单文件不超过 500 行；允许文件内显式豁免标记（必须附理由），CI 报告列出豁免清单，而非无条件 fail；
- 版权头：每个源文件必须含 SPDX 标识与『Copyright (C) 小黎的部落（www.qingdujian.com）』，由 REUSE 工具权威校验（reuse 6.3.0，7875/7875 文件全合规），覆盖 .rs 及 toml / yml / sh / Dockerfile 等全部文件类型；禁止自写正则校验。

## 4. unsafe 策略

- unsafe 只允许出现在 xs-l1-sys 及必要 FFI 层；
- 其余 crate 一律 #![forbid(unsafe_code)]；
- unsafe 审查清单：每条 unsafe 块必须附安全论证注释（不变量、为什么安全、调用契约），作为 Required 门禁的人工核查项；当前基线 16 处 unsafe 全部 PASS（docs/07-UNSAFE-REVIEW.md）。

## 5. 可观测性（xs-core）

- 结构化审计日志：能力请求、拒绝事件、资源超限事件必落审计；
- no-record → no-execute：审计不可用则不得执行（SP-G-01）；
- 审计通道独立配额与丢弃策略（SP-L2-04）：溢出降级为『标记事件丢失』而非静默丢弃；
- 指标与追踪：tracing + OpenTelemetry。

## 6. 工具链与 MSRV

- rust-toolchain.toml 锁定 channel = 1.100.0，components = [clippy, rustfmt, rust-src]，这是贡献者与 CI 环境；
- Cargo.toml 的 rust-version 字段是对外承诺的 MSRV；两个数字语义不同，下游集成方无需安装 1.100.0；
- nightly（1.102.0）仅用于 fuzz / Miri / TSan 等检查辅助，其结论只作趋势参考：nightly 编译产物与 stable 发布产物非同一编译器，不作为发布判据。

## 7. 依赖治理要点

- wasmtime / tokio / libc 版本策略、cargo-deny advisory 白名单、vendoring 决策见 docs/05-SUPPLY-CHAIN.md；
- wasmtime 攻击面纳入审计范围，版本升级需独立审查。

## 8. fail-closed 语义

配置解析失败、能力未识别、内核特性不支持、探测低于 min_assurance、审计不可用、隔离机制安装顺序错误——一律拒绝启动 / 拒绝执行，禁止降级放行（SP-G-01 完整清单见 docs/01-SECURITY-PROPERTIES.md）。
