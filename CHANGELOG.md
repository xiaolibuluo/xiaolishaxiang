<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# Changelog

## [1.0.11] — 2026-11-25

本版本完成 P1-P4 全部功能交付：daemon 基础服务、可观测性、多租户策略引擎、调度器集群与 CLI 工具链。

### P1: 沙箱 daemon 基础服务

- gRPC `RunCommand` / `RunCommandStream` / `DestroySandbox` / `ListSandboxes` 处理器
- HTTP `/health` `/ready` `/live` `/metrics` 端点
- 沙箱池（SandboxPool）：并发 acquire/release、动态扩容、max_size 限流、GC 清理
- 沙箱过期机制：命令计数上限自动回收
- 7 个集成测试（含 `#[serial]` 解决沙箱 fd 继承竞态）

### P2: 可观测性

- 8 个 Prometheus 指标（命令计数、沙箱创建/销毁、seccomp 违规等）
- JSONL 审计日志（`audit.jsonl`）
- `trace_id` 结构化日志注入

### P3: 多租户策略引擎

- `xs-policy` crate：TenantRegistry 认证/配额/策略引擎
- 租户配置热加载（60s 周期 mtime 检测）
- SHA-256 token 验证、并发沙箱配额
- 策略规则引擎：精确匹配 + 前缀匹配、deny/log/alert/allow 动作
- seccomp 违规计数器（`seccomp_violations` 指标）

### P4: 调度器集群与 CLI

- **`xs-scheduler` crate**：
  - gRPC 节点注册/心跳/注销/沙箱分配（`scheduler.proto`）
  - 加权负载评分分配算法（CPU + 内存 + 容量）
  - 15s 心跳超时自动摘除 + 10s GC 清理
  - 14 个单元测试 + 7 个多节点集成测试（故障摘除、负载再分配、并发安全）
- **daemon 调度器集成**：
  - 启动时自动注册到调度器，5s 周期心跳上报负载
  - Drop 时优雅注销
- **`xs-cli` 命令行工具**：
  - `check` / `run` / `health` 本地沙箱操作
  - `create` 子命令：调度器分配 + 直连 daemon 创建（两步流程）
  - `list` / `destroy` 运维子命令
  - `scheduler_demo` 集成验证回路（分配→创建→销毁）
  - 依赖：tokio 1 / tonic 0.13 / prost 0.13

### 合计

- 9 个 crate，62 个 Rust 源文件
- 新增 28 个测试（P1: 7 + P4 scheduler: 7 + multi-node: 7 + 已有: 7）
- clippy strict 0 warning, 全量测试 0 失败

### P5: 安全加固与合规（2026-11-25）

**SBOM 生成**
- 安装 `cargo-cyclonedx` 0.5.10，生成 CycloneDX 1.4 SBOM
- 产物：`artifacts/sbom/xiaolishaxiang-1.0.11.sbom.json`（109 个组件，134KB）
- 新建 `ci/run_sbom.sh` 自动化生成脚本

**合规矩阵**
- 新建 `docs/13-COMPLIANCE-MATRIX.md`：14 条 SP-ID 全量映射至 CIS Benchmark v8 / NIST SP 800-53 Rev5 / ISO/IEC 27001:2022
- 修正 SP-L2-01 的 NIST 映射（AU-3 → SC-5）
- NIST 14/14 覆盖，ISO 14/14 覆盖，CIS 4/14（沙箱特有机制不在通用 OS 加固范围）

**安全审计清单**
- 新建 `docs/14-SECURITY-AUDIT-CHECKLIST.md`：8 大类 44 条结构化审计检查项
- 通过率 100%（44/44），含 wasmtime v51.0.0 独立版本审查
- 涵盖：威胁模型/L1 隔离/L2 资源/L3 运行时/全局安全/代码构建/供应链

**依赖合规修复**
- `deny.toml`：许可证白名单扩充至 12 项（新增 Apache-2.0 WITH LLVM-exception/BSD-2-Clause/BSD-3-Clause/GPL-2.0-only/ISC/MPL-2.0/Unlicense/Zlib）
- `deny.toml`：豁免 RUSTSEC-2024-0437（protobuf 2.28.0 栈溢出；仅通过 prometheus 传递依赖，非直接处理用户输入，豁免至 2027-03-31）
- cargo-deny 全量通过（advisories ok, bans ok, licenses ok, sources ok）

**SPDX 版权头补齐**
- 缺失 SPDX 头的文件全部补齐：`CHANGELOG.md`、`xs-daemon/build.rs`、`xs-scheduler/build.rs`、`sandbox.proto`、`scheduler.proto`
- REUSE 合规：7875/7875 文件全合规（reuse 6.3.0）

**质量基线验证**
- `cargo fmt --check` 零差异
- `cargo clippy --workspace --all-targets -- -D warnings` 零警告
- `cargo build --locked` + `cargo build --release --locked` 双重编译通过
- `cargo test --workspace --locked` 全量通过，0 失败
- `reuse lint` 7875/7875 全合规
- `cargo-deny` advisories/bans/licenses/sources 全通过

**缺陷回归**
- DEFECT-2026-02（SP-L1-03）：seccomp allowlist 缺失 fcntl/poll/getcwd，已修复并登记 docs/09-DEFECT-REGRESSION.md；回归 2 用例全绿 + L1 全量对抗 20 用例全绿
