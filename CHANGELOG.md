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
