# xiaolishaxiang 平台化迭代路线图

> 版本：1.0.5-dev → 3.0.0  
> 状态：P1 进行中  
> 关联：docs/00-THREAT-MODEL.md、docs/03-ARCHITECTURE.md、docs/04-TEST-MATRIX.md  

## 0. 总览

将 xiaolishaxiang 从单机 CLI 沙箱工具（~6,800 行 Rust）演进为：
- **v2.0**：单机多租户沙箱守护进程（Daemon + gRPC API + 沙箱池 + 可观测性）
- **v3.0**：集群级沙箱编排平台（Scheduler + K8s Operator + SDK 生态）

核心策略不变：**隔离原语复用内核**（namespace/cgroup v2/landlock/seccomp/fanotify），**L3 运行时复用 wasmtime**，代码量将保持在 25,000 行以内——远小于 gVisor（50 万行 Go）和 Firecracker（15 万行 Rust）。

---

## 1. 架构演进

### 1.1 当前（v1.0.5-dev）

```
┌──────────┐
│  xs-cli  │  one-shot CLI
└────┬─────┘
     │ SandboxBuilder::new() → build() → run()
     ▼
┌──────────┐
│  xs-api   │  编排层（配置校验、探测、建域）
└────┬─────┘
     │
     ▼
┌──────────────────────────────────────────┐
│  L1 (xs-l1-sys)  │  L2 (xs-l2-res)     │  L3 (xs-l3-rt)
│  ns/landlock/     │  cgroup v2 委派     │  wasmtime 51
│  seccomp/fanotify │  审计背压            │  句柄对抗
└──────────────────────────────────────────┘
```

### 1.2 v2.0 目标（单机多租户平台）

```
                         ┌─────────────────┐
                         │  gRPC / HTTP API │
                         │  (tonic + axum)  │
                         └────────┬────────┘
                                  │
                         ┌────────▼────────┐
                         │   xs-daemon      │  ← 新增 crate
                         │  (tokio actor)   │
                         └────────┬────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
     ┌──────▼──────┐     ┌───────▼───────┐     ┌───────▼───────┐
     │ Sandbox Pool │     │ Tenant Mgmt   │     │ Policy Engine  │
     │ (预热 N 域)  │     │ (配额/标识)   │     │ (TOML 热加载)  │
     └──────┬──────┘     └───────┬───────┘     └───────┬───────┘
            │                    │                     │
            └────────────────────┼─────────────────────┘
                                 │
                        ┌────────▼────────┐
                        │   Metrics/Log    │  ← 新增 crate
                        │ (Prometheus+tracing) │
                        └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │ 三层沙箱引擎    │  ← xs-l{1,2,3} 不变
                        └─────────────────┘
```

### 1.3 v3.0 目标（集群级平台）

```
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ Daemon-1 │   │ Daemon-2 │   │ Daemon-3 │
        └────┬─────┘   └────┬─────┘   └────┬─────┘
             └───────────────┼───────────────┘
                             │ gRPC
                    ┌────────▼────────┐
                    │  xs-scheduler   │  ← 新增 crate
                    │ (负载感知调度)  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  K8s Operator   │  ← 可选
                    │ (Sandbox CRD)   │
                    └─────────────────┘
```

---

## 2. 六阶段详细规划

### P1：平台内核 —— Daemon + gRPC + 沙箱池（4-6 周）

#### 2.1 新增 crate：`xs-daemon`

**文件结构**：
```
crates/xs-daemon/
├── Cargo.toml
├── src/
│   ├── lib.rs           # 公共类型与错误
│   ├── main.rs          # 入口：tokio + tonic server
│   ├── pool.rs          # SandboxPool：预热 N 个已建域 L1Domain
│   ├── lifecycle.rs     # 沙箱 TTL、最大命令数、空闲伸缩
│   └── metrics.rs       # Prometheus metrics（counter/histogram）
```

**依赖**：tokio、tonic、prost、axum、tracing-subscriber、prometheus

**沙箱池设计**：
- 预热策略：启动时 build() N 个 Sandbox（配置从 TOML 加载）
- 获取：`pool.acquire(tenant_id) -> SandboxHandle`
- 归还：handle.drop() 自动回收（带 TTL 重置）
- 池尺寸：min=4 / max=128 / idle_timeout=300s
- 冷启动延迟目标：从 1.6ms 降至 <200μs（取用已建域）

#### 2.2 gRPC API 定义

**proto/xiaolishaxiang/v1/sandbox.proto**：
```protobuf
service SandboxService {
  rpc CreateSandbox(CreateRequest) returns (CreateResponse);  // 新建沙箱
  rpc RunCommand(RunRequest) returns (RunResponse);           // 执行命令
  rpc RunCommandStream(stream RunRequest) returns (stream RunResponse);  // 流式
  rpc DestroySandbox(DestroyRequest) returns (DestroyResponse);  // 销毁
  rpc HealthCheck(HealthRequest) returns (HealthResponse);     // 健康检查
  rpc ListSandboxes(ListRequest) returns (ListResponse);       // 列出
}
```

**关键消息字段**：
- `CreateRequest`：tenant_id、config_toml（base64 或 inline）、ttl_secs、max_commands
- `RunResponse`：exit_code、stdout、stderr、sandbox_id、latency_us
- `HealthResponse`：pool_size、active_count、uptime_secs、latency_p50_us、latency_p99_us、rss_kb、version

#### 2.3 请求队列与优先级

- 基于 cgroup v2 backpressure（xs-l2-res 已有 TokenBucket/BoundedQueue）
- 排队模式：FIFO + 优先级（critical > normal > best_effort）
- 超时拒绝：队列等待 >5s 返回 RESOURCE_EXHAUSTED

#### 2.4 生命周期管理

- 每个沙箱实例：`created_at`、`expires_at`、`command_count`、`max_commands`
- 后台 GC goroutine：每 30s 扫描超期实例并 DestroySandbox
- 优雅关闭：SIGTERM → 拒绝新请求 → 等待运行中实例完成（最多 30s）→ SIGKILL

---

### P2：可观测性（2-3 周）

#### 2.5 Prometheus Metrics

| 指标名 | 类型 | 标签 | 说明 |
|---|---|---|---|
| `xs_sandbox_creates_total` | Counter | tenant_id, status | 沙箱创建总数 |
| `xs_sandbox_destroys_total` | Counter | tenant_id, reason | 销毁总数 |
| `xs_sandbox_active` | Gauge | tenant_id | 当前活跃数 |
| `xs_sandbox_pool_size` | Gauge | — | 池中可用数 |
| `xs_command_latency_seconds` | Histogram | tenant_id, cmd | 命令延迟分布 |
| `xs_command_errors_total` | Counter | tenant_id, error_type | 命令失败数 |
| `xs_seccomp_violations_total` | Counter | tenant_id, syscall | seccomp 拦截数 |
| `xs_rss_bytes` | Gauge | — | 守护进程内存 |

暴露端点：`GET /metrics`（text/plain Prometheus 格式）

#### 2.6 结构化日志与审计

- tracing 框架：spawn→info、command→debug、error→error
- 每个沙箱带 `sandbox_id` 和 `trace_id`
- 审计日志 JSONL：`audit.jsonl` 记录所有 Create/Run/Destroy 事件

#### 2.7 健康检查升级

三个端点（K8s probe 兼容）：
- `GET /health`：200 + `{"sandbox_ok": true, "latency_us": ...}`
- `GET /ready`：池可用 + 资源充足
- `GET /live`：进程存活

---

### P3：多租户与策略引擎（3-4 周）

#### 2.8 租户模型

```rust
struct TenantConfig {
    tenant_id: String,
    max_sandboxes: u32,          // 并发上限
    max_commands_per_sandbox: u64,
    allowed_assurance_levels: Vec<AssuranceLevel>,
    max_lifetime_secs: u64,
    quota: Option<ResourceQuota>,  // CPU/内存限制
    network_egress_allow: Vec<String>,  // CIDR 白名单
}
```

- 租户配置文件：`/etc/xiaolishaxiang/tenants/` 下按 `tenant_id.toml`
- inotify 热加载：修改配置无需重启

#### 2.9 策略引擎（xs-policy crate）

- 策略 TOML 格式：条件（capability/assurance_level/resource）+ 动作（allow/deny/log/alert）
- 预定义策略模板：CI 不受信构建、OJ 在线评测、AI Agent 沙箱
- 策略冲突检测：新策略加载时检查与现有策略冲突

#### 2.10 认证与授权

- gRPC interceptor：mTLS（x509 cert）或 Bearer Token
- 认证失败：UNAUTHENTICATED → 不建立任何连接
- 授权失败（配额超限）：RESOURCE_EXHAUSTED
- 策略拒绝：PERMISSION_DENIED + 审计日志

---

### P4：编排与调度（4-6 周）

#### 2.11 xs-scheduler（新增 crate）

- 中心调度器，通过 gRPC 与各 daemon 节点通信
- 调度算法：加权轮询 + 节点负载感知（CPU/内存/活跃沙箱数）
- 节点注册：daemon 启动时向 scheduler 注册（heartbeat 5s）
- 故障转移：超时未心跳（15s）自动摘除，在途请求重分配到健康节点

#### 2.12 K8s Operator（可选）

- CRD：`Sandbox` 自定义资源
- Controller：Reconcile 循环，将 CRD 映射到 scheduler 请求
- 优势：K8s 原生服务发现、滚动升级、HPA

---

### P5：安全加固与合规（2-4 周）

#### 2.13 独立安全审计

- 渗透测试：覆盖全部 SP-ID（docs/01-SECURITY-PROPERTIES.md）
- 代码审计：unsafe 块 + 关键路径（xs-l1-sys 域建立、xs-l3-rt 句柄校验）
- 目标：获得至少一家第三方安全厂商的审计报告

#### 2.14 SBOM 与漏洞管理

- `cargo cyclonedx` → CycloneDX SBOM
- `osv-scanner` + `cargo-audit` 纳入 CI Schedule
- SECURITY.md 补充：报告流程、CVE 分配、修复 SLA

#### 2.15 合规矩阵

| SP-ID | CIS Benchmark | NIST SP 800-53 | ISO 27001 |
|---|---|---|---|
| SP-L1-01 | 1.6.1 (AppArmor) | AC-3 (Access Enforcement) | A.9.4.2 |
| SP-L1-02 | 5.4.2 (User Privs) | AC-6 (Least Privilege) | A.9.2.3 |
| SP-L1-03 | — | SI-3 (Malicious Code Protection) | A.12.2.1 |
| SP-L2-01 | 1.6.2 (SELinux) | AU-3 (Content of Audit Records) | A.12.4.1 |
| SP-L2-04 | — | AU-4 (Audit Storage Capacity) | A.12.4.3 |
| SP-L3-01 | — | AC-3 (Access Enforcement) | A.9.4.1 |
| SP-G-01 | — | SA-11 (Developer Testing) | A.14.2.8 |

---

### P6：SDK 与生态（3-4 周）

#### 2.16 多语言 SDK

| 语言 | 特性 | 交付物 |
|---|---|---|
| Python | pip install xiaolishaxiang-client | gRPC 封装 + async/await |
| Go | go get github.com/xiaolishaxiang/client-go | gRPC 封装 + context |
| JavaScript/TypeScript | npm install @xiaolishaxiang/client | gRPC-web / REST |

#### 2.17 OpenAPI 文档

- protobuf → grpc-gateway → OpenAPI v3
- Swagger UI 集成到 daemon HTTP 端口
- 交互式 API 浏览器

#### 2.18 集成示例

| 场景 | 说明 | 目录 |
|---|---|---|
| CI/CD 不受信构建 | GitHub Actions runner 安全执行 `make` | examples/ci-build/ |
| OJ 在线评测 | 隔离执行用户提交代码，防止逃逸 | examples/oj-judge/ |
| AI Agent 沙箱 | 执行 LLM 生成的命令/代码 | examples/ai-sandbox/ |
| 远程开发环境 | per-user 隔离的开发容器 | examples/dev-env/ |

#### 2.19 插件系统

- wasmtime 层自定义 host function 注册
- 审计回调：每个命令执行前后触发 wasm 回调
- 文件系统钩子：在 landlock 授权前运行插件判定

---

## 3. 里程碑与时间线

```
v1.0.5-dev (当前)     2026-11-25
    │
    ▼
v2.0.0-alpha.1         2026-12-09   P1 完成（Daemon + gRPC + 沙箱池）
v2.0.0-alpha.2         2026-12-23   P2 完成（Metrics + 日志 + 审计）
v2.0.0-beta.1          2027-01-13   P3 完成（多租户 + 策略引擎）
    │
v2.0.0                 2027-01-27   ★ 单机多租户平台正式发布
    │
v3.0.0-alpha.1         2027-02-24   P4 完成（Scheduler + K8s Operator）
v3.0.0-alpha.2         2027-03-17   P5 完成（安全审计 + SBOM + 合规）
v3.0.0-beta.1          2027-04-07   P6 完成（SDK + 文档 + 示例）
    │
v3.0.0                 2027-04-21   ★ 集群级沙箱平台正式发布
```

总工期约 18-22 周（4.5-5.5 个月），全量可并行阶段（P2/P3 与 P1 尾段、P5 与 P4 尾段）可压缩至 16 周。

---

## 4. 风险矩阵

| 风险 | 可能性 | 影响 | 缓解措施 |
|---|---|---|---|
| gRPC 引入增加沙箱 TC 复杂度 | 中 | 高 | proto 严格禁止 unsafe；服务端与沙箱在不同进程 |
| 沙箱池池化导致隔离域复用（信息泄露） | 低 | 极高 | 每个 SandboxHandle 取用后重新建立域（而非复用旧域） |
| 多租户配置语法错误导致权限放大 | 中 | 极高 | 策略 TOML 单元测试全覆盖；加载前 dry-run |
| wasmtime 大版本升级引入 CVE | 中 | 高 | P5 持续集成 cargo-audit + osv-scanner；sandbox CVSS≥7 自动阻断发布 |
| K8s Operator 增加运维复杂度 | 高 | 中 | Operator 为可选路径，Daemon + Scheduler 可直接运行 |

---

## 5. P1 首步实施规范

### 5.1 本次改动范围

1. 新建 `crates/xs-daemon/`（Cargo.toml + 依赖）
2. 新建 `proto/xiaolishaxiang/v1/sandbox.proto`（gRPC 服务定义）
3. xs-daemon/src/main.rs（tonic server 脚手架 + health gRPC 实现）
4. xs-daemon/src/pool.rs（SandboxPool 结构体 + 预热逻辑）
5. 根 Cargo.toml workspace.members 添加 `crates/xs-daemon`
6. 版本升版 1.0.5-dev → 1.0.6-dev

### 5.2 验收标准

- `cargo check -p xs-daemon` 通过
- `cargo fmt` + `cargo clippy -- -D warnings` 通过
- `protoc` 生成的 Rust 代码可编译
- 沙箱池逻辑单元测试（mock L1Domain）覆盖

### 5.3 文件变更清单

| 文件 | 操作 | 行数估计 |
|---|---|---|
| `crates/xs-daemon/Cargo.toml` | 新建 | 25 |
| `crates/xs-daemon/src/main.rs` | 新建 | 80 |
| `crates/xs-daemon/src/lib.rs` | 新建 | 30 |
| `crates/xs-daemon/src/pool.rs` | 新建 | 120 |
| `proto/xiaolishaxiang/v1/sandbox.proto` | 新建 | 60 |
| `Cargo.toml`（根） | 修改 | +1 行（members） |
| `docs/12-PLATFORM-ROADMAP.md` | 新建 | 本文档 |
