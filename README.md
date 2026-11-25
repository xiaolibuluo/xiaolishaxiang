<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->
# xiaolishaxiang（小黎沙箱）

Linux 专用三层隔离沙箱，Rust 实现，许可证 AGPL-3.0-only。当前版本 **1.0.11**。

## 功能

### 三层隔离架构

| 层 | 机制 | crate |
|---|---|---|
| L1 系统隔离 | namespace、seccomp allowlist（io_uring 默认关闭）、landlock、no_new_privs、ptrace 限制 | xs-l1-sys |
| L2 资源治理 | cgroup v2 真实委派、rlimit、令牌桶背压、独立配额审计通道 | xs-l2-res |
| L3 运行时隔离 | wasmtime 51 + capability 句柄表 | xs-l3-rt |

### 保证等级（运行时探测导出）

| 等级 | 条件 | 行为 |
|---|---|---|
| A | 内核 6.2+，landlock ABI v3+（含网络管控），cgroup v2 真实委派 | 完整防线 |
| A- | 内核 5.15~6.1 | 网络仅 netns 单防线 |
| B | landlock 缺失或 cgroup v2 不可委派 | 降级防线 |
| C | 低于最低条件 | 默认拒绝启动 |

min_assurance ∈ {A, A-, B}；低于门禁即拒启，fail-closed，禁止静默降级。

### 产品形态

- **库**：xs-api 编排（校验 → 探测 → 判定 → 建域）
- **CLI**：`xs-cli check <config.toml>`
- **Daemon**：xs-daemon，gRPC `0.0.0.0:50051` + HTTP `0.0.0.0:3000`；沙箱池 max_size 默认 128
- **Scheduler**：xs-scheduler，gRPC `0.0.0.0:50052`
- **gRPC 接口**：sandbox.proto 6 RPC、scheduler.proto 4 RPC

### workspace 组成（9 crates）

xs-core、xs-l1-sys、xs-l2-res、xs-l3-rt、xs-api、xs-cli、xs-daemon、xs-policy、xs-scheduler。

## 实测数据

### 测试

| 项 | 数据 |
|---|---|
| workspace 全量测试 | 36 套件全部通过、0 失败（`cargo test --workspace --locked`，干净 env 验证，2026-11-25） |
| 本机测试基线 | 172 用例全绿（内核 7.0.0-42 / Ubuntu 26.04.1，2026-11-24） |
| L1 对抗用例 | 20 用例全绿 |
| 混沌工程 | 6 类故障 9 用例全绿 |
| 缺陷回归用例 | 2 条登记在册（DEFECT-2026-01、DEFECT-2026-02），回归全绿 |

### fuzz

| 项 | 数据 |
|---|---|
| 60s 冒烟 | 656,896 runs / 0 crash / 0 ASan（nightly 1.102.0 + libfuzzer-sys + ASan，2026-11-25） |
| 语料 | fuzz_config_parse 语料库入库管理，2026-11-25 新增 805 条 |
| 长程 fuzz | systemd timer 每日 05:00 触发 |

### 性能（内核 7.0.0-42 裸 VM）

| 指标 | 实测 | 预算 |
|---|---|---|
| spawn 延迟（基线 vs 沙箱） | 0.589ms vs 1.403ms，增加 0.802~1.004ms | ≤2ms ✅ |
| 吞吐损失 | 56.9%~64.3% | ≤70% ✅ |

### 供应链与安全

| 项 | 数据 |
|---|---|
| REUSE 版权合规 | 7875/7875 文件全合规（reuse 6.3.0） |
| unsafe 审查 | xs-l1-sys 16 处 unsafe 全部 PASS；其余 crate `#![forbid(unsafe_code)]` |
| SBOM | CycloneDX，`artifacts/sbom/xiaolishaxiang-1.0.11.sbom.json`，109 组件 |
| cargo-vet | 265 个依赖全部登记（exempted 基线） |
| cargo-audit | 离线 advisory-db 1566 条，196 依赖，0 告警 |
| osv-scanner | 196 packages，0 issues |
| 安全审计清单 | 44 项，通过率 100% |
| 合规矩阵 | 14 条 SP-ID：NIST SP 800-53 14/14 映射、ISO/IEC 27001:2022 14/14 映射、CIS v8 4/14 直接映射 |
| 变异测试 | xs-core 59 mutants 覆盖率 58.3%（15 missed）；xs-l2-res 68 mutants 覆盖率 51.6%（30 missed） |

### 内核矩阵

| 内核 | 状态 |
|---|---|
| 7.0（本机观察位，landlock ABI 8） | ✅ 172 用例全绿 |
| 5.15 / 6.1 / 6.6 / 6.12 | ⏳ blocked_by_single_kernel |

## 环境约束

- 内核 ≥ 5.15（推荐 6.2+）；本机实测 7.0.0-42-generic / Ubuntu 26.04.1 / systemd 259 / landlock ABI 8
- Rust stable 1.100.0（rust-toolchain.toml 锁定）；nightly 1.102.0 仅用于 fuzz / Miri / TSan
- rootful supervisor 为唯一支持形态

## 文档索引

| 文档 | 内容 |
|---|---|
| docs/00-THREAT-MODEL.md | 威胁模型 |
| docs/01-SECURITY-PROPERTIES.md | 安全属性注册表（SP-ID） |
| docs/02-ASSURANCE-LEVELS.md | 保证等级 |
| docs/03-ARCHITECTURE.md | 架构 |
| docs/04-TEST-MATRIX.md | 测试矩阵 |
| docs/05-SUPPLY-CHAIN.md | 供应链 |
| docs/06-M0-SPIKE.md | M0 探针实测 |
| docs/07-UNSAFE-REVIEW.md | unsafe 审查清单 |
| docs/08-CVE-CORPUS.md | CVE 对抗语料登记 |
| docs/09-DEFECT-REGRESSION.md | 缺陷回归登记 |
| docs/10-KERNEL-MATRIX.md | 内核矩阵 |
| docs/11-CHAOS-ENGINEERING.md | 混沌工程 |
| docs/13-COMPLIANCE-MATRIX.md | 合规矩阵 |
| docs/14-SECURITY-AUDIT-CHECKLIST.md | 安全审计清单（44 项，通过率 100%） |

## 版权

AGPL-3.0-only。版权头由 REUSE 权威校验（ci/check_copyright.sh）。
