<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->
# 测试矩阵（四级门禁）

全部测试项分为四级。任何用例必须声明验证的 SP-ID；跨内核环境跑同一套用例时区分 pass / fail / not_applicable 三种结果，not_applicable 必须由 capabilities() 推导，禁止手写 skip。

## 第 1 级：Blocker（任何 PR 必过，失败即阻断）

| 门禁项 | 工具 / 手段 | 通过标准 |
|---|---|---|
| 版权头扫描 | reuse lint（ci/check_copyright.sh 调用 reuse lint 做 SPDX/规范合规检查 + 版权持有者行检查『小黎的部落』；REUSE.toml 全局配置；LICENSES/AGPL-3.0-only.txt 落盘） | 全部文件含 SPDX 与版权行；当前基线 reuse 6.3.0，7875/7875 文件全合规 |
| 文件行数扫描 | ci/check_file_length.sh | 不超过 500 行，或含带理由的显式豁免标记 |
| 格式化 | cargo fmt --check | 零差异 |
| lint 高强度 | cargo clippy --all-targets -- -D warnings（含 pedantic） | 零警告 |
| 依赖策略 | cargo-deny（license / duplicate / ban） | 全部通过 |
| debug+release 双重编译 | cargo build 与 cargo build --release（均 --locked） | 双双成功零警告 |
| debug+release 运行测试 | 两种 profile 下 cargo test --locked | 双双全绿 |
| 单元测试 | cargo test（lib 内） | 100% 通过 |
| 集成测试 | tests/ 端到端场景 | 100% 通过 |

当前基线：workspace 36 个测试套件全部通过、0 失败（`cargo test --workspace --locked`，2026-11-25）。

## 第 2 级：Required（激活后 PR 必过）

| 门禁项 | 工具 / 手段 | 通过标准 | 当前状态 |
|---|---|---|---|
| 并发模型检查 | loom（仅受控原子/锁/通道子集） | 无死锁、无违反不变量 | 已激活 |
| 数据竞争检查 | TSan（nightly 辅助通道） | 无数据竞争 | 已激活 |
| 隔离有效性用例 | SP-L1-01/02/04/05/06 场景集（路径穿越、ptrace/提权、fd 继承、网络默认拒绝、PID ns init 语义） | 全部按 SP-ID 通过 | 已激活 |
| 能力探测一致性 | SP-G-02（landlock ABI / cgroup 真实委派 / seccomp TSYNC）；cgroup 委派探测在写入 +memory +cpu 后回读 cgroup.subtree_control 确认 enable 真实生效（API：subtree_controllers / controller_enabled_in_subtree，xs-l2-res/src/cgroup.rs） | 报告可用项全部实测通过 | 已激活 |
| seccomp 顺序反向用例 | no_new_privs 缺失 / 无 TSYNC / exec 后安装 三组 | 全部显式失败（禁止静默降级） | 已激活 |
| 审计背压用例 | SP-L2-04 审计通道独立配额 | sink 缓慢不拖死业务，溢出标记丢失 | 已激活 |
| 背压测试 | SP-L2-03 洪流注入 | 不丢控、不 OOM、队列有界 | 已激活 |
| 容错测试 | 错误注入后降级与重试 | 按策略降级 | 已激活 |
| 崩溃测试 | panic / abort 注入与恢复 | 沙箱边界不被击穿、可恢复 | 已激活 |
| 对抗逃逸语料 | CVE PoC 回归 + io_uring 阻断用例 + 句柄伪造/复用/越权 | 全部拦截；PoC 不可获得时标记 skipped_pending_advisory，连续 14 天未处理升级为发布阻断（N=14） | 已激活：io_uring 2 用例（crates/xs-l1-sys/tests/l1_adversarial_iouring.rs）、句柄对抗 7 用例（crates/xs-l3-rt/tests/l3_adversarial_handles.rs）全绿；CVE 登记 docs/08-CVE-CORPUS.md |
| fuzz 冒烟 | cargo-fuzz 短程（ci/run_fuzz_smoke.sh，目标 crates/xs-core/fuzz，SP-G-01：from_toml 任意输入不 panic、Ok 必须过 validate() 复检） | 无崩溃 | 已激活，实测见第 5 节 |
| unsafe 审查清单 | 人工核查每条 unsafe 的安全论证注释 | 全覆盖 | 已激活：docs/07-UNSAFE-REVIEW.md 登记 xs-l1-sys 全部 16 处 unsafe 块，三要素齐备全 PASS；零 unsafe fn/impl；其余 crate 由 forbid(unsafe_code) 编译期兜底 |
| 冲突测试 | 资源争用 / 端口与路径冲突场景（crates/xs-l1-sys/tests/l1_conflict.rs：路径授权隔离 / 同 netns 端口冲突 EADDRINUSE / 跨 netns 端口隔离） | 隔离正确、无串扰 | 已激活：3 用例全绿 |
| 缺陷回归 | 历史缺陷用例集（登记表 docs/09-DEFECT-REGRESSION.md） | 全部通过 | 已激活：2 条登记（DEFECT-2026-01、DEFECT-2026-02），回归用例全绿 |

## 第 3 级：Scheduled（定时任务，不阻断 PR，阻断发布）

| 门禁项 | 工具 / 手段 | 通过标准 | 当前状态 |
|---|---|---|---|
| 长程 fuzz | cargo-fuzz 定时长任务（systemd timer 每日 05:00；ci/systemd/xiaolishaxiang-fuzz.{service,timer}，产物落 artifacts/fuzz/） | 无崩溃、无异常新语料 | 已部署 enable |
| soak 持久稳定 | systemd timer 每日 03:00（ci/systemd/xiaolishaxiang-soak.{service,timer} + ci/run_soak.sh + crates/xs-l1-sys/examples/soak_probe.rs），≥24h | 无泄漏（supervisor RSS 增长 ≤ 10%）、无性能漂移（spawn 延迟中位数漂移 ≤ 15%）、0 失败迭代，verdict 判定文件落 artifacts/soak/ | 已部署 enable |
| 变异测试 | cargo-mutants，作用域限定 xs-core + xs-l2-res 纯逻辑 | 存活率不超过 15% 且不得较基线上升 | 实测见第 5 节 |
| 性能基线 | criterion，主判据为指令数/分配数等确定性指标；墙上时钟阈值 10~15% 且标注人工复核 | 回归不超阈值；隔离开销在预算内（吞吐损失 ≤ 70%、单次调用延迟增加 ≤ 2ms） | 实测见第 5 节 |
| ASan | nightly 辅助通道 | 无内存错误报告 | 已激活 |
| 漏洞扫描 | cargo-audit + osv-scanner，带过期日期的豁免清单 | 无未豁免已知漏洞 | 实测见第 5 节 |
| 内核版本矩阵 | 5.15 / 6.1 / 6.6 / 6.12（本机 7.0 作为附加观察位） | 各内核上按 SP-ID 全绿或 not_applicable 有正当推导 | 登记 docs/10-KERNEL-MATRIX.md |
| 混沌测试 | 故障注入（IO 失败、时钟跳变、网络抖动），方案文档 docs/11-CHAOS-ENGINEERING.md | 行为符合规约 | 6 类 9 用例全绿 |

## 第 4 级：Advisory（只报趋势不判成败）

| 项 | 工具 | 说明 |
|---|---|---|
| 突变体存活率趋势 | cargo-mutants 报告 | 长期趋势观察 |
| 新增代码覆盖率 | cargo-llvm-cov | 不设全局百分比硬门禁（平台分支大量不可达） |
| benchmark 波动 | criterion 历史 | 趋势告警，不判 fail |

## 5. 实测数据基线

### fuzz（nightly 1.102.0 + libfuzzer-sys + ASan）

| 项 | 数据 |
|---|---|
| 60s 冒烟 | 656,896 runs / 0 崩溃 / 0 ASan 报错（2026-11-25） |
| 语料库 | fuzz_config_parse 语料入库管理，2026-11-25 新增 805 条；字典 crates/xs-core/fuzz/dictionaries/fuzz_config_parse.dict |

### 性能（内核 7.0.0-42 裸 VM，测量工具 crates/xs-l1-sys/examples/overhead_probe.rs）

| 指标 | 实测 | 预算 |
|---|---|---|
| spawn 全链路中位数 | 基线 0.589ms / 沙箱 1.403ms | — |
| 延迟增加（三次复测） | 0.802~1.004ms | ≤2ms ✅ |
| 吞吐损失（三次复测） | 56.9%~64.3% | ≤70% ✅ |

### 变异测试（cargo-mutants，2026-11-24 双基线）

| crate | mutants | missed / caught / unviable | 覆盖率 | missed 分布 |
|---|---|---|---|---|
| xs-core | 59 | 15 / 21 / 23 | 58.3% | probe.rs（9）、assurance.rs（4）、capability.rs（2）、error.rs（1） |
| xs-l2-res | 68 | 30 / 32 / 6 | 51.6% | backpressure.rs（TokenBucket/BoundedQueue/AuditChannel 边界）、cgroup.rs（控制器探测/委派） |

### 漏洞扫描（2026-11-24 终验）

| 通道 | 版本 | 数据 |
|---|---|---|
| cargo-audit | 0.22.2（--no-fetch 离线模式） | 1566 advisory / 196 依赖 / 0 RUSTSEC 告警 |
| osv-scanner | v1.9.2 | 196 packages / 0 issues |

cargo-audit 在线 git fetch 受网络限制（blocked_by_git_protocol），离线本地 advisory-db 支撑 Scheduled 门禁。

### 整机测试

| 项 | 数据 |
|---|---|
| workspace 全量 | 36 套件全过 / 0 失败（2026-11-25） |
| 本机基线 | 172 用例全绿（内核 7.0.0-42 / Ubuntu 26.04.1，2026-11-24） |
| L1 全量对抗 | 20 用例全绿 |
| 混沌工程 | 6 类故障 9 用例全绿（docs/11-CHAOS-ENGINEERING.md） |

## 补充规约

1. 动态检查适用范围写实：Miri 仅作用于 xs-core / xs-l2-res 纯 Rust 逻辑（L1 的 libc/FFI 不在 Miri 覆盖范围，必要处 #[cfg(miri)] 打桩）；loom 不作为 OS 级隔离正确性依据；TSan 先于 ASan。
2. 发布门禁统计必须显式列出本环境未覆盖的 SP-ID 清单，与保证等级表自动对齐。
3. 兼容矩阵 PR 阶段只跑当前环境，完整内核矩阵在 Scheduled / 发布门禁执行。
4. CI/CD 检查：流水线自身 dry-run 校验与门禁脚本自测，随 Blocker 一并上线。
5. fuzz 运行载体：fuzz crate 为独立 workspace（crates/xs-core/fuzz 自带空 [workspace] 表），不进主 workspace 编译；冒烟门禁统一经 ci/run_fuzz_smoke.sh 触发，默认 60s 可用 XS_FUZZ_DURATION_SECS 覆盖，crash/oom/timeout 产物非空即判 fail。
6. systemd timer PATH 注意事项：systemd 默认 PATH 不含 ~/.cargo/bin（rustup/cargo）与 ~/.local/bin（reuse 等 venv 工具）。所有 systemd service 单元（soak/fuzz）必须显式设置 Environment=PATH=/root/.cargo/bin:/root/.local/bin:...；脚本首行注入 export PATH 双重兜底；HOME 按 EUID 兜底（getent passwd），避免 systemd 环境 HOME 未绑定崩溃。
7. 镜像策略：(a) cargo registry → ustc sparse index（~/.cargo/config.toml）；(b) APT → tsinghua mirror；(c) GitHub git clone 端点和 GitHub advisory-db 端点在当前网络后不可达——cargo-audit 走离线本地 advisory-db，cargo-mutants 走 cargo registry 安装免 git clone；(d) rustup 安装/更新走腾讯云镜像（RUSTUP_DIST_SERVER / RUSTUP_UPDATE_ROOT）。
