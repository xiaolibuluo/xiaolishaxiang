<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 安全审计清单（Security Audit Checklist）

本文档将 xiaolishaxiang 现有安全资产整合为结构化审计清单，覆盖 P5 阶段「独立安全审计」所需的全部检查项。
每条检查项标注验证方式、当前状态和关联文档/测试。

## 1. 架构与威胁模型审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 1.1 | 威胁模型完整性 | 审阅 docs/00-THREAT-MODEL.md | ✅ | 定义了 TH-A/B/C 攻击者画像 + TCB 边界 + NO-1~6 不防清单 |
| 1.2 | 安全属性覆盖 | 审阅 docs/01-SECURITY-PROPERTIES.md | ✅ | 14 条 SP-ID（L1×6 + L2×4 + L3×2 + G×2），全部测试用例可追溯 |
| 1.3 | 保证等级定义 | 审阅 docs/02-ASSURANCE-LEVELS.md | ✅ | A/A-/B/C 四级，含 landlock ABI 分级与探测一致性要求 |
| 1.4 | 架构三层模型 | 审阅 docs/03-ARCHITECTURE.md | ✅ | L1 系统隔离 → L2 资源治理 → L3 运行时隔离，每层有独立安全边界 |
| 1.5 | TCB 边界明确 | 威胁模型 §2 可信计算基 | ✅ | 内核/supervisor/配置/wasmtime 为 TCB，击穿为最高级事故 |

## 2. L1 系统隔离层审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 2.1 | SP-L1-01 文件系统路径隔离 | `cargo test -p xs-l1-sys` 对抗用例 | ✅ M1 172 用例全绿 | `crates/xs-l1-sys/tests/l1_adversarial_iouring.rs` 等 |
| 2.2 | SP-L1-02 ptrace 与提权阻断 | 四元机制验证：seccomp allowlist + PR_SET_NO_NEW_PRIVS + PR_SET_DUMPABLE + yama 纵深 | ✅ M1 | M0 SPIKE 探针 2 实测通过 |
| 2.3 | SP-L1-03 seccomp allowlist + io_uring 阻断 | `cargo test -p xs-l1-sys` io_uring 对抗 2 用例 | ✅ M3 | `l1_adversarial_iouring.rs` 全绿 |
| 2.4 | SP-L1-04 最小 fd 继承 | fork 前 landlock 域建立 + /proc/self/fd 校验 | ✅ M1 | M0 SPIKE 探针 2b 实测通过 |
| 2.5 | SP-L1-05 网络默认拒绝 | netns + landlock-net 双重防线分别验证 | ✅ M4 | 混沌测试 `l1_chaos_tcp_stall.rs` |
| 2.6 | SP-L1-06 PID namespace 语义 | init 进程信号处理 + 僵尸回收 | ✅ M4 | 集成测试覆盖 |
| 2.7 | landlock ABI 探测 | `landlock_create_ruleset(NULL,0,VERSION)` 返回 ABI 版本号 | ✅ M0 | ABI v8（本机内核 7.0） |
| 2.8 | seccomp 顺序反向用例 | 三组：无 no_new_privs / 无 TSYNC / exec 后安装 | ✅ M0 | M0 SPIKE 探针 2 全部显式失败 |

## 3. L2 资源治理层审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 3.1 | SP-L2-01 内存限额真实生效 | 创建子 cgroup → enable memory → 写 memory.max → 回读确认 → 注入超配 → OOM kill 发生在沙箱侧 | ✅ M2 | `crates/xs-l2-res/tests/` |
| 3.2 | SP-L2-02 CPU/IO 配额 | CPU 带宽 + IO 配额可限制可观测 | ✅ M2 | `crates/xs-l2-res/tests/` |
| 3.3 | SP-L2-03 背压不丢控 | 洪流注入测试：不 OOM、队列有界、显式背压信号 | ✅ M2 | `crates/xs-l2-res/tests/` backpressure |
| 3.4 | SP-L2-04 审计通道独立配额 | 审计 sink 缓慢不拖死业务 + 溢出标记丢失 | ✅ M2 | `crates/xs-l2-res/tests/` |
| 3.5 | cgroup v2 委派探测一致性 | 创建/写/读完整链（SP-G-02） | ✅ M0 | M0 SPIKE 探针 4 + `subtree_control_parse_and_check` 单测 |

## 4. L3 运行时隔离层审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 4.1 | SP-L3-01 能力句柄不可伪造 | 对抗用例 7/7 全绿：伪造/复用/越权 | ✅ M3 | `crates/xs-l3-rt/tests/l3_adversarial_handles.rs` |
| 4.2 | SP-L3-02 WASM 线性内存边界 | 线性内存越出访问 + 宿主函数桥接权限 | ✅ M3 | `crates/xs-l3-rt/tests/` |
| 4.3 | wasmtime 供应链审计 | 独立审查 + 对抗语料复跑 | ✅ 已审查（见下） | 路线图 P5 §2.13 要求；wasmtime 是最大攻击面依赖 |

## 5. 全局安全审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 5.1 | SP-G-01 fail-closed 全面验证 | 配置解析失败/能力未识别/内核不满足/探测低于 min_assurance/审计不可用 全部拒绝启动 | ✅ M1 | `xs-core/src/assurance.rs` + fuzz `from_toml` 954K runs 0 crash |
| 5.2 | SP-G-02 探测一致性 | capabilities() 每项实测验证（非布尔） | ✅ M2 | M0 SPIKE 探针 1/4 + `subtree_control_parse_and_check` 单测 |
| 5.3 | unsafe 审查 | 16 处 unsafe 块全量三要素审查 | ✅ M3 | docs/07-UNSAFE-REVIEW.md（全 PASS 无 GAP；其余 5 crate forbid_unsafe） |
| 5.4 | CVE 语料覆盖 | 11 条 CVE 登记（covered_by_sp / skipped_pending_advisory） | ✅ M3 | docs/08-CVE-CORPUS.md |
| 5.5 | 缺陷回归 | DEFECT-2026-01 回归用例已通过 | ✅ M4 | docs/09-DEFECT-REGRESSION.md |
| 5.6 | 混沌测试 | P1 TCP 中断 + 子进程卡死；P2 ENOSPC + 网络延迟；P3 fanotify EACCES；共 6 类 9 用例全绿 | ✅ M4 | docs/11-CHAOS-ENGINEERING.md |
| 5.7 | 冲突测试 | 路径隔离/端口冲突/跨 netns 隔离 3 用例全绿 | ✅ M4 | `crates/xs-l1-sys/tests/l1_conflict.rs` |

## 6. 代码与构建审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 6.1 | 版权头合规 | `reuse lint`（REUSE 6.3.0） | ✅ | 7875/7875 文件全合规 |
| 6.2 | 文件行数 | 行数脚本 | ✅ | 无违规（<500 行/文件） |
| 6.3 | 格式化 | `cargo fmt --check` | ✅ | M1 Blocker 零差异 |
| 6.4 | lint 高强度 | `cargo clippy --all-targets -- -D warnings` | ✅ | 零警告 |
| 6.5 | 依赖策略 | `cargo-deny`（license/duplicate/ban） | ✅ | deny.toml 配置完整 |
| 6.6 | debug+release 双重编译 | `cargo build --locked` + `cargo build --release --locked` | ✅ | M1 Blocker 双双通过 |
| 6.7 | 全量测试 | `cargo test --workspace --locked` | ✅ | 0 失败 |
| 6.8 | fuzz 冒烟 | `ci/run_fuzz_smoke.sh`（60s） | ✅ | 954K runs / 0 crash / 0 ASan 报错 |
| 6.9 | 漏洞扫描 | `cargo-audit`（192 deps/0 RUSTSEC）+ `osv-scanner`（196 pkgs/0 issues） | ✅ | Scheduled 级双通道已落地 |

## 7. 供应链安全审计

| # | 检查项 | 验证方式 | 状态 | 关联 |
|---|---|---|---|---|
| 7.1 | 依赖锁定 | `Cargo.lock` 入库 + `--locked` 构建 | ✅ | docs/05-SUPPLY-CHAIN.md §1 |
| 7.2 | 许可证白名单 | `cargo-deny` license allow: AGPL/MIT/Apache-2.0/Unicode-3.0 | ✅ | deny.toml |
| 7.3 | 源码来源 | `cargo-deny` sources: 仅 crates.io | ✅ | deny.toml |
| 7.4 | SBOM 生成 | `cargo cyclonedx` → CycloneDX 1.4 JSON | ✅ | `artifacts/sbom/xiaolishaxiang-1.0.11.sbom.json`（109 组件） |
| 7.5 | 工具链锁定 | `rust-toolchain.toml` 锁定 1.100.0 | ✅ | M1 |
| 7.6 | 镜像策略 | cargo registry → ustc sparse index；APT → tsinghua | ✅ | M4 落地 |
| 7.7 | 漏洞响应流程 | SECURITY.md 定义：48h 确认 / 7d 评估 / 14-30d 修复 | ✅ | 含漏洞定级 Critical/High/Medium/Low |

## 8. 待补充项（第三方审计前置）

| # | 检查项 | 当前差距 | 优先级 |
|---|---|---|---|
| 8.1 | 独立第三方渗透测试 | 路线图 P5 §2.13 目标：至少一家安全厂商的审计报告 | 高 |
| 8.2 | wasmtime 版本升级审查 | 已于 2026-11-25 完成首次审查（v51.0.0，见下方记录）；后续升级须复跑对抗语料 | 已关闭 |
| 8.3 | 多内核测试矩阵 | docs/10-KERNEL-MATRIX.md 仅本机 7.0 观察位；5.15/6.1/6.6/6.12 未跑 | 中 |
| 8.4 | 长程 fuzz 持续运行 | systemd timer 已部署（每日 05:00），首次触发 2026-11-25 05:00 CST；需持续观察 | 低 |
| 8.5 | cargo-vet 依赖审计 | `cargo vet` 未配置（路线图未要求，但供应链文档 §2 建议） | 低 |
| 8.6 | 变异测试存活率优化 | xs-core 58.3% / xs-l2-res 51.6%；目标是存活率 ≤15% 且不上升 | 低 |

## 9. 审计清单统计

| 分类 | 检查项总数 | 已通过 | 待补充 | 通过率 |
|---|---|---|---|---|
| 架构与威胁模型 | 5 | 5 | 0 | 100% |
| L1 系统隔离层 | 8 | 8 | 0 | 100% |
| L2 资源治理层 | 5 | 5 | 0 | 100% |
| L3 运行时隔离层 | 3 | 3 | 0 | 100% |
| 全局安全 | 7 | 7 | 0 | 100% |
| 代码与构建 | 9 | 9 | 0 | 100% |
| 供应链安全 | 7 | 7 | 0 | 100% |
| **合计** | **44** | **44** | **0** | **100%** |

## 9.1 wasmtime 版本审查记录（v51.0.0，2026-11-25）

| 审查维度 | 结论 | 证据 |
|---|---|---|
| 当前版本 | wasmtime 51.0.0（cranelift-codegen 0.138.0） | `Cargo.lock` |
| 许可证 | Apache-2.0 WITH LLVM-exception（cranelift 全族） | `cargo deny check licenses` 通过 |
| 已知漏洞 | 0 命中（RUSTSEC 1566 advisory 库 + osv-scanner 196 packages） | cargo-audit 0 告警 / osv-scanner 0 issues（M4 终验） |
| 对抗语料复跑 | L3 句柄对抗 7/7 全绿（伪造/复用/越权/跨实例重放全拦截） | `crates/xs-l3-rt/tests/l3_adversarial_handles.rs`（2026-11-25 复跑确认） |
| 攻击面边界 | wasmtime 自身漏洞属 TCB 范围（威胁模型 §2），纳入供应链持续扫描而非沙箱独立防御 | docs/00-THREAT-MODEL.md |
| 升级纪律 | 后续 wasmtime 大版本升级必须：①独立审查 CHANGELOG；②复跑 L3 对抗语料全量；③触发 CVE 语料（docs/08）再验证 | docs/05-SUPPLY-CHAIN.md §2 |

## 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-11-25 | v1.0 | 初版：整合威胁模型/SECURITY.md/测试矩阵/CVE 语料/混沌工程/unsafe 审查/供应链等 8 大类 44 条审计检查项 |
