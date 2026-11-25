<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# xiaolishaxiang

万能通用三层隔离层沙箱（Linux 专用）。为不可信代码与外部工作负载提供纵深防御的统一隔离执行环境，以库（crate）+ CLI 双形态交付。

## 开源协议与传染性声明

本项目采用 AGPL-3.0-only 协议发布（见 LICENSE）。

> 网络传染性提示：AGPL 具有网络传染性。任何将 xiaolishaxiang 集成进网络服务（包括通过 SaaS 方式对外提供服务）的第三方，都必须以 AGPL-3.0 开源其服务源码。请在集成前确认你的业务模式可以接受该义务。

## 环境前提（务必先读）

| 项 | 要求 / 说明 |
|---|---|
| 操作系统 | 仅 Linux（Windows / macOS 不支持系统级隔离层 L1） |
| 最低内核 | 5.15（首个含 landlock 的 LTS；低于此版本 L1 不可用，沙箱按 fail-closed 拒绝启动） |
| 推荐内核 | 6.2 及以上（landlock ABI v3，网络维度纳入能力模型，可达保证等级 A） |
| 推荐部署形态 | 特权 supervisor（root 运行）+ 裸机 / VM。非特权模式依赖发行版的 unprivileged_userns_clone 策略，保证等级可能仅为 B，由运行时探测决定 |
| 容器 / K8s | 容器编排环境中 namespace 套娃不可用、seccomp 被上层锁定、cgroup 委派通常拿不到，三者同时成立时 L1 基本不可用，仅能提供 L3（WASM）。A / A- 级仅裸机 / VM 可达 |
| 信任天花板 | namespaces + seccomp 的信任上限是内核本身。对抗有决心攻击者的场景需要 VM/microVM 后端（未来扩展，非 v0.1 范围） |

## 三层隔离架构

| 层 | 名称 | 机制 |
|---|---|---|
| L1 | 系统隔离层 | namespace + seccomp（allowlist，io_uring 默认关闭）+ landlock + no_new_privs + ptrace 限制 + network namespace |
| L2 | 资源治理层 | cgroup v2 + rlimit + 令牌桶背压 |
| L3 | 运行时隔离层 | WASM 沙箱 + capability 句柄表 |

三层各自实现统一 trait，逐层收紧、可独立启用、可组合叠加；层间仅通过窄接口通信，单层失效不波及其他层。

## 保证等级（运行时探测导出，非静态承诺）

| 等级 | 条件 | 用途 |
|---|---|---|
| A | 内核 6.2+ 且 userns 可用 且 seccomp allowlist 生效 且 cgroup v2 真实可委派 | 完全不可信代码 |
| A- | 内核 5.15 至 6.1（landlock ABI 不高于 v2）+ 其余同 A | 完全不可信代码（网络隔离仅依赖 netns） |
| B | userns 可用但 landlock 缺失，或 cgroup v2 不可委派 | 仅半可信负载 |
| C | 容器内 / seccomp 无法收紧 / userns 被禁用 | 默认拒绝启动 |

调用方通过 capabilities() / assurance_level() 程序化获取探测后的有效等级；min_assurance 不满足时按 SP-G-01 fail-closed。

## 文档索引

| 文档 | 内容 |
|---|---|
| docs/00-THREAT-MODEL.md | 威胁模型：攻击者画像、TCB、不防清单 |
| docs/01-SECURITY-PROPERTIES.md | 安全属性规约（SP-ID 注册表，全部测试可追溯） |
| docs/02-ASSURANCE-LEVELS.md | 保证等级与运行时探测规则 |
| docs/03-ARCHITECTURE.md | 架构与代码组织、工程纪律 |
| docs/04-TEST-MATRIX.md | 四级测试矩阵门禁 |
| docs/05-SUPPLY-CHAIN.md | 供应链防护 |
| docs/06-M0-SPIKE.md | M0 技术探针计划与实测结果 |
| docs/07-UNSAFE-REVIEW.md | unsafe 审查清单（16 处全 PASS） |
| docs/08-CVE-CORPUS.md | CVE 对抗语料登记 |
| docs/09-DEFECT-REGRESSION.md | 缺陷回归用例集 |
| docs/10-KERNEL-MATRIX.md | 内核版本兼容矩阵 |
| docs/11-CHAOS-ENGINEERING.md | 混沌工程方案与用例 |
| docs/12-PLATFORM-ROADMAP.md | 平台化迭代路线图（P1~P6） |
| docs/13-COMPLIANCE-MATRIX.md | 合规矩阵（SP-ID → CIS/NIST/ISO 映射） |
| docs/14-SECURITY-AUDIT-CHECKLIST.md | 安全审计清单（44 项，通过率 97.7%） |

## 工具链

- 贡献者 / CI 环境：rust-toolchain.toml 锁定 1.100.0（含 clippy / rustfmt）。
- 库对外承诺的 MSRV：见 Cargo.toml 的 rust-version 字段，与 1.100.0 是两个不同概念，下游集成方无需安装 1.100.0。

## 版权

Copyright (C) 小黎的部落（www.qingdujian.com）。本项目的版权头任何人不得更改/删除，由 CI 第一道门禁（reuse 校验）强制保护。
