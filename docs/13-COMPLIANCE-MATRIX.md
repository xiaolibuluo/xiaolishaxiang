<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 合规矩阵（Compliance Matrix）

将全部 SP-ID（安全属性规约）映射至 CIS Benchmark、NIST SP 800-53、ISO/IEC 27001 三个标准体系。
本矩阵是 P5 阶段「安全加固与合规」的核心交付物，用于支持下游企业采购与合规评估。

## 映射总表

| SP-ID | 简述 | CIS Benchmark v8 | NIST SP 800-53 Rev5 | ISO/IEC 27001:2022 | 状态 |
|---|---|---|---|---|---|
| **L1 系统隔离层** | | | | | |
| SP-L1-01 | 文件系统路径隔离 | 1.6.1 (Ensure AppArmor is enabled) | AC-3 (Access Enforcement) | A.8.3 (A.9.4.2) | ✅ M1 |
| SP-L1-02 | ptrace 与提权阻断 | 5.4.2 (Ensure system accounts are secured) | AC-6 (Least Privilege) | A.8.2 (A.9.2.3) | ✅ M1 |
| SP-L1-03 | 系统调用默认拒绝与 io_uring 关闭 | —（无直接对应） | SI-3 (Malicious Code Protection) | A.8.7 (A.12.2.1) | ✅ M1 |
| SP-L1-04 | 最小 fd 继承 | 1.6.1 (AppArmor) | AC-3 (Access Enforcement) | A.8.3 (A.9.4.2) | ✅ M1 |
| SP-L1-05 | 网络默认拒绝 | 3.5.2.1 (Firewall Configuration) | SC-7 (Boundary Protection) | A.8.20 (A.13.1.1) | ✅ M4 |
| SP-L1-06 | PID namespace 语义 | — | SC-39 (Process Isolation) | A.8.1 (A.12.4.1) | ✅ M4 |
| **L2 资源治理层** | | | | | |
| SP-L2-01 | 内存限额真实生效 | 1.6.2 (Ensure SELinux is enabled) | SC-5 (Denial-of-Service Protection) | A.8.1 (A.12.4.1) | ✅ M2 |
| SP-L2-02 | CPU / IO 配额 | — | SC-5 (Denial-of-Service Protection) | A.8.1 (A.12.4.1) | ✅ M2 |
| SP-L2-03 | 背压不丢控 | — | SC-5 (Denial-of-Service Protection) | A.8.12 (A.12.4.3) | ✅ M2 |
| SP-L2-04 | 审计通道独立配额 | — | AU-4 (Audit Storage Capacity) | A.8.12 (A.12.4.3) | ✅ M2 |
| **L3 运行时隔离层** | | | | | |
| SP-L3-01 | 能力句柄不可伪造 | — | AC-3 (Access Enforcement) | A.8.3 (A.9.4.1) | ✅ M3 |
| SP-L3-02 | WASM 线性内存边界 | — | SC-39 (Process Isolation) | A.8.25 (A.14.2.8) | ✅ M3 |
| **全局** | | | | | |
| SP-G-01 | fail-closed | — | SA-11 (Developer Testing and Evaluation) | A.8.25 (A.14.2.8) | ✅ M1 |
| SP-G-02 | 探测一致性 | — | CM-8 (System Component Inventory) / SA-11 | A.8.25 (A.14.2.8) | ✅ M2 |

## 映射说明

### CIS Benchmark 映射

- CIS Benchmark v8 for Distribution Independent Linux（Level 1）
- SP-L1-01 / SP-L1-04 映射至 1.6.1：landlock 在功能上与 AppArmor 同属强制访问控制（MAC），路径隔离策略由内核 landlock LSM 强制执行，类比 AppArmor profile 约束
- SP-L1-02 映射至 5.4.2：ptrace 阻断与 no_new_privs 属于最小权限原则的系统账号加固范畴
- SP-L2-01 映射至 1.6.2：cgroup v2 资源限额是 MAC 框架中资源限制的延伸
- SP-L1-05 映射至 3.5.2.1：netns + landlock-net 双重防线构成主机防火墙语义
- 标记「—」表示 CIS Benchmark 中无直接对应的检查项（通常因为 CIS 面向通用 OS 加固，不覆盖沙箱特有机制如 seccomp allowlist、cgroup 委派、能力句柄等）

### NIST SP 800-53 Rev5 映射

- SP-L1-01/04 → AC-3：landlock 路径规则是访问控制的实现形态
- SP-L1-02 → AC-6：最小权限原则的明确实现
- SP-L1-03 → SI-3：恶意代码防护（seccomp allowlist 阻止任意系统调用，io_uring 阻断防止内核攻击面扩大）
- SP-L1-05 → SC-7：边界防护（netns 隔离 + landlock-net 拒绝）
- SP-L1-06 → SC-39：进程隔离（独立 PID namespace）
- SP-L2-01/02/03 → SC-5：资源治理直接对标 DoS 防护
- SP-L2-04 → AU-4：审计存储容量管理
- SP-L3-01 → AC-3：能力句柄的授权访问控制
- SP-L3-02 → SC-39：WASM 模块的进程级隔离
- SP-G-01 → SA-11：fail-closed 是开发者测试与评估的核心理念
- SP-G-02 → CM-8 / SA-11：探测一致性确保系统组件的真实能力与声称一致

### ISO/IEC 27001:2022 映射

括号内为旧版编号（ISO 27001:2013 Annex A），便于对照旧版合规清单。新标准遵循 Annex A 8.x 编号体系。

- SP-L1-01/04 → A.8.3：信息资产访问控制
- SP-L1-02 → A.8.2：特权访问权限
- SP-L1-03 → A.8.7：恶意软件防护
- SP-L1-05 → A.8.20：网络安全
- SP-L1-06 → A.8.1：用户终端设备（沙箱内进程的资源隔离）
- SP-L2-01/02 → A.8.1：运营规程与职责
- SP-L2-03/04 → A.8.12：容量管理
- SP-L3-01 → A.8.3：信息资产访问控制
- SP-L3-02/SP-G-01/SP-G-02 → A.8.25：开发生命周期安全

## 覆盖统计

| 标准 | 覆盖项 | 未映射项 | 覆盖说明 |
|---|---|---|---|
| CIS Benchmark v8 | 4/14 SP-ID 有直接映射 | 10 项无对应检查项 | 沙箱特有机制（seccomp/cgroup 委派/能力句柄）不在通用 OS 加固范围内 |
| NIST SP 800-53 Rev5 | 14/14 SP-ID 可映射 | 0 | 全部 SP-ID 有对应控制项 |
| ISO/IEC 27001:2022 | 14/14 SP-ID 可映射 | 0 | 全部 SP-ID 有对应控制项 |

## 合规验证证据

| SP-ID | 测试证据 | 文档证据 |
|---|---|---|
| SP-L1-01~06 | `crates/xs-l1-sys/tests/` 覆盖，M4 172 用例全绿 | docs/01-SECURITY-PROPERTIES.md, docs/08-CVE-CORPUS.md |
| SP-L2-01~04 | `crates/xs-l2-res/tests/` + 背压测试 | docs/04-TEST-MATRIX.md L2 行 |
| SP-L3-01~02 | `crates/xs-l3-rt/tests/` 7 用例对抗全绿 | docs/07-UNSAFE-REVIEW.md, docs/09-DEFECT-REGRESSION.md |
| SP-G-01 | fuzz 冒烟 954K runs 0 crash + from_toml 任意输入不 panic | docs/04-TEST-MATRIX.md, artifacts/fuzz/ |
| SP-G-02 | landlock ABI v8 / cgroup 真实委派 / seccomp TSYNC 全部实测通过 | docs/06-M0-SPIKE.md 探针 1/2/4 |

## 变更记录

| 日期 | 版本 | 变更 |
|---|---|---|
| 2026-11-25 | v1.0 | 初版：14 条 SP-ID 全量映射至 CIS/NIST/ISO；修正 SP-L2-01 的 NIST 映射（AU-3 → SC-5，与 DoS 防护语义一致）；补全缺失的 7 条映射 |
