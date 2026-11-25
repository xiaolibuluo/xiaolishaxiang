<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 缺陷回归用例集（M4 Required 门禁）

依据 docs/04-TEST-MATRIX.md 第 2 级『缺陷回归：历史缺陷用例集，全部通过』。

## 登记规则

1. 每个已修复缺陷必须在此登记，包含：编号、发现里程碑、SP-ID、缺陷摘要、修复提交/变更 ID、回归用例位置、验证状态。
2. 回归用例必须在对应的 crate tests/ 中落地为断言型测试（禁止仅靠文档声明，必须可自动执行）。
3. 回归用例跑全量时需在 Blocker 第 7 步（双模式测试）中触发；新增缺陷修后立即登记，缺失即判 fail。
4. 编号格式：`DEFECT-YYYY-NN`（发现年份-序号）。

## 回归登记表

| 编号 | 发现里程碑 | SP-ID | 缺陷摘要 | 修复变更 ID | 回归用例位置 | 验证状态 |
|---|---|---|---|---|---|---|
| DEFECT-2026-01 | M3 | SP-L3-01 | 能力句柄范围校验使用朴素 starts_with，允许 `/data/../etc/passwd` 路径穿越与 `/database` 前缀混淆两类对抗输入被误放行（fail-open），违反 fail-closed 规约 | file-change-d21d566d-aebb-4f17-9c41-308be1ea854d（handle.rs check_use 加固） | crates/xs-l3-rt/tests/l3_adversarial_handles.rs（sp_l3_01_scope_traversal_rejected / sp_l3_01_scope_prefix_confusion_rejected / sp_l3_01_scope_escape_rejected） | ✅ 7/7 用例全绿，已入 Blocker 门禁 |
| DEFECT-2026-02 | P5 深度打磨 | SP-L1-03 | seccomp allowlist 缺失 fcntl/poll/getcwd：Ubuntu coreutils 经 libselinux 启动期调用 fcntl(0/1/2, F_GETFD) 与 poll(stdin/out/err, events=0) 检查 fd 状态，被默认 ERRNO(EPERM) 拒绝后进程自触发 SIGABRT（/bin/echo exec 成功即 abort）；/bin/sh 启动期 getcwd() 被拒产生警告噪音。属策略缺陷而非代码逻辑缺陷——隔离强度未受影响但『可运行常规命令』的产品承诺不成立 | file-change-1f7bef8f（filter.rs 补 fcntl/poll）+ file-change-ff16f5ae（补 getcwd） | crates/xs-l1-sys/tests/fault_crash.rs（defect_2026_02_dynamically_linked_binary_runs_without_sigabrt / defect_2026_02_sh_startup_no_getcwd_warning） | ✅ 2 用例全绿 + L1 全量对抗 20 用例全绿（io_uring 阻断/ptrace 阻断/网络双防线/路径隔离无回归） |

## 维护纪律

1. **修后登记时效**：缺陷修复 PR 合并后 24 小时内必须登记，否则 review 判 fail。
2. **不可回退**：已登记的回归用例不得以任何理由删除或 skip；如测试因环境不适用需 not_applicable，必须由 capabilities() 推导（禁手写），且指向本表编号编写 why-not-applicable 论证注释。
3. **年度审计**：每年 01-01 审查回归表完整性，缺失的缺陷（git log 中有 fix/CVE 关键字但未登记）补齐并补充用例。

## 与 CVE 登记的关系

- CVE PoC 回归语料登记在 docs/08-CVE-CORPUS.md（外部已知漏洞的覆盖与豁免），本表登记在开发/测试/对抗过程中发现的**自主缺陷**（内部引入的 bug），两者互补。
- 对抗语料驱动发现的缺陷（如 DEFECT-2026-01）同时出现在两表中：08-CVE-CORPUS.md 记录其作为对抗语料的发现过程，本表记录其作为缺陷回归的修复与验证。
