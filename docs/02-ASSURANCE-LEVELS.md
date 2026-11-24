<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 保证等级与运行时探测（Assurance Levels）

保证等级是运行时探测后导出的有效等级（effective level），不是按环境查表得到的静态承诺。
调用方通过 capabilities() / assurance_level() 程序化获取；探测结果低于 min_assurance 时按 SP-G-01 fail-closed。

## 1. 等级定义

| 等级 | 全部条件 | 隔离强度 | 适用负载 |
|---|---|---|---|
| A | 内核 6.2+（landlock ABI v3+）且 userns 可用且 seccomp allowlist 生效且 cgroup v2 真实可委派 | 文件与网络均纳入能力模型，完整三层隔离 | 完全不可信代码 |
| A- | 内核 5.15 至 6.1（landlock ABI v1/v2）+ 其余同 A | 文件隔离完整；网络隔离仅依赖 network namespace | 完全不可信代码（网络维度单防线） |
| B | userns 可用但 landlock 缺失，或 cgroup v2 不可委派 | 降级：明确缺失的维度不被保证 | 仅半可信负载 |
| C | 容器内 / 已有 seccomp 无法收紧 / unprivileged_userns_clone=0 | 无有效系统级隔离 | 默认拒绝启动 |

## 2. landlock ABI 分级

| 内核 | landlock ABI | 覆盖维度 |
|---|---|---|
| 5.15 | v1 | 仅文件系统 |
| 5.19 | v2 | 文件系统（语义增强） |
| 6.2 | v3 | 文件系统 + 网络 |
| 6.7 | v4 | 文件系统 + 网络 + IPC/socket |

capabilities() 必须返回 ABI 版本号，禁止只返回布尔『支持/不支持』。

## 3. 探测项与降级触发条件

| 探测项 | 探测方法 | 失败后果 |
|---|---|---|
| 内核版本 | uname 解析 | 低于 5.15 → L1 不可用，报 C |
| landlock | landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) 读取 ABI | ABI 为 0（缺失）→ 降至 B；ABI v1/v2 → 上限 A-；v3+ → 可评 A |
| user namespace | 实际 clone(CLONE_NEWUSER) 尝试 + 读取 /proc/sys/kernel/unprivileged_userns_clone | 不可用 → 报 C（除非 supervisor 为 root 走 setuid 路径，见第 5 节） |
| seccomp 可收紧性 | 检查当前进程是否已有不可移除的 filter（/proc/self/status Seccomp 字段与 PR_GET_SECCOMP） | 已有 lock 且与目标策略冲突 → 报 C |
| cgroup v2 委派 | 实际创建子 cgroup、cgroup.subtree_control 中 enable memory/cpu、写入 memory.max 并回读确认生效 | 任一环节失败 → L2 降级，整体上限 B |
| no_new_privs | PR_SET_NO_NEW_PRIVS 调用确认 | 失败 → fail-closed |
| yama ptrace_scope | 读 /proc/sys/kernel/yama/ptrace_scope 记录进审计（仅纵深参考，不计等级） | 不降级 |

## 4. 探测一致性原则（SP-G-02）

- 报告可用 = 实测通过。任何『理论上应该可用』的推断都不得进入 capabilities() 返回值。
- 『挂载了 cgroup2fs』不等于『可委派』：必须创建、enable 控制器、写入并回读。
- 『编译时启用了 landlock 头文件』不等于『运行时可用』：必须查 ABI 版本。

## 5. 特权与非特权部署形态

| 形态 | userns 依赖 | 定调 |
|---|---|---|
| 特权 supervisor（root） | 不依赖 unprivileged_userns_clone | 推荐部署形态，可稳定达到 A / A- |
| 非特权 supervisor | 依赖发行版策略（Debian/Ubuntu 部分版本默认关闭或限制） | 支持但保证等级由探测决定，可能仅为 B |

非特权模式是否作为正式支持形态：**M3 收口决策——不正式支持**。
A 级保证所需的多项基础能力（cgroup v2 真实委派的 subtree_control 写操作、
network namespace 创建、landlock restrict_self 全量生效）依赖 root 权限；
非特权路径的探测结果上限为 B 且发行版策略差异大（userns 可用性、landlock
非特权调用受限），投入产出不足以支撑 M3 发布质量。
M3 以 rootful supervisor 为唯一支持形态；非特权路径评估推迟到后续里程碑
单独评审，届时需提供发行版兼容矩阵与降级路径方案。

## 6. 容器环境

容器 / K8s Pod 中：namespace 套娃通常不可用、seccomp 被上层 profile 锁定、cgroup 委派拿不到，三者同时成立时探测报 C，仅 L3（WASM）可用。文档与 README 前置声明，不允许用户通过关闭 min_assurance 检查『强行跑起来』。

## 7. min_assurance 门禁

配置项 min_assurance ∈ {A, A-, B}（C 不可设为允许值）：

- 探测 effective 等级 < min_assurance → 拒绝启动（SP-G-01）；
- 禁止『降一级继续跑』的隐式行为；如确需降级运行，必须由部署方显式下调 min_assurance 并留下审计记录。

## 8. 与测试矩阵的联动

- 隔离有效性用例按 effective 等级筛选：等级不满足的用例结果为 not_applicable（由 capabilities() 推导，禁止手写 skip）；
- 发布门禁报告列出本环境未覆盖的 SP-ID 清单，与等级表自动对齐。
