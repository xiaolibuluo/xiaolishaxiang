<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->
# M0 技术探针（Spike）

探针代码位于 spike/，为一次性验证代码，不进入 crates/。以下为关键内核机制的实测结果。

## 探针环境基线（实测采集）

| 项 | 实测值 | 含义 |
|---|---|---|
| 内核 | 7.0.0-42-generic | 高于 6.7，landlock ABI v8（实测），满足 A 级 |
| 发行版 | Ubuntu 26.04.1 LTS | 非特权 userns 受 AppArmor 策略限制（见探针 2a 注） |
| unprivileged_userns_clone | 1 | sysctl 层面开启，但叠加 apparmor_restrict_unprivileged_userns=1 |
| cgroup | cgroup2fs | v2 环境，真实委派能力已实测（探针 4 PASS） |
| 容器迹象 | 无 /.dockerenv | 裸 VM，符合 A / A- 可达前提 |
| yama ptrace_scope | 1 | 宿主侧纵深存在（不作为沙箱自身保证） |
| seccomp actions_avail | kill_process kill_thread trap errno user_notif trace log allow | 全部动作可用 |

## 探针 1：landlock 可用性与 ABI 版本

- 方法：调用 landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)（syscall 444）读取 ABI 版本号。
- 实测结果：PASS，返回 ABI = 8（内核 7.0）。
- 结论：capabilities() 的 landlock 探测必须返回 ABI 版本号（本机为 8），网络维度能力自 ABI v3（6.2）起可用，本机远超门槛。

## 探针 2：seccomp 顺序反向用例

验证『顺序错误必须显式失败』，三组反向用例实测结果：

| 用例 | 错误操作 | 期望 | 实测 |
|---|---|---|---|
| 2a | 非特权进程（uid=65534）未设 no_new_privs 加载 filter | 显式失败 | PASS（语义达成），错误码为 EACCES(13) 而非经典 EPERM(1) |
| 2b-1 | 多线程无 TSYNC 安装 filter | filter 仅作用于安装线程（检出风险） | PASS：安装线程被过滤、其他线程不受影响，证实无 TSYNC 的危险 |
| 2b-2 | 多线程加 TSYNC 安装 filter | 全部线程被过滤 | PASS：主线程与工作线程均被过滤 |
| 2c | filter 在 exec 之后补装 | 设计约束：必须在 exec 前安装，代码路径断言 | 代码路径断言覆盖 |

### 探针 2a 注（重要）

- 经典文档中非特权无 no_new_privs 加载 seccomp 返回 EPERM；本机（Ubuntu 26.04、内核 7.0、AppArmor 启用）实测返回 EACCES。
- 原因：Ubuntu 的 AppArmor 限制非特权程序（kernel.apparmor_restrict_unprivileged_userns=1、apparmor_restrict_unprivileged_unconfined=1），在 seccomp 检查前先行拒绝。
- 对规约的影响：『显式失败』目标达成（绝不允许静默成功），但 xs-l1-sys 的错误处理必须同时识别 EPERM 与 EACCES 作为『被拒绝』信号，并给出指向 no_new_privs / AppArmor 的明确错误信息。

## 探针 3：io_uring 阻断可行性

- 方法：安装不含 io_uring_setup 的 seccomp allowlist filter（io_uring_setup 返回 EPERM）后尝试调用。
- 实测结果：PASS，io_uring_setup 被 EPERM 阻断且进程存活。
- 结论：SP-L1-03 的『io_uring 默认关闭』可行；对抗用例原型固化于 spike/spike2.py。

## 探针 4：cgroup v2 真实委派探测

- 方法（完整链路）：创建子 cgroup -> cgroup.subtree_control 写入 +memory +cpu -> 子组写 memory.max=134217728 -> 回读确认。
- 实测结果：PASS，四步全部成功，回读值等于写入值。
- 结论：本环境 L2 可真实委派；SP-G-02 探测一致性用例的完整实现范式固化于 spike/spike1.py。

## 探针 5：最低内核 5.15 假设确认

- 实测结果：PASS。本机内核 7.0 远超门槛；landlock v1 随 5.15 LTS 进入，全部文档统一以 5.15 为最低内核。

## 探针总结论

本机（裸 VM、内核 7.0、Ubuntu 26.04）满足保证等级 A 的全部条件：landlock ABI 8、seccomp 全动作可用、io_uring 可阻断、cgroup v2 真实可委派、userns sysctl 开启。
