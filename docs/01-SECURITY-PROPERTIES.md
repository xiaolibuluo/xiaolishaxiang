<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 安全属性规约（SP-ID 注册表）

每条安全属性具有唯一 SP-ID。全部测试用例、对抗用例、隔离有效性用例必须声明其所验证的 SP-ID；发布门禁报告按 SP-ID 统计覆盖与未覆盖清单。

## L1 系统隔离层

### SP-L1-01 文件系统路径隔离

沙箱内进程无法读写宿主机未授权路径，覆盖：

- 符号链接穿越（指向沙箱外的 symlink）；
- .. 相对路径穿越；
- /proc、/sys、/dev 下的宿主敏感入口；
- 通过 rename / link 跨授权边界的移动。

机理声明：路径隔离完全依赖 landlock。seccomp 无法过滤 openat 的路径参数（只能拿到指针值），不得将 seccomp 视为文件隔离手段。

### SP-L1-02 ptrace 与提权阻断

沙箱内进程无法 ptrace supervisor 及宿主其他进程，无法获取 setuid 能力与任何 CAP_*。

机制落点（M0 定调，M1 实现与对抗用例均以此为准）：

1. seccomp allowlist 默认不包含 ptrace 与 process_vm_readv / process_vm_writev；
2. PR_SET_NO_NEW_PRIVS=1 阻断 setuid 与 file capability 提权；
3. PR_SET_DUMPABLE=0 使进程不可被同 uid 的 yama scope 1 附加；
4. yama（kernel.yama.ptrace_scope）作为宿主侧纵深防御由 supervisor 启动时检测并记录，不作为沙箱自身保证（裸 VM 默认值为 1 时仅作纵深，值为 0 时前三条仍独立成立）。

### SP-L1-03 系统调用默认拒绝与 io_uring 关闭

- seccomp 采用 allowlist 模式：未列出的 syscall 默认拒绝，禁止 denylist；
- io_uring_setup / io_uring_enter / io_uring_register 默认不在 allowlist（io_uring 默认关闭），作为显式配置项存在，开启需在配置中声明并接受文档警示；
- 内核版本升级触发 syscall 清单漂移审查：新内核引入的 syscall 必须经人工确认后方可加入 allowlist。
- 安装被拒的识别（M0 Spike 实测）：seccomp 安装被拒绝时错误码可能是 EPERM 或 EACCES（Ubuntu 的 AppArmor 限制非特权程序时返回 EACCES）。xs-l1-sys 必须将两者都识别为『被拒绝』，并报出指向 no_new_privs / AppArmor 的明确错误信息；任何错误码都不得被解释为静默成功。

### SP-L1-04 最小 fd 继承

landlock 只约束『未来』操作，不约束已打开的 fd 与已建立的连接，且规则只收紧不放宽。因此：

- supervisor 必须在 fork 子进程之前、且自身持有最小 fd 集的状态下建立 landlock 域；
- 子进程不得继承任何未授权 fd（启动前枚举 /proc/self/fd 校验白名单）。

用例语义：防的是父进程继承下去的 fd，不是防沙箱内自开 fd（自开由 SP-L1-01 的 landlock 域约束）。

### SP-L1-05 网络默认拒绝

- 网络隔离由 network namespace（CLONE_NEWNET，建命名空间但不配 veth 即无网络）保证；landlock 自 ABI v3（内核 6.2）起叠加网络维度；
- 默认拒绝全部出向与入向连接，按能力放行需显式声明；
- DNS 绕过尝试（直接向 53 端口发包、利用允许的目标做 DNS 隧道）纳入对抗用例；
- A 级（内核 6.2+）下 netns 与 landlock-net 两道防线必须分别验证：单独关闭 netns 时 landlock-net 仍能拦截，单独关闭 landlock-net 时 netns 仍能拦截；禁止只验证联合结果导致其中一道从未真正被触发。

### SP-L1-06 PID namespace 语义

- 沙箱运行于独立 PID namespace，其内 init（PID 1）语义正确：信号处理、子进程回收符合规范；
- 僵尸进程必须被回收，不得积累拖垮 PID 配额。

## L2 资源治理层

### SP-L2-01 内存限额真实生效

内存超限触发沙箱内 OOM kill，不得拖垮宿主。验证方式：在真实委派的子 cgroup 中写入 memory.max 并回读确认生效，再注入超配负载观察 OOM kill 发生在沙箱侧。

### SP-L2-02 CPU / IO 配额

CPU 带宽与 IO 配额在沙箱维度可限制、可观测；超额时按背压策略排队或拒绝，不允许静默超限。

### SP-L2-03 背压不丢控

洪流注入下：不丢控、不 OOM、队列有界；触发限流时调用方收到显式背压信号而非静默阻塞。

### SP-L2-04 审计通道独立配额

审计写入独立于业务背压：审计 sink 缓慢不得阻塞沙箱内进程释放资源（防死锁环）；审计缓冲溢出时的降级行为是『标记事件丢失』而非静默丢弃。

## L3 运行时隔离层

### SP-L3-01 能力句柄不可伪造

能力句柄的伪造、复用（跨会话/跨实例重放）、越权使用（超出授权范围调用）必须失败并产生审计事件。

### SP-L3-02 WASM 线性内存边界

WASM 模块无法越出线性内存读写宿主或其他实例内存；宿主函数桥接不放大权限。

## 全局

### SP-G-01 fail-closed

以下任一情况必须拒绝启动 / 拒绝执行，禁止降级放行：

- 配置解析失败或配置项无法识别；
- 请求的能力未在策略中声明；
- 内核特性不满足（内核低于 5.15、landlock 缺失等）；
- 运行时探测的 effective 保证等级低于 min_assurance 设定；
- 审计不可用（no-record → no-execute）；
- seccomp / landlock / cgroup 任一安装步骤顺序错误或部分失败（禁止『看着隔离其实没隔离』的静默状态）。

### SP-G-02 探测一致性

capabilities() 报告可用的每一项机制必须实测验证：landlock 报 ABI 版本（非布尔）、cgroup v2 报真实可委派（实际创建子 cgroup、写入 memory.max 并回读生效，且 cgroup.subtree_control 已 enable memory/cpu 控制器）、seccomp 报 filter 已安装且含 TSYNC。

## 变更记录

| 版本 | 变更 |
|---|---|
| v5 定稿 | 初版注册表；SP-L1-02 补充 ptrace 机制四元落点；SP-L1-05 补充 A 级双网络防线分别验证条款；SP-G-02 补充 subtree_control 控制器 enable 检查 |
| v6 M3 收口 | 占位决策落地：skipped_pending_advisory 升级发布阻断天数 N=14；CLA/DCO 选 DCO（sign-off 即可，无 CLA 签署基础设施）；非特权模式 M3 不予正式支持（rootful supervisor 为唯一支持形态，见 docs/02）。版权头工具迁移至 REUSE 权威校验（check_copyright.sh 调用 reuse lint + 持有者行检查） |
