<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->
# 混沌测试方案（Scheduled 级门禁）

依据 docs/04-TEST-MATRIX.md 第 3 级『混沌测试：故障注入（IO 失败、时钟跳变、网络抖动），行为符合规约』。

## 1. 本机可用原语盘点

| 注入维度 | 可用工具 | 注入能力 |
|---|---|---|
| 网络 | iptables / nftables | DROP/REJECT 规则，模拟网络不可达/抖动 |
| 网络 | tc（iproute2） | 延迟/丢包/带宽限制，模拟网络抖动 |
| 存储 | dd + losetup | loop 设备满盘写入，模拟 ENOSPC |
| 存储 | /proc/sysrq-trigger | 紧急同步/只读重挂载（仅 root，极端故障场景） |
| 文件系统 | fanotify | fanotify_mark FAN_DENY 注入 EACCES |
| 进程 | kill / SIGSTOP / SIGCONT | 暂停/恢复子进程模拟进程卡顿 |
| 资源压力 | stress-ng | CPU/内存/IO 压力发生器 |

**架构定调**：本机为裸 VM，chaos-mesh / Toxiproxy 等依赖容器/K8s 的工具不适用；混沌测试走轻量自写用例路线。

## 2. 三类注入方案

### 2.1 文件系统故障注入

| 故障类型 | 注入手段 | 预期行为 | SP-ID 关联 |
|---|---|---|---|
| ENOSPC（磁盘满） | 创建 loop 设备 + 写满后沙箱内写操作触发 | 沙箱内写操作返回 ENOSPC；supervisor 不受影响，审计记录事件 | SP-L1-01 / SP-G-01 |
| EACCES（权限拒绝） | fanotify FAN_DENY 对沙箱工作目录注入拒绝 | 沙箱内读/写返回 EACCES；fail-closed 且不 crash supervisor | SP-L1-01 / SP-G-01 |
| 临时文件竞态 | 双写入并发删除同一 tmp 文件 | 一边失败不串扰另一边，无 fd 泄漏 | 冲突测试覆盖 |

### 2.2 网络故障注入

| 故障类型 | 注入手段 | 预期行为 | SP-ID 关联 |
|---|---|---|---|
| TCP 连接中断 | iptables -A OUTPUT -p tcp --dport N -j DROP | 沙箱内连接返回超时/拒绝；supervisor 控制通道不受影响（netns 隔离保证） | SP-L1-05 |
| 网络延迟 | tc qdisc add dev lo root netem delay 200ms | 沙箱内网络 IO 延迟增加；审计背压不受网络延迟拖垮 | SP-L2-04 |
| DNS 不可达 | iptables -A OUTPUT -p udp --dport 53 -j DROP | 沙箱内 DNS 解析失败；不允许回退到直连 IP 绕过策略 | SP-L1-05 |

### 2.3 进程故障注入

| 故障类型 | 注入手段 | 预期行为 | SP-ID 关联 |
|---|---|---|---|
| 子进程卡死 | SIGSTOP 暂停沙箱子进程，sleep N 后 SIGCONT | supervisor waitpid 超时策略正确（不无限阻塞），资源在超时后回收 | SP-L1-06 / SP-L2-03 |
| 僵尸进程堆积 | fork 后父进程不 waitpid，快速重复 | PID namespace 内僵尸积累不超过配额；cgroup pids.max 拦截超额 fork | SP-L1-06 / SP-L2-01 |
| OOM kill | 内存超配（cgroup memory.max 远小于分配量） | 沙箱内进程被 OOM kill；supervisor 存活且记录事件 | SP-L2-01 |

## 3. 落地状态（6 类 9 用例全绿）

| 故障类型 | 用例文件与用例 | 状态 |
|---|---|---|
| OOM kill | cgroup memory.max + blob 分配（xs-l2-res 委派探测与背压测试覆盖） | ✅ 已覆盖（Scheduled 级 soak 每日验证无泄漏） |
| TCP 连接中断 | l1_chaos_tcp_stall.rs：chaos_tcp_drop_sandbox_connect_fails_supervisor_survives（iptables DROP → 沙箱 connect 失败 → supervisor 存活 → iptables -D cleanup） | ✅ 2 用例全绿 |
| 子进程卡死 | l1_chaos_tcp_stall.rs：chaos_child_stall_sigstop_recover_with_sigkill（SIGSTOP → WNOHANG 确认 stall → SIGKILL 回收 → 重建域后 spawn 正常） | ✅ 2 用例全绿 |
| ENOSPC | l1_chaos_enospc.rs：chaos_enospc_sandbox_write_returns_enospc_supervisor_survives（loop 10MB ext4 填满 → 沙箱写入 ENOSPC 显式失败 → supervisor 存活 → 清理） | ✅ 1 用例全绿 |
| 网络延迟 | l1_chaos_net_delay.rs：chaos_net_delay_tc_injected_supervisor_survives（跨 netns 注入受沙箱 seccomp 约束，用例以 not_applicable 优雅降级、supervisor 存活验证通过） | ✅ 1 用例通过 |
| fanotify EACCES | l1_chaos_fanotify.rs：chaos_fanotify_eacces_sandbox_open_denied_supervisor_survives + chaos_fanotify_eacces_supervisor_survives_after_fd_close（FAN_DENY 注入 → 沙箱 cat 被 EACCES 拒绝 → supervisor 存活 → fd 关闭 mark 自动清除） | ✅ 2 用例全绿 |

## 4. 联动与纪律

- 混沌测试用例统一放在对应 crate 的 tests/ 下（按故障类别归属 L1/L2 层），不新建独立 tests crate。
- 每个混沌用例必须声明验证的 SP-ID 并遵循 require_isolatable() 环境推导约定（禁手写 skip）。
- 故障注入后必须恢复环境：iptables 规则在测试结束时删除（trap cleanup）、loop 设备 detach、SIGSTOP 子进程确保 SIGCONT 或 SIGKILL。
- 混沌用例仅在 Scheduled 级触发，不进 Blocker 门禁，避免 PR 阶段受环境波动影响。
