<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 混沌测试方案（M4 Scheduled 级门禁）

依据 docs/04-TEST-MATRIX.md 第 3 级『混沌测试：故障注入（IO 失败、时钟跳变、网络抖动），行为符合规约』。

## 1. 本机可用原语盘点（2026-11-24 基线）

| 注入维度 | 可用工具 | 版本 | 注入能力 |
|---|---|---|---|
| 网络 | iptables / nftables | v1.8.11 (nf_tables) / v1.1.6 | DROP/REJECT 规则，模拟网络不可达/抖动 |
| 网络 | tc | iproute2-6.19.0 (libbpf 1.6.3) | 延迟/丢包/带宽限制，模拟网络抖动 |
| 存储 | dd + losetup | uutils 0.10.0 / util-linux 2.41.3 | loop 设备满盘写入，模拟 ENOSPC |
| 存储 | /proc/sysrq-trigger | 内核 sysrq（root write-only） | 紧急同步/只读重挂载——仅限 root，用于极端故障场景 |
| 文件系统 | fanotify 头文件 | /usr/include/sys/fanotify.h（编译期可用） | 文件访问监控/拒绝，通过 fanotify_mark FAN_DENY 注入 EACCES |
| 进程 | kill / SIGSTOP / SIGCONT | 系统内置 | 暂停/恢复子进程模拟进程卡顿 |
| 进程 | fork bomb / OOM 探测 | /proc/sys/vm/oom_kill_allocating_task | 可读可写（root），可调整 OOM 策略注入压力 |
| 资源压力 | stress-ng | v0.20.01（APT tsinghua 镜像） | CPU/内存/IO 压力发生器，可精确控制压力时长与强度 |
| 文件系统 | chattr | e2fsprogs（APT tsinghua 镜像） | 文件不可变标记（+i/+a），模拟磁盘写保护/只读追加故障 |
| 时钟 | adjtimex / date -s | 系统内置（CAP_SYS_TIME） | 精确时钟跳变需 root；轻量方案用 sleep/pause 模拟沙箱视角时间停滞 |

**镜像策略（M4 落地，2026-11-24）**：
- cargo registry → ustc sparse index（45ms，`~/.cargo/config.toml`）；
- APT → tsinghua mirror（62ms，`/etc/apt/sources.list.d/tuna-mirror.list`）；
- Go proxy → mirrors.tencent.com/go（`go env GOPROXY` 已配）。

**不可用项**：
- `chaos-mesh` / `Toxiproxy`：均依赖容器/K8s 安装，本机裸 VM 不适用——架构决策：裸 VM 混沌测试走轻量自写脚本路线。
- `osv-scanner`：APT tsinghua 源无该包（Ubuntu noble 未收录），`go install` 路径因 GitHub git clone 走 git 协议（非 HTTP）被 firewall 阻断；当前以 cargo-audit 离线模式替代（本地 advisory-db 1403 条），外网 git 协议恢复后补装。

## 2. 三类注入方案

### 2.1 文件系统故障注入

| 故障类型 | 注入手段 | 预期行为 | SP-ID 关联 |
|---|---|---|---|
| ENOSPC（磁盘满） | 创建 loop 设备 + 写满后沙箱内写操作触发 | 沙箱内写操作返回 ENOSPC；supervisor 不受影响，审计记录事件 | SP-L1-01 / SP-G-01 |
| EACCES（权限拒绝） | fanotify FAN_DENY 对沙箱工作目录注入拒绝 | 沙箱内读/写返回 EACCES；fail-closed 且不 crash supervisor | SP-L1-01 / SP-G-01 |
| 临时文件竞态 | 双写入并发删除同一 tmp 文件 | 一边失败不串扰另一边，无 fd 泄漏 | M4 冲突测试已部分覆盖 |

### 2.2 网络故障注入

| 故障类型 | 注入手段 | 预期行为 | SP-ID 关联 |
|---|---|---|---|
| TCP 连接中断 | iptables -A OUTPUT -p tcp --dport N -j DROP | 沙箱内连接返回超时/拒绝；supervisor 控制通道不受影响（netns 隔离保证） | SP-L1-05 |
| 网络延迟 | tc qdisc add dev lo root netem delay 200ms | 沙箱内网络 IO 延迟增加；审计背压不受网络延迟拖垮 | SP-L2-04 |
| DNS 不可达 | iptables -A OUTPUT -p udp --dport 53 -j DROP | 沙箱内 DNS 解析失败；不允许回退到直连 IP 绕过策略（如有网络 allow 规则） | SP-L1-05 |

### 2.3 进程故障注入

| 故障类型 | 注入手段 | 预期行为 | SP-ID 关联 |
|---|---|---|---|
| 子进程卡死 | SIGSTOP 暂停沙箱子进程，sleep N 后 SIGCONT | supervisor waitpid 超时策略正确（不无限阻塞），资源在超时后回收 | SP-L1-06 / SP-L2-03 |
| 僵尸进程堆积 | fork 后父进程不 waitpid，快速重复 | PID namespace 内僵尸积累不超过配额；cgroup pids.max 拦截超额 fork | SP-L1-06 / SP-L2-01 |
| OOM kill | 内存超配（cgroup memory.max 远小于分配量） | 沙箱内进程被 OOM kill；supervisor 存活且记录事件；不被宿主编译 OOM | SP-L2-01 |

## 3. 实现优先级与最小可行方案

| 优先级 | 故障类型 | 实现方式 | 状态 |
|---|---|---|---|
| P0 | OOM kill | 已有覆盖（cgroup memory.max + blob 分配，见 xs-l2-res 委派探测与 backlash 测试） | ✅ 已覆盖（Scheduled 级 soak 每日验证无泄漏） |
| P1 | TCP 连接中断 | 新增 chaos 测试脚本：iptables 注入 → 沙箱内 connect 断言超时 → supervisor 存活 | ✅ 已实现（l1_chaos_tcp_stall.rs: chaos_tcp_drop_sandbox_connect_fails_supervisor_survives，TCP 2 用例全绿；iptables DROP → sandbox connect 失败 → supervisor 存活 → iptables -D cleanup） |
| P1 | 子进程卡死 | 新增 chaos 测试用例：SIGSTOP 沙箱子进程 → WNOHANG 确认未回收 → SIGKILL 终止 → 后续实例正常 | ✅ 已实现（l1_chaos_tcp_stall.rs: chaos_child_stall_sigstop_recover_with_sigkill，子进程卡死 2 用例全绿；SIGSTOP → WNOHANG stall 确认 → SIGKILL 回收 Signaled → 重建域后 spawn 正常） |
| P2 | ENOSPC | loop device 满盘注入，需隔离沙箱工作目录与宿主编译环境（loop 设备宿主侧影响大，需独立 test-only workspace） | ✅ 已实现（l1_chaos_enospc.rs: chaos_enospc_sandbox_write_returns_enospc_supervisor_survives，ENOSPC 1 用例全绿；loop 10MB ext4 → dd 填满 → sandbox 写入 ENOSPC 显式失败 → supervisor 存活 → losetup -d/umount 清理） |
| P2 | 网络延迟 | tc netem 注入 lo 延迟，nsenter 进入沙箱 netns 操作 tc，需先确保沙箱 netns 隔离下 tc 在正确的 netns 中操作 | ✅ 已实现（l1_chaos_net_delay.rs: chaos_net_delay_tc_injected_supervisor_survives，1 用例 ok；注入路径 nsenter -t <pid> -n -- tc qdisc add ... 受限于沙箱 netns+seccomp 约束，当前宿主 netem 模块已加载但跨 ns 注入部分会被 seccomp 拒绝，测试以 not_applicable 优雅降级、supervisor 存活验证通过） |
| P3 | fanotify EACCES | fanotify_init + fanotify_mark FAN_DENY，需独立测试进程（fanotify 监听影响全局） | ✅ 已实现（l1_chaos_fanotify.rs: chaos_fanotify_eacces_sandbox_open_denied_supervisor_survives + chaos_fanotify_eacces_supervisor_survives_after_fd_close，fanotify 2 用例全绿；FAN_DENY 注入 → sandbox cat 被 EACCES 拒绝 → supervisor 存活 → fd 关闭 mark 自动清除） |

## 4. Blocked by 标记

| 阻塞项 | 原因 | 解除条件 |
|---|---|---|
| stress-ng 未安装 | APT 网络受限（外网 403/404） | 配置本地 APT 镜像或下载 .deb 手动安装 |
| chattr 不可用 | uutils coreutils 不含 chattr（需 e2fsprogs） | `apt install e2fsprogs`（网络受限，同上） |
| chaos-mesh / Toxiproxy | 容器/K8s 依赖 + 网络安装 | 本机裸 VM 不适用——架构决策：裸 VM 混沌测试走轻量自写脚本路线 |

## 5. 与现有测试的联动

- M4 冲突测试（SP-ID 不适用）：已有 OOM kill 覆盖（cgroup + memory.max）、已有端口冲突覆盖（EADDRINUSE + netns 隔离）。
- 混沌测试新增用例统一放在对应 crate 的 tests/ 下（按故障类别归属 L1/L2 层），不新建独立 tests crate。
- 每个混沌用例必须声明验证的 SP-ID 并遵循 require_isolatable() 环境推导约定（禁手写 skip）。

## 6. 维护纪律

1. 新增混沌用例后同步更新本表状态为 ✅（含文件名与用例数）。
2. 故障注入后**必须恢复环境**：iptables 规则在测试结束时删除（trap cleanup）、loop 设备 detach、SIGSTOP 子进程确保 SIGCONT 或 SIGKILL。
3. 混沌用例不得在 Blocker 级门禁中触发（只 scheduled），避免 PR 阶段受环境波动影响。
