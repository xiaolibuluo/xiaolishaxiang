<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 内核版本兼容矩阵（Scheduled 级门禁）

依据 docs/04-TEST-MATRIX.md 第 3 级『内核版本矩阵：5.15 / 6.1 / 6.6 / 6.12（本机 7.0 作为附加观察位），各内核上按 SP-ID 全绿或 not_applicable 有正当推导』。

## 当前状态

- **本机（推理机）**：内核 7.0.0-42-generic，Ubuntu 26.04.1，landlock ABI=8，cgroup v2，systemd 259。
- **状态**：M4 baseline **blocked_by_single_kernel**——本机仅一个内核版本，无法执行多内核兼容矩阵测试。
- **在本机上的作用**：7.0 作为『附加观察位』——所有用例在本机上 run 并记录结果，作为最高内核版本的当前行为快照，但**不能替代** 5.15 / 6.1 / 6.6 / 6.12 各版本上的独立验证。

## 目标版本与 SP-ID 覆盖

| 内核版本 | 代表性发行版 | key 能力差异 | 验证要求 | 当前状态 |
|---|---|---|---|---|
| 5.15 | Ubuntu 22.04 LTS / Debian 11 | landlock ABI v1（仅 FS）；userns 策略因发行版而异 | 所有 SP-ID 跑满，landlock 网络维度 not_applicable（ABI v1 无网络维） | ⏳ blocked_by_single_kernel |
| 6.1 | Ubuntu 22.04 HWE / Debian 12 backports | landlock ABI v2（FS 增强）；无网络维 | 同上 | ⏳ blocked_by_single_kernel |
| 6.6 | Ubuntu 24.04 HWE | landlock ABI v3（+ 网络）；io_uring 阻断维持 | 同上 | ⏳ blocked_by_single_kernel |
| 6.12 | Ubuntu 24.10 / Fedora 41 | landlock ABI v4（+ IPC） | 同上 | ⏳ blocked_by_single_kernel |
| **7.0** | Ubuntu 26.04（本机） | landlock ABI v8；本机所有能力满配 | 作为附加观察位：全用例跑满记录 baseline | ✅ 172 用例全绿（2026-11-24 基线） |

## 迁移路径

| 方案 | 工具 | 优势 | 劣势 | 推荐优先级 |
|---|---|---|---|---|
| A：Docker 多内核容器 | docker run + 挂载 /lib/modules | 轻量，单机可并跑 | 容器内内核版本与宿主一致，无法切换内核；仅适用于发行版差异测试 | ❸ 最低 |
| B：Vagrant + VirtualBox/KVM | Vagrantfile 多 box | 完整 VM 隔离，可切换内核 | 需虚拟化 + box 镜像拉取（网络） | ❷ 中等 |
| C：QEMU 云镜像 + cloud-init | qemu-system-x86_64 + Ubuntu cloud image | 全自动化，可 CI 集成 | 资源开销大（单 VM 1-2 GB RAM） | ❶ 推荐 |
| D：GitHub Actions 多 runner | actions/checkout + matrix | CI 原生，维护成本低 | 依赖外网 + GitHub 平台 | ❶ 推荐（外网恢复后） |

## 决策状态

- **M4 暂不决策迁移方案**：C/D 均依赖外网（云镜像拉取 / GitHub Actions runner），本机网络受限。
- **无外网时的降级策略**：
  1. 本机 7.0 作为唯一观察位持续跑 full test suite（当前已覆盖）。
  2. Scheduled 级发布门禁中内核矩阵结果登记为 `blocked_by_single_kernel`，不作为发布阻断。
  3. 外网恢复后优先选方案 C（QEMU 云镜像）在本地建立多内核 CI 管道，并登记结果回填本表。

## 维护纪律

1. 新增内核版本（如 7.1/7.2）时追加行，记录版本 + 代表性发行版 + key 能力差异。
2. 每年 LTS 周期复查一次——目标版本是否仍需保留（如对应发行版 EOL 即剔除）。
3. 迁移方案落地后将本表中 `blocked_by_single_kernel` 条目逐个更新为实测结果（pass / not_applicable by SP-ID）。
