<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->

# 安全政策（Security Policy）

xiaolishaxiang 是安全基座类组件，其自身安全问题的处理标准高于一般项目。

## 支持的版本

| 版本 | 状态 |
|---|---|
| main（未发布） | 安全修复直接合入 |
| 最新 release | 接受安全修复，以补丁版本发布 |
| 更早 release | 仅最高危（沙箱逃逸级）问题提供修复建议 |

## 报告漏洞

请勿在公开 issue 中报告安全漏洞。推荐渠道：

1. 通过项目主页（www.qingdujian.com）提供的安全联系方式提交；
2. 报告内容请包含：受影响的 SP-ID（见 docs/01-SECURITY-PROPERTIES.md）、复现条件、概念验证（如有）、影响评估。

## 响应时限

| 阶段 | 时限 |
|---|---|
| 确认收到报告 | 48 小时内 |
| 初步评估（是否成立、定级） | 7 天内 |
| 修复与补丁发布 | 沙箱逃逸级（TCB 被击穿）14 天内；其余 30 天内 |
| 公开披露 | 补丁发布后，与报告者协商披露时间 |

## 漏洞定级

| 级别 | 定义 |
|---|---|
| Critical | 沙箱逃逸：L1/L2/L3 任一隔离边界被从内部击穿，或 fail-closed 机制失效（静默降级） |
| High | 单条安全属性（SP-ID）失效但不出边界，或能力句柄可被伪造/复用 |
| Medium | 审计事件丢失未被标记、探测误报可用 |
| Low | 文档与实际行为不符等 |

## yank / 回滚策略

- 确认某 release 包含 Critical/High 漏洞且补丁尚未就绪时：立即在 crates.io 执行 yank，并在 README 与发布页公示；
- 补丁版本发布后，在 changelog 中标注被 yank 版本与漏洞编号；
- 对外发布的安全公告统一编号（XS-YYYY-NNN），并回归固化为对抗逃逸语料（见 docs/04-TEST-MATRIX.md）。

## 供应链事故

凭据泄漏、恶意发布等供应链事故按 docs/05-SUPPLY-CHAIN.md 第 5 节执行：立即撤销凭据、yank 受污染产物、公示哈希清单供下游核对。
