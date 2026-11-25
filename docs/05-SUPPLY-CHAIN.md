<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 小黎的部落（www.qingdujian.com）
本版权头任何人不得更改/删除。
-->
# 供应链防护

对一个以 AGPL 发布、且被下游当安全基座使用的 crate，发布链路风险与代码风险同等重要。本章为强制规范。

## 1. 依赖锁定

- CI 一律使用 cargo build --locked / cargo test --locked，防止依赖在构建间静默漂移；
- Cargo.lock 必须入库（包括库 crate），依赖更新只能通过显式 PR 完成；
- cargo-deny 作为 Blocker 门禁：license 白名单（只允许与 AGPL-3.0 兼容的许可）、禁止重复版本、ban 清单。

## 2. 依赖审查（cargo vet）

- 引入 cargo vet（audit-based 依赖审查）：每个第三方依赖版本需要有审计记录；
- 与 unsafe 审查清单同属一套纪律：引入新依赖 = 引入新的信任假设，必须有书面理由；
- wasmtime 作为攻击面最大的依赖，其版本升级必须独立审查并复跑对抗逃逸语料；
- 审计豁免（imports 机制）只允许指向可信组织的公开审计，且带过期日期。

当前基线：cargo-vet 0.10.3 已接入，`supply-chain/{audits,config,imports.lock}.toml` 入库，265 个依赖全部登记（exempted 基线），首检通过。

## 3. 漏洞扫描

- cargo-audit + osv-scanner 位于 Scheduled 级（带过期日期的豁免清单），不做 PR Blocker——传递性依赖存在『无修复版本』的著名案例，Blocker 会被不可控因素永久卡红；
- 豁免必须写明：CVE/GHSA 编号、评估理由（为何不 reachable）、过期日期；过期未处理自动升级为发布阻断。

当前基线（2026-11-24）：cargo-audit 0.22.2 离线模式 1566 advisory / 196 依赖 / 0 告警；osv-scanner v1.9.2 196 packages / 0 issues。

## 4. 发布产物可复现性与来源证明

- release 构建启用可复现选项，产物哈希入册（SHA-256 清单随发布归档）；
- SLSA attestation：发布工作流生成来源证明，下游可验证产物确由本仓库、本提交、本工具链构建；
- 发布产物始终由 stable 1.100.0 构建，nightly 检查结果不作为发布判据。

## 5. SBOM

- 发布版本生成 CycloneDX 格式 SBOM（cargo-cyclonedx 0.5.10，ci/run_sbom.sh）；
- 当前产物：`artifacts/sbom/xiaolishaxiang-1.0.11.sbom.json`，109 个组件。

## 6. crates.io 发布护栏

- 维护者账号强制 2FA；
- 维护者数量设上限，新增维护者需既有维护者多数同意并记录；
- publish 前先 cargo publish --dry-run + 独立审查打包内容（防止误带本地文件）；
- 发现恶意发布或凭据泄漏时按 SECURITY.md 的 yank / 回滚策略执行。

## 7. 工具链来源校验

- 禁止使用 curl 管道方式安装 rustup；
- rustup 安装包必须校验签名 / 哈希；
- rust-toolchain.toml 锁定 1.100.0，CI 显式校验 rustc --version 防漂移；
- 容器镜像构建时使用固定 digest 的基础镜像，不使用 latest 标签。

## 8. vendoring 决策

- 发布到 crates.io 的版本不 vendoring（违背 crates.io 生态惯例）；
- 企业交付场景如需离线构建，提供 vendor 打包脚本作为独立制品，不作为默认发布物。
