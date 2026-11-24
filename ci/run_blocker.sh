#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。

# Blocker 级门禁总入口（docs/04-TEST-MATRIX.md 第 1 级）。
# 任何 PR 必过；任一环节失败即非零退出。
# cargo-deny 在 Blocker 中固定检查 licenses/bans/sources（不依赖 GitHub advisory 库）；
# advisories 漏洞扫描按规约属 Scheduled 级（cargo-audit/osv-scanner，带豁免过期）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { echo "==== [Blocker] $1 ===="; }

step "1/7 版权头扫描"
"$ROOT/ci/check_copyright.sh" "$ROOT"

step "2/7 文件行数扫描"
"$ROOT/ci/check_file_length.sh" "$ROOT"

step "3/7 rustfmt"
cargo fmt --all --check

step "4/7 cargo-deny（licenses/bans/sources）"
cargo deny check licenses bans sources

step "5/7 clippy -D warnings"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "6/7 debug+release 双重编译"
cargo build --workspace --locked
cargo build --workspace --locked --release

step "7/7 debug+release 双模式测试"
cargo test --workspace --locked
cargo test --workspace --locked --release

echo "==== Blocker 门禁全部通过 ===="
