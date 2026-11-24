#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。

# 自动升版脚本：递增 workspace.package.version 的 patch 号（dev 后缀保持）。
# 用法：
#   bash ci/bump_version.sh "commit message"
#   bash ci/bump_version.sh "feat: add health endpoint"
# 如果未提供 message，自动生成 "chore: bump version to X.Y.Z-dev"。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_TOML="$ROOT/Cargo.toml"
MESSAGE="${1:-}"

# 读取当前版本
current=$(grep -oP '^version\s*=\s*"\K[^"]+' "$CARGO_TOML" | head -1)
if [ -z "$current" ]; then
    echo "ERROR: 无法从 $CARGO_TOML 中读取版本号" >&2
    exit 1
fi

# 解析 MAJOR.MINOR.PATCH-dev
base="${current%%-dev*}"
suffix="${current#$base}"  # 可能是 "" 或 "-dev"

IFS='.' read -r major minor patch <<< "$base"

new_patch=$((patch + 1))
new_version="${major}.${minor}.${new_patch}${suffix}"

echo "${current} → ${new_version}"

# 原地替换（仅替换 workspace.package 下的 version 行）
sed -i "s/^version = \"${current}\"$/version = \"${new_version}\"/" "$CARGO_TOML"

# 校验替换成功
after=$(grep -oP '^version\s*=\s*"\K[^"]+' "$CARGO_TOML" | head -1)
if [ "$after" != "$new_version" ]; then
    echo "ERROR: 替换失败，期望 ${new_version}，实际 ${after}" >&2
    exit 1
fi

cd "$ROOT"
git add "$CARGO_TOML"
if [ -n "$MESSAGE" ]; then
    git commit -m "${MESSAGE} (${new_version})"
else
    git commit -m "chore: bump version to ${new_version}"
fi

echo "version: ${new_version}"
