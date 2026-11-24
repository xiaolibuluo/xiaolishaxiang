#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。

# Blocker 门禁：单文件行数上限检查。
# 规则（docs/03-ARCHITECTURE.md 第 3 节）：
#   - 默认每个源文件 <= 500 行；
#   - 允许文件内显式豁免标记：  // allow-file-length: <理由>
#   - 豁免文件会被列出在报告中（供审查），但不判 fail。
set -euo pipefail

LIMIT=500
ROOT="${1:-.}"
FAIL=0
EXEMPTED=()
VIOLATED=()

while IFS= read -r -d '' f; do
  lines=$(wc -l < "$f")
  if [ "$lines" -le "$LIMIT" ]; then
    continue
  fi
  if grep -q 'allow-file-length:' "$f"; then
    EXEMPTED+=("$f ($lines 行, 已豁免)")
  else
    VIOLATED+=("$f ($lines 行)")
    FAIL=1
  fi
done < <(find "$ROOT" \
  -path '*/target' -prune -o \
  -path '*/.git' -prune -o \
  -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.sh' \) -print0)

if [ "${#EXEMPTED[@]}" -gt 0 ]; then
  echo "== 豁免文件（需人工审查理由） =="
  printf '  %s\n' "${EXEMPTED[@]}"
fi

if [ "$FAIL" -ne 0 ]; then
  echo "== 超限文件（> ${LIMIT} 行，无豁免标记） ==" >&2
  printf '  %s\n' "${VIOLATED[@]}" >&2
  exit 1
fi

echo "文件行数检查通过（上限 ${LIMIT} 行）。"
