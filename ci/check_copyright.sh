#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。
# Blocker 第 1 道门禁：版权头完整性扫描。
# M3 起迁移至 REUSE 工具做权威校验（docs/03-ARCHITECTURE.md）：
#   reuse lint 校验 SPDX 头、LICENSES/ 许可证文本与 REUSE 3.3 规范合规；
#   本脚本追加项目特定检查：版权持有者行『小黎的部落』必须逐文件出现
#   （REUSE 只校验存在任意版权行，不校验持有者归属）。
set -euo pipefail
ROOT="${1:-.}"

# 定位 reuse：PATH 优先，回退用户级 venv 软链（安装方式见 docs/03）。
REUSE_BIN="$(command -v reuse || true)"
if [ -z "$REUSE_BIN" ] && [ -x "$HOME/.local/bin/reuse" ]; then
    REUSE_BIN="$HOME/.local/bin/reuse"
fi
if [ -z "$REUSE_BIN" ]; then
    echo "未找到 reuse 工具（python venv 安装，见 docs/03-ARCHITECTURE.md）" >&2
    exit 1
fi

echo "== 1/2 reuse lint（SPDX/规范权威校验）=="
(cd "$ROOT" && "$REUSE_BIN" lint)

echo "== 2/2 版权持有者行检查（小黎的部落）=="
FAIL=0
MISSING=()
while IFS= read -r -d '' f; do
    if ! grep -q '小黎的部落' "$f"; then
        MISSING+=("$f (缺版权持有者行)")
        FAIL=1
    fi
done < <(find "$ROOT" \
    -path '*/target' -prune -o \
    -path '*/.git' -prune -o \
    -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.sh' -o -name '*.py' -o -name '*.md' \) -print0)
if [ "$FAIL" -ne 0 ]; then
    echo "== 版权持有者行缺失文件 ==" >&2
    printf '  %s\n' "${MISSING[@]}" >&2
    exit 1
fi
echo "版权头检查通过（reuse lint + 持有者行）。"
