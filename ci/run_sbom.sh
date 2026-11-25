#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。
#
# P5 SBOM 生成脚本
# 生成 CycloneDX SBOM（JSON v1.4），产出物落 artifacts/sbom/。
# 用法：ci/run_sbom.sh [--all] [--format json|xml]
set -euo pipefail

export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# 从 Cargo.toml 提取版本号
VERSION=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)"/\1/')
FORMAT="${2:-json}"
OUTPUT_DIR="artifacts/sbom"
OUTPUT_FILE="${OUTPUT_DIR}/xiaolishaxiang-${VERSION}.sbom.${FORMAT}"

echo "[SBOM] 生成 CycloneDX SBOM v1.4，版本 ${VERSION}，格式 ${FORMAT}..."

# 检查 cargo-cyclonedx 是否已安装
if ! command -v cargo-cyclonedx &>/dev/null; then
    echo "[SBOM] 安装 cargo-cyclonedx..."
    cargo install cargo-cyclonedx
fi

mkdir -p "${OUTPUT_DIR}"

# 生成 SBOM（--describe=binaries 为可执行产物生成独立 BOM）
cargo cyclonedx \
    -f "${FORMAT}" \
    -a \
    --spec-version 1.4 \
    --override-filename "xiaolishaxiang-${VERSION}.sbom.${FORMAT}" \
    -v 2>&1 | grep -E '(Outputting|Error|WARN)' || true

# 收集产物（cargo cyclonedx 将每个 crate 的 SBOM 写在各 crate 目录下）
for f in $(find crates -name "xiaolishaxiang-${VERSION}.sbom.${FORMAT}*" 2>/dev/null); do
    crate_name=$(echo "$f" | sed 's|.*/crates/\([^/]*\)/.*|\1|')
    cp "$f" "${OUTPUT_DIR}/xiaolishaxiang-${VERSION}-${crate_name}.sbom.${FORMAT}"
    echo "[SBOM]   ${crate_name} → ${OUTPUT_DIR}/xiaolishaxiang-${VERSION}-${crate_name}.sbom.${FORMAT}"
done

# 清理 crate 目录下的临时文件
find crates -name "xiaolishaxiang-${VERSION}.sbom.${FORMAT}*" -delete 2>/dev/null || true

# 验证 JSON 有效性
if [ "$FORMAT" = "json" ]; then
    for f in "${OUTPUT_DIR}"/*.sbom.json; do
        python3 -c "import json; d=json.load(open('$f')); _=d.get('bomFormat'), d.get('specVersion'), len(d.get('components',[])); print(f'  ✓ $f: {d.get(\"bomFormat\")} {d.get(\"specVersion\")} ({len(d.get(\"components\",[]))} components)')" || echo "  ✗ $f: JSON 无效"
    done
fi

echo "[SBOM] 完成。产物目录：${OUTPUT_DIR}/"
