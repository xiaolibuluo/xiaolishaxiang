#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。

# 发布包脚本：打包 xs-cli 二进制 + systemd 单元 + 文档 + 许可证为 .tar.xz
# 用法：
#   bash ci/publish_release.sh              # 输出到当前目录
#   bash ci/publish_release.sh /tmp         # 输出到指定目录
# 前置条件：cargo build --release --locked 已完成

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT}"
cd "$ROOT"

# 读取版本号
version=$(grep -oP '^version\s*=\s*"\K[^"]+' Cargo.toml | head -1)
if [ -z "$version" ]; then
    echo "ERROR: 无法读取版本号" >&2
    exit 1
fi

# 验证二进制存在
binary="target/release/xs-cli"
if [ ! -f "$binary" ]; then
    echo "ERROR: 未找到 $binary，请先执行 cargo build --release --locked" >&2
    exit 1
fi

pkg_name="xiaolishaxiang-${version}-x86_64"
archive="${pkg_name}.tar.xz"
echo "== 打包 $pkg_name =="

# 构建临时目录
staging="/tmp/xs-publish-$$"
mkdir -p "$staging/$pkg_name/bin" "$staging/$pkg_name/etc/systemd"

# 二进制
cp "$binary" "$staging/$pkg_name/bin/xs-cli"
strip "$staging/$pkg_name/bin/xs-cli" 2>/dev/null || true

# systemd 单元
cp ci/systemd/xiaolishaxiang-soak.service "$staging/$pkg_name/etc/systemd/"
cp ci/systemd/xiaolishaxiang-soak.timer "$staging/$pkg_name/etc/systemd/"
cp ci/systemd/xiaolishaxiang-fuzz.service "$staging/$pkg_name/etc/systemd/" 2>/dev/null || true
cp ci/systemd/xiaolishaxiang-fuzz.timer "$staging/$pkg_name/etc/systemd/" 2>/dev/null || true

# 文档
mkdir -p "$staging/$pkg_name/docs"
cp docs/*.md "$staging/$pkg_name/docs/"
cp README.md SECURITY.md "$staging/$pkg_name/" 2>/dev/null || true

# 许可证
cp -r LICENSES/ "$staging/$pkg_name/"

# CI 脚本（运维用）
mkdir -p "$staging/$pkg_name/ci"
cp ci/run_blocker.sh ci/check_copyright.sh ci/check_file_length.sh ci/bump_version.sh ci/run_soak.sh "$staging/$pkg_name/ci/" 2>/dev/null || true

# 打包
cd "$staging"
tar -cJf "$OUT_DIR/$archive" "$pkg_name"
rm -rf "$staging"

echo "== $OUT_DIR/$archive =="
ls -lh "$OUT_DIR/$archive"
