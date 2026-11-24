#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。

# soak 持久稳定流水线主入口（docs/04-TEST-MATRIX.md 第 3 级 Scheduled）。
# 不阻断 PR，阻断发布：verdict=fail 时退出码 1。
# 载体决策（M2 回填占位）：本机 systemd 259 + cron 均可用，选用 systemd timer
# （服务管理、日志 journalctl 可查、失败重启语义明确），单元文件见 ci/systemd/。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DURATION="${XS_SOAK_DURATION_SECS:-86400}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$ROOT/artifacts/soak/$STAMP"
OUT_FILE="$OUT_DIR/soak.jsonl"

mkdir -p "$OUT_DIR"

echo "==== [soak] 构建 release 版 soak_probe ===="
cargo build --release -p xs-l1-sys --example soak_probe

echo "==== [soak] 启动 soak：时长 ${DURATION}s，产物 $OUT_FILE ===="
set +e
XS_SOAK_DURATION_SECS="$DURATION" XS_SOAK_OUT="$OUT_FILE" \
    "$ROOT/target/release/examples/soak_probe"
rc=$?
set -e

ln -sfn "$OUT_DIR" "$ROOT/artifacts/soak/latest"

echo "==== [soak] 结果（退出码 $rc，0=pass 非 0=fail）===="
cat "$OUT_FILE.verdict.json"
exit "$rc"
