#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 小黎的部落（www.qingdujian.com）
# 本版权头任何人不得更改/删除。

# fuzz 冒烟门禁主入口（docs/04-TEST-MATRIX.md M3 级）。
# 目标：SP-G-01 —— xs_core::SandboxConfig::from_toml 任意输入不 panic，
# Ok 必须过 validate() 复检。崩溃或非零退出即失败（退出码 1）。
# 运行器：cargo-fuzz + libFuzzer（ nightly 工具链，ASan 由 cargo-fuzz 默认注入）。

set -euo pipefail

# systemd 环境 PATH 默认为 /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin，
# 不含 ~/.cargo/bin（rustup/cargo），手动注入以确保 cargo +nightly 可找到。
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/crates/xs-core/fuzz"
TARGET="${XS_FUZZ_TARGET:-fuzz_config_parse}"
DURATION="${XS_FUZZ_DURATION_SECS:-60}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="$ROOT/artifacts/fuzz/$STAMP"
ARTIFACT_DIR="$OUT_DIR/artifacts"
LOG_FILE="$OUT_DIR/fuzz.log"

mkdir -p "$ARTIFACT_DIR"

cd "$FUZZ_DIR"

echo "==== [fuzz] 目标 $TARGET，限时 ${DURATION}s，产物 $OUT_DIR ===="
set +e
timeout "$((DURATION + 300))" cargo +nightly fuzz run "$TARGET" -- \
    -max_total_time="$DURATION" \
    -artifact_prefix="$ARTIFACT_DIR/" \
    > "$LOG_FILE" 2>&1
rc=$?
set -e

ln -sfn "$OUT_DIR" "$ROOT/artifacts/fuzz/latest"

# libFuzzer 正常跑满 max_total_time 会以 0 退出（DONE）；
# 发现崩溃时以非零退出并在 artifact_prefix 下写出 crash-* 文件。
CRASH_COUNT="$(find "$ARTIFACT_DIR" -maxdepth 1 -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' 2>/dev/null | wc -l)"

echo "==== [fuzz] 结果：退出码 $rc，crash 产物 $CRASH_COUNT 个 ===="
tail -n 20 "$LOG_FILE" || true

if [ "$rc" -ne 0 ] || [ "$CRASH_COUNT" -ne 0 ]; then
    echo "[fuzz] FAIL：详见 $LOG_FILE 与 $ARTIFACT_DIR" >&2
    exit 1
fi

echo "[fuzz] PASS：${DURATION}s 无崩溃"
