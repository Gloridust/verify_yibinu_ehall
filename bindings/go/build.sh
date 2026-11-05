#!/usr/bin/env bash
# 构建 Rust 静态库并放到 bindings/go/lib/，供 cgo 链接。
# 用法：./bindings/go/build.sh [--vendored-openssl]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FEATURES=()
[[ "${1:-}" == "--vendored-openssl" ]] && FEATURES=(--features vendored-openssl)
cargo build --release -p yibinu-auth-ffi "${FEATURES[@]}" --manifest-path "$ROOT/Cargo.toml"
mkdir -p "$ROOT/bindings/go/lib"
cp "$ROOT/target/release/libyibinu_auth_ffi.a" "$ROOT/bindings/go/lib/"
echo "OK: $ROOT/bindings/go/lib/libyibinu_auth_ffi.a"
