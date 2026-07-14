#!/usr/bin/env bash
# A plugin-intake gate: audit every .wasm file in a directory before it is
# allowed anywhere near a runtime. Policy: no network, no file writes, and
# nothing above medium severity. Exits non-zero when any module violates it.
#
# Usage:
#   cargo run --example gen_fixtures -- /tmp/wasm-fixtures
#   bash examples/ci-gate.sh /tmp/wasm-fixtures; echo "exit: $?"
set -euo pipefail

DIR="${1:?usage: ci-gate.sh <directory-of-wasm-files>}"

cd "$(dirname "$0")/.."
cargo build --quiet
BIN=target/debug/wasmscout

status=0
for module in "$DIR"/*.wasm; do
  echo "=== $module"
  if ! "$BIN" scan --fail-on medium --deny network,fs-write "$module"; then
    status=1
  fi
  echo
done

if [ "$status" -ne 0 ]; then
  echo "GATE: at least one module was refused" >&2
else
  echo "GATE: all modules passed"
fi
exit "$status"
