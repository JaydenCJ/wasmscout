#!/usr/bin/env bash
# Smoke test: builds wasmscout, generates real wasm fixtures with the
# in-repo deterministic writer, then drives the CLI end to end — clean
# pass, every major finding class, the inference rule, capability denial,
# severity gating, JSON output and the documented exit codes.
# Self-contained: temp dirs only, no network.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN=target/debug/wasmscout

WORK=$(mktemp -d "${TMPDIR:-/tmp}/wasmscout-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- 1. version/help sanity -------------------------------------------------
"$BIN" --version > "$WORK/version.out"
grep -q '^wasmscout 0\.1\.0$' "$WORK/version.out" || fail "--version mismatch"
"$BIN" --help > "$WORK/help.out"
grep -q 'COMMANDS:' "$WORK/help.out" || fail "--help missing sections"

# --- 2. generate fixtures with the in-repo writer ---------------------------
echo "[smoke] generating fixtures"
cargo run --quiet --example gen_fixtures -- "$WORK" > /dev/null

# --- 3. a pure compute module passes clean ----------------------------------
echo "[smoke] clean module"
"$BIN" scan "$WORK/image-filter.wasm" > "$WORK/clean.out" \
  || fail "clean module failed the gate"
grep -q 'pure compute module' "$WORK/clean.out" || fail "pure module not identified"
grep -q 'findings' "$WORK/clean.out" || fail "findings block missing"
grep -q 'gate: fail-on high → PASS' "$WORK/clean.out" || fail "clean gate not PASS"

# --- 4. each finding class is caught with its id ----------------------------
echo "[smoke] finding classes"
if "$BIN" scan "$WORK/report-writer.wasm" > "$WORK/rw.out"; then
  fail "file-writing module passed the default gate"
fi
grep -q 'high\[wasi.fs-write\]' "$WORK/rw.out" || fail "fs-write not caught"
grep -q 'medium\[wasi.environment\]' "$WORK/rw.out" || fail "environment not caught"
grep -q 'info\[section.debug-info\]' "$WORK/rw.out" || fail "debug bloat not caught"
grep -q 'low\[memory.unbounded\]' "$WORK/rw.out" || fail "unbounded memory not caught"

if "$BIN" scan "$WORK/net-agent.wasm" > "$WORK/net.out"; then
  fail "network module passed the default gate"
fi
grep -q 'high\[wasi.network\]' "$WORK/net.out" || fail "network not caught"
grep -q 'medium\[module.start-function\]' "$WORK/net.out" || fail "start function not caught"

# --- 5. the inference rule: path_open + fd_write = file writes --------------
echo "[smoke] inferred fs-write"
if "$BIN" scan "$WORK/sneaky-logger.wasm" > "$WORK/sneaky.out"; then
  fail "sneaky module passed the default gate"
fi
grep -q '\[inferred\]' "$WORK/sneaky.out" || fail "inference not marked"
grep -q 'high\[wasi.fs-write\]' "$WORK/sneaky.out" || fail "inferred fs-write missing"

# --- 6. deny / fail-on / ignore gating --------------------------------------
echo "[smoke] policy gates"
"$BIN" scan --fail-on never "$WORK/net-agent.wasm" > /dev/null \
  || fail "--fail-on never must always pass"
if "$BIN" scan --fail-on never --deny network "$WORK/net-agent.wasm" > "$WORK/deny.out"; then
  fail "--deny network did not gate the network module"
fi
grep -q "deny: capability 'network' is present" "$WORK/deny.out" || fail "deny line missing"
"$BIN" scan --deny network,fs-write "$WORK/image-filter.wasm" > /dev/null \
  || fail "--deny must pass a module without the capability"
"$BIN" scan --ignore wasi.network "$WORK/net-agent.wasm" > /dev/null \
  || fail "--ignore did not suppress the only high finding"

# --- 7. JSON output ----------------------------------------------------------
echo "[smoke] JSON output"
"$BIN" scan --format json "$WORK/sneaky-logger.wasm" > "$WORK/out.json" && \
  fail "json run should still exit 1"
grep -q '"id":"wasi.fs-write"' "$WORK/out.json" || fail "json missing finding id"
grep -q '"inferred":true' "$WORK/out.json" || fail "json missing inferred flag"
grep -q '"pass":false' "$WORK/out.json" || fail "json missing pass=false"

# --- 8. the other views -------------------------------------------------------
echo "[smoke] caps / imports / exports / sections"
"$BIN" caps "$WORK/report-writer.wasm" > "$WORK/caps.out"
grep -q 'fs-write fs-read environment' "$WORK/caps.out" || fail "caps line wrong"
"$BIN" imports "$WORK/host-plugin.wasm" > "$WORK/imports.out"
grep -q 'env.host_log' "$WORK/imports.out" || fail "imports view missing host import"
grep -q '16..256 pages' "$WORK/imports.out" || fail "imports view missing memory limits"
"$BIN" exports "$WORK/host-plugin.wasm" > "$WORK/exports.out"
grep -q 'mutable' "$WORK/exports.out" || fail "exports view missing mutable global"
"$BIN" sections "$WORK/report-writer.wasm" > "$WORK/sections.out"
grep -q 'custom ".debug_info"' "$WORK/sections.out" || fail "sections view missing debug section"

# --- 9. exit codes for broken inputs ------------------------------------------
echo "[smoke] exit codes"
set +e
"$BIN" scan "$WORK/not-wasm.wasm" 2> "$WORK/html.err"; [ $? -eq 2 ] \
  || { set -e; fail "HTML page should exit 2"; }
grep -q 'HTML' "$WORK/html.err" || { set -e; fail "HTML page not identified"; }
"$BIN" scan "$WORK/truncated.wasm" 2> "$WORK/trunc.err"; [ $? -eq 2 ] \
  || { set -e; fail "truncated file should exit 2"; }
grep -q 'truncated' "$WORK/trunc.err" || { set -e; fail "truncation not diagnosed"; }
"$BIN" scan "$WORK/component.wasm" 2> "$WORK/comp.err"; [ $? -eq 2 ] \
  || { set -e; fail "component should exit 2"; }
grep -q 'component-model binary' "$WORK/comp.err" || { set -e; fail "component not identified"; }
"$BIN" scan "$WORK/does-not-exist.wasm" 2> /dev/null; [ $? -eq 2 ] \
  || { set -e; fail "missing file should exit 2"; }
set -e

# --- 10. multi-file scan summary -----------------------------------------------
echo "[smoke] batch summary"
"$BIN" scan "$WORK/image-filter.wasm" "$WORK/net-agent.wasm" "$WORK/sneaky-logger.wasm" \
  > "$WORK/batch.out" || true
grep -q 'summary: 3 module(s) scanned' "$WORK/batch.out" || fail "batch summary wrong"

echo "SMOKE OK"
