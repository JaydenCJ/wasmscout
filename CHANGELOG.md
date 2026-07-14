# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Core wasm binary parser (`std` only): sections, imports, exports, memories with shared/memory64 flags, globals with mutability, start section, function signatures resolved through the full index space — with hostile-input guards (byte-offset errors for truncation, impossible vector counts, overlong LEB128) and graceful degradation for post-MVP content (GC types, unknown init opcodes, unknown sections).
- Capability analysis: the complete 46-function WASI preview 1 catalog mapped to 11 capability groups with risk ranks; preview 2 interface prefixes (`wasi:filesystem/`, `wasi:sockets/`, `wasi:http/`, `wasi:cli/`, …) mapped conservatively at interface granularity; non-WASI function imports reported as the `host` capability.
- The inference rule: `path_open` plus a descriptor-write primitive (`fd_write`/`fd_pwrite`/`fd_allocate`/`fd_filestat_set_size`) is reported as `fs-write` marked `[inferred]`, because path_open's rights are chosen at call time.
- 17 finding types with stable ids and severities (`wasi.*`, `host.imports`, `module.*`, `memory.*`, `global.mutable-export`, `section.*`), documented in `docs/capabilities.md`.
- Custom-section decoding: `producers` (toolchain provenance), `target_features`, `name` (module name), `sourceMappingURL` (leak detection), DWARF/`external_debug_info` size aggregation, `linking`/`reloc.*` object-file detection, `dylink` detection.
- CLI: `wasmscout scan` (text or JSON Lines report with a CI gate), `caps` (one risk-ordered line per module), `imports`, `exports`, `sections` (size breakdown with bars); component-model binaries, truncated files and non-wasm impostors (HTML, ELF, gzip, ZIP, `.wat`) are diagnosed with exit code 2.
- Policy gating: `--fail-on high|medium|low|info|never` (default `high`), `--deny <capabilities>` on presence, `--ignore <finding-ids>` validated against the catalog; exit codes `0`/`1`/`2`.
- Deterministic in-repo wasm writer (`builder`) powering the tests, `examples/gen_fixtures.rs` (nine fixture stories) and `examples/ci-gate.sh` (a plugin-intake gate).
- Test suite: 77 unit tests, 13 CLI integration tests, and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/wasmscout/releases/tag/v0.1.0
