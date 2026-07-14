# Contributing to wasmscout

Thanks for your interest in improving wasmscout. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain). No other dependencies — the crate is std-only.

```bash
git clone https://github.com/JaydenCJ/wasmscout.git
cd wasmscout
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` generates real wasm fixtures with the in-repo writer and drives the CLI end to end — every finding class, the inference rule, policy gating, JSON output and the documented exit codes. It finishes in well under a minute and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. Parsing and classification live in pure modules (`reader`, `wasm`, `wasi`, `caps`, `custom`, `audit`) that are easy to unit-test; please keep it that way.

## Ground rules

- Keep dependencies at zero. wasmscout parses a binary format with plain `std`; adding a crate needs a very strong justification in the PR description.
- No network calls, ever. wasmscout reads local files and writes to stdout — that is the entire I/O surface, and it is a selling point.
- Never panic on hostile input. Malformed binaries get a diagnostic with a byte offset; unknown-but-plausible content (post-MVP types, new sections) is recorded and skipped. Fuzz-style regression cases are very welcome.
- Finding ids are a public interface: people put them in `--ignore` lists. Renaming one is a breaking change; new findings need an entry in `docs/capabilities.md` and `KNOWN_IDS`.
- Capability classifications must be defensible from the WASI spec or the reference runtimes' behavior — link your source in the PR. When in doubt, be conservative and say so in the finding message.
- Code comments and doc comments are written in English.

## Reporting bugs

Please include the `wasmscout --version` output, the full `scan --format json` output if the file parses, and ideally the offending `.wasm` file itself (or a `gen_fixtures`-style builder snippet that reproduces the shape — see `examples/gen_fixtures.rs`). Misclassification reports ("this import should be capability X") are especially valuable.

## Security

If you find a security issue — for example an input that makes the parser allocate unboundedly, loop forever, or misreport a capability a module actually has — please do not open a public issue. Use GitHub's private vulnerability reporting on this repository instead.
