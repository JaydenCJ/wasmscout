# wasmscout examples

Two runnable examples, both offline and deterministic.

## gen_fixtures.rs

Generates a set of small wasm binaries with wasmscout's built-in
deterministic writer: one clean pure-compute module plus eight files each
telling a specific audit story (a WASI CLI tool that writes files, a
network agent with a start function, the `path_open + fd_write` inference
case, an embedder plugin with custom host imports, a relocatable object
file, a component, a truncated upload, an HTML page saved as `.wasm`).

```bash
cargo run --example gen_fixtures -- /tmp/wasm-fixtures
cargo run -- scan /tmp/wasm-fixtures/report-writer.wasm
cargo run -- scan --format json /tmp/wasm-fixtures/sneaky-logger.wasm
```

| File | Expected outcome |
|---|---|
| `image-filter.wasm` | exit 0, no capabilities, no findings |
| `report-writer.wasm` | `wasi.fs-write` high + fs-read/environment medium + debug-info info |
| `net-agent.wasm` | `wasi.network` high + `module.start-function` medium |
| `sneaky-logger.wasm` | `wasi.fs-write` high, marked `[inferred]` |
| `host-plugin.wasm` | `host.imports` medium + mutable-export, source-map, imported memory |
| `object-file.wasm` | `module.object-file` low (linker input, not a runnable module) |
| `component.wasm` | exit 2: component-model binary, not audited in 0.1.0 |
| `truncated.wasm` | exit 2: section claims more bytes than remain |
| `not-wasm.wasm` | exit 2: bad magic, identified as an HTML page |

## ci-gate.sh

Shows `wasmscout scan` as a plugin-intake gate: audits every `.wasm` file
in a directory with `--fail-on medium --deny network,fs-write` and exits
non-zero when any module violates the policy — ready to sit in front of a
plugin registry or an agent's tool directory.

```bash
cargo run --example gen_fixtures -- /tmp/wasm-fixtures
bash examples/ci-gate.sh /tmp/wasm-fixtures; echo "exit: $?"
```

The fixture generator emits fixed byte sequences, so its output is
byte-identical on every machine.
