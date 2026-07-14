# Capabilities and findings reference

How wasmscout decides what a module can touch, and every finding it can
emit. All of this is derived from the binary's import section and custom
sections — wasmscout never executes a byte of the module.

## The capability model

Every **function import** grants exactly one capability (structural
imports — memories, tables, globals — grant none; they are reported as
findings where they matter). WASI preview 1 imports are mapped
function-by-function from the complete 46-entry catalog in
[`src/wasi.rs`](../src/wasi.rs). Preview 2 style imports in core modules
(`wasi:namespace/interface@version` module names) are mapped at interface
granularity. Anything else is `host`.

| Capability | Risk | Grants |
|---|---|---|
| `fs-write` | high | create, modify or delete files and directories under the runtime's preopens |
| `network` | high | accept, send or receive on host-provided sockets |
| `host` | medium | call custom host functions — power depends entirely on the embedder |
| `fs-read` | medium | open paths and read files and directory listings |
| `environment` | medium | read environment variables passed by the host |
| `fd-io` | low | read/write already-open descriptors (stdio and preopens) |
| `args` | low | read the command-line arguments |
| `clocks` | low | read wall and monotonic clocks |
| `random` | low | obtain random bytes from the host |
| `process` | low | exit the instance or raise signals |
| `scheduling` | low | yield and wait on descriptors (poll) |

Two classification decisions worth knowing:

- **`fd_read`/`fd_write` are `fd-io`, not filesystem access.** On their own
  they only reach descriptors the host already opened (stdin/stdout/stderr,
  preopens). Calling them "filesystem write" would make every hello-world
  look dangerous, which trains people to ignore the report.
- **Preview 2 `wasi:filesystem/*` grants both `fs-read` and `fs-write`.**
  Preview 2 functions are methods on descriptor resources, so interface-level
  mapping cannot separate the directions; wasmscout is conservative rather
  than optimistic.

## The inference rule

`path_open` chooses its rights *at call time* — they are function
arguments, not import metadata. So a module that imports `path_open` plus
any descriptor-write primitive (`fd_write`, `fd_pwrite`, `fd_allocate`,
`fd_filestat_set_size`) can write any file it can open, even though it
imports none of the `path_*` mutation functions. wasmscout reports this as
`fs-write` marked `[inferred]`, with the reasoning in the finding message.

## Findings

| Id | Severity | Fires when |
|---|---|---|
| `wasi.fs-write` | high | file-mutating imports present, or the inference rule fires |
| `wasi.network` | high | any `sock_*` import or `wasi:sockets/`/`wasi:http/` interface |
| `wasi.fs-read` | medium | path-reading imports present |
| `wasi.environment` | medium | `environ_get`/`environ_sizes_get` or `wasi:cli/environment` |
| `host.imports` | medium | function imports from non-WASI modules |
| `module.start-function` | medium | a start section: code runs at instantiation |
| `memory.shared` | medium | any memory declares the shared (threads) flag |
| `wasi.unknown-import` | low | a WASI-looking import that is in no catalog |
| `wasi.mixed-targets` | low | imports from both `wasi_snapshot_preview1` and `wasi_unstable` |
| `memory.unbounded` | low | a memory with no declared maximum |
| `memory.large-initial` | low | initial memory ≥ 1024 pages (64 MiB) |
| `global.mutable-export` | low | an exported global that is mutable |
| `module.object-file` | low | `linking`/`reloc.*` sections: a linker input, not a module |
| `memory.imported` | info | memory comes from the host, which can observe all of it |
| `section.debug-info` | info | DWARF / `external_debug_info` sections, with size and % |
| `section.source-map` | info | a `sourceMappingURL` section, with the URL it leaks |
| `module.dynamic-linking` | info | a `dylink`/`dylink.0` section |

Low-risk capabilities (`fd-io`, `clocks`, `random`, …) appear in the
capability table but deliberately produce no finding — findings are for
things worth a human's attention, and the gate should stay quiet enough
that people keep it on.

## Exit codes and gating

| Exit code | Meaning |
|---|---|
| `0` | scanned, and no finding at or above `--fail-on` (default `high`), no denied capability |
| `1` | a finding at or above the gate, or a `--deny` capability is present |
| `2` | usage error, unreadable file, malformed binary, or a component-model binary |

`--deny` works on capability *presence* and ignores severities entirely:
`--deny network,fs-write --fail-on never` is exactly "I don't care what
else it does, it must not touch these."

## What wasmscout does not do

- It does not validate or execute code, so it cannot see what a module
  *does* with a capability — only what the host makes possible.
- Signatures of WASI imports are displayed but not checked against the
  spec's types (roadmap).
- Component-model binaries (layer 1) are detected and refused, not
  analyzed (roadmap).
