//! End-to-end tests against the compiled `wasmscout` binary. Fixtures are
//! built with the crate's own deterministic wasm writer into per-test temp
//! dirs, so every run is offline and byte-identical.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use wasmscout::builder::{ModuleBuilder, FUNC, GLOBAL, I32, MEMORY};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_wasmscout")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run wasmscout")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("no exit code")
}

/// Fresh temp dir per test, cleaned up on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!("wasmscout-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A module with network + environment access and a start function.
fn net_module() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    b.import_wasi("sock_send");
    b.import_wasi("sock_recv");
    b.import_wasi("environ_get");
    let t = b.add_type(&[], &[]);
    let f = b.add_function(t);
    b.set_start(f);
    b.build()
}

/// A pure compute module: no imports, bounded memory, one export.
fn pure_module() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    let t = b.add_type(&[I32, I32], &[I32]);
    let f = b.add_function(t);
    b.add_memory(16, Some(32), false);
    b.export("apply", FUNC, f);
    b.export("memory", MEMORY, 0);
    b.producers(&[("language", &[("Rust", "1.75.0")])]);
    b.name_section("image_filter", &[(0, "apply")]);
    b.build()
}

/// The sneaky case: no path-mutation imports, but path_open + fd_write.
fn sneaky_module() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    b.import_wasi("path_open");
    b.import_wasi("fd_write");
    b.import_wasi("fd_close");
    b.import_wasi("clock_time_get");
    b.build()
}

#[test]
fn version_and_help() {
    let o = run(&["--version"]);
    assert_eq!(code(&o), 0);
    assert_eq!(
        stdout(&o).trim(),
        format!("wasmscout {}", wasmscout::VERSION)
    );
    let o = run(&["--help"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("COMMANDS:"));
    assert!(stdout(&o).contains("scan"));
    // Asking a subcommand for help must print usage, not a usage *error*.
    for args in [&["scan", "--help"][..], &["caps", "-h"][..]] {
        let o = run(args);
        assert_eq!(code(&o), 0, "{args:?} must exit 0");
        assert!(stdout(&o).contains("COMMANDS:"), "{args:?}");
    }
}

#[test]
fn no_arguments_and_unknown_commands_exit_2() {
    let o = run(&[]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("USAGE:"));
    let o = run(&["lint", "x.wasm"]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("unknown command 'lint'"));
}

#[test]
fn scan_of_a_pure_module_passes_with_no_findings() {
    let dir = TempDir::new("pure");
    let file = dir.write("pure.wasm", &pure_module());
    let o = run(&["scan", &file]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("pure compute module"), "{out}");
    assert!(out.contains("module name: \"image_filter\""), "{out}");
    assert!(out.contains("producers: language Rust 1.75.0"), "{out}");
    assert!(
        out.contains("(none — the module cannot touch the host at all)"),
        "{out}"
    );
    assert!(out.contains("gate: fail-on high → PASS"), "{out}");
}

#[test]
fn scan_of_a_network_module_fails_the_default_gate() {
    let dir = TempDir::new("net");
    let file = dir.write("net.wasm", &net_module());
    let o = run(&["scan", &file]);
    assert_eq!(code(&o), 1);
    let out = stdout(&o);
    assert!(out.contains("high[wasi.network]"), "{out}");
    assert!(out.contains("medium[module.start-function]"), "{out}");
    assert!(out.contains("gate: fail-on high → FAIL"), "{out}");
}

#[test]
fn scan_detects_the_inferred_write_combination() {
    let dir = TempDir::new("sneaky");
    let file = dir.write("sneaky.wasm", &sneaky_module());
    let o = run(&["scan", &file]);
    assert_eq!(code(&o), 1, "inferred fs-write must fail the default gate");
    let out = stdout(&o);
    assert!(out.contains("[inferred]"), "{out}");
    assert!(out.contains("high[wasi.fs-write]"), "{out}");
    assert!(out.contains("path_open"), "{out}");
}

#[test]
fn fail_on_never_and_ignore_turn_a_fail_into_a_pass() {
    let dir = TempDir::new("gates");
    let file = dir.write("net.wasm", &net_module());
    let o = run(&["scan", "--fail-on", "never", &file]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    assert!(stdout(&o).contains("gate: fail-on never → PASS"));
    // Ignoring the only high finding passes the default gate...
    let o = run(&["scan", "--ignore", "wasi.network", &file]);
    assert_eq!(code(&o), 0, "stderr: {}", stderr(&o));
    // ...but a stricter gate still trips on the medium start-function.
    let o = run(&[
        "scan",
        "--ignore",
        "wasi.network",
        "--fail-on",
        "medium",
        &file,
    ]);
    assert_eq!(code(&o), 1);
}

#[test]
fn deny_gates_on_capability_presence() {
    let dir = TempDir::new("deny");
    let net = dir.write("net.wasm", &net_module());
    let pure = dir.write("pure.wasm", &pure_module());
    let o = run(&["scan", "--fail-on", "never", "--deny", "network", &net]);
    assert_eq!(code(&o), 1);
    assert!(
        stdout(&o).contains("deny: capability 'network' is present but denied by policy"),
        "{}",
        stdout(&o)
    );
    let o = run(&[
        "scan",
        "--fail-on",
        "never",
        "--deny",
        "network,fs-write",
        &pure,
    ]);
    assert_eq!(code(&o), 0);
    // Unknown capability names are usage errors that list the valid set.
    let o = run(&["scan", "--deny", "sockets", &net]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("unknown capability 'sockets'"));
}

#[test]
fn json_output_is_one_parseable_object_per_module() {
    let dir = TempDir::new("json");
    let file = dir.write("net.wasm", &net_module());
    let o = run(&["scan", "--format", "json", &file]);
    assert_eq!(code(&o), 1, "json mode keeps the gate exit code");
    let out = stdout(&o);
    assert_eq!(out.lines().count(), 1, "one line per module: {out}");
    assert!(out.contains(r#""name":"network","risk":"high""#), "{out}");
    assert!(out.contains(r#""id":"wasi.network""#), "{out}");
    assert!(out.contains(r#""pass":false"#), "{out}");
}

#[test]
fn imports_exports_and_sections_views_render() {
    let dir = TempDir::new("views");
    let file = dir.write("pure.wasm", &pure_module());
    let o = run(&["imports", &file]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("(no imports — pure compute module)"));

    let o = run(&["exports", &file]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("apply"), "{}", stdout(&o));
    assert!(stdout(&o).contains("(i32, i32) -> i32"), "{}", stdout(&o));

    let o = run(&["sections", &file]);
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    assert!(out.contains("custom \"producers\""), "{out}");
    assert!(out.contains('%'), "{out}");

    let sneaky = dir.write("sneaky.wasm", &sneaky_module());
    let o = run(&["imports", &sneaky]);
    assert!(
        stdout(&o).contains("wasi_snapshot_preview1.path_open"),
        "{}",
        stdout(&o)
    );
}

#[test]
fn caps_prints_one_risk_ordered_line_per_module() {
    let dir = TempDir::new("caps");
    let net = dir.write("net.wasm", &net_module());
    let pure = dir.write("pure.wasm", &pure_module());
    let o = run(&["caps", &net, &pure]);
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    assert!(out.contains("net.wasm: network environment"), "{out}");
    assert!(out.contains("pure.wasm: (none)"), "{out}");
}

#[test]
fn broken_inputs_exit_2_with_a_diagnosis() {
    let dir = TempDir::new("broken");
    let missing = dir.path().join("nope.wasm");
    let o = run(&["scan", missing.to_str().unwrap()]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("cannot read"));

    let html = dir.write("page.wasm", b"<!doctype html><h1>404</h1>");
    let o = run(&["scan", &html]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("HTML"), "{}", stderr(&o));

    let component = dir.write("comp.wasm", &ModuleBuilder::component_header());
    let o = run(&["scan", &component]);
    assert_eq!(code(&o), 2);
    assert!(
        stderr(&o).contains("component-model binary"),
        "{}",
        stderr(&o)
    );

    let full = pure_module();
    let truncated = dir.write("cut.wasm", &full[..full.len() - 9]);
    let o = run(&["scan", &truncated]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("truncated"), "{}", stderr(&o));
}

#[test]
fn multi_file_scan_sums_the_severity_counts() {
    let dir = TempDir::new("multi");
    let net = dir.write("net.wasm", &net_module());
    let pure = dir.write("pure.wasm", &pure_module());
    let sneaky = dir.write("sneaky.wasm", &sneaky_module());
    let o = run(&["scan", &net, &pure, &sneaky]);
    assert_eq!(code(&o), 1);
    let out = stdout(&o);
    assert!(out.contains("summary: 3 module(s) scanned"), "{out}");
    // net: network(high) + environment(medium) + start(medium);
    // sneaky: fs-write(high) + fs-read(medium). pure: nothing.
    assert!(out.contains("2 high, 3 medium"), "{out}");
}

#[test]
fn mutable_global_exports_show_up_end_to_end() {
    let dir = TempDir::new("global");
    let mut b = ModuleBuilder::new();
    b.add_global(I32, true);
    b.export("state", GLOBAL, 0);
    let file = dir.write("g.wasm", &b.build());
    let o = run(&["scan", &file]);
    assert_eq!(code(&o), 0, "a low finding passes the default gate");
    assert!(
        stdout(&o).contains("low[global.mutable-export]"),
        "{}",
        stdout(&o)
    );
    let o = run(&["exports", &file]);
    assert!(stdout(&o).contains("mutable"), "{}", stdout(&o));
}
