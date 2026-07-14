//! Generates the demo fixture set: small, valid, deterministic .wasm files
//! that each exercise one audit story. Usage:
//!
//! ```bash
//! cargo run --example gen_fixtures -- /tmp/wasm-fixtures
//! ```

use std::fs;
use std::path::Path;
use wasmscout::builder::{ModuleBuilder, FUNC, GLOBAL, I32, MEMORY};

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write fixture");
    println!("wrote {} ({} bytes)", path.display(), bytes.len());
}

/// A clean pure-compute module: no imports, bounded memory, named.
fn image_filter() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    let t = b.add_type(&[I32, I32], &[I32]);
    let f = b.add_function(t);
    b.add_memory(16, Some(32), false);
    b.export("apply", FUNC, f);
    b.export("memory", MEMORY, 0);
    b.producers(&[
        ("language", &[("Rust", "1.75.0")]),
        ("processed-by", &[("rustc", "1.75.0"), ("wasm-opt", "116")]),
    ]);
    b.target_features(&[('+', "simd128"), ('+', "bulk-memory")]);
    b.name_section("image_filter", &[(0, "apply")]);
    b.build()
}

/// The hero: a WASI CLI-style module that reads env, reads and writes
/// files, and ships its debug info.
fn report_writer() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    for f in [
        "environ_get",
        "environ_sizes_get",
        "path_open",
        "fd_read",
        "fd_write",
        "fd_close",
        "fd_readdir",
        "path_create_directory",
        "path_unlink_file",
        "path_rename",
        "clock_time_get",
        "random_get",
        "proc_exit",
    ] {
        b.import_wasi(f);
    }
    let t = b.add_type(&[], &[]);
    let f = b.add_function(t);
    b.add_memory(17, None, false);
    b.export("process", FUNC, f);
    b.export("memory", MEMORY, 0);
    b.producers(&[("language", &[("Rust", "1.75.0")])]);
    // Deterministic filler standing in for real data and DWARF payloads.
    b.add_data(&vec![0x2e; 52_000]);
    b.custom(".debug_info", &vec![0x2e; 18_000]);
    b.custom(".debug_str", &vec![0x2e; 6_000]);
    b.build()
}

/// Network + a start function: the module phones out and runs code at load.
fn net_agent() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    for f in [
        "sock_send",
        "sock_recv",
        "sock_shutdown",
        "poll_oneoff",
        "fd_write",
        "proc_exit",
    ] {
        b.import_wasi(f);
    }
    let t = b.add_type(&[], &[]);
    let f = b.add_function(t);
    b.set_start(f);
    b.export("run", FUNC, f);
    b.build()
}

/// No path-mutation imports anywhere — but path_open + fd_write together
/// can still write any file the module can open. The inference showcase.
fn sneaky_logger() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    for f in ["path_open", "fd_write", "fd_close", "clock_time_get"] {
        b.import_wasi(f);
    }
    let t = b.add_type(&[I32], &[]);
    let f = b.add_function(t);
    b.export("log", FUNC, f);
    b.build()
}

/// An embedder-style plugin: custom host functions, imported memory,
/// an exported mutable global.
fn host_plugin() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    let t = b.add_type(&[I32, I32], &[I32]);
    b.import_func("env", "host_log", t);
    b.import_func("env", "host_alloc", t);
    b.import_memory("env", "memory", 16, Some(256), false);
    b.import_global("env", "__stack_pointer", I32, true);
    b.add_global(I32, true);
    let f = b.add_function(t);
    b.export("plugin_main", FUNC, f);
    b.export("state", GLOBAL, 1);
    b.source_mapping_url("http://127.0.0.1:8000/plugin.wasm.map");
    b.build()
}

/// A relocatable object file that escaped the linker.
fn object_file() -> Vec<u8> {
    let mut b = ModuleBuilder::new();
    let t = b.add_type(&[], &[]);
    b.add_function(t);
    b.custom("linking", &[0x02]);
    b.custom("reloc.CODE", &[0x00, 0x00]);
    b.build()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = args
        .first()
        .map(String::as_str)
        .unwrap_or("fixtures")
        .to_string();
    let dir = Path::new(&dir);
    fs::create_dir_all(dir).expect("create fixture dir");

    write(dir, "image-filter.wasm", &image_filter());
    write(dir, "report-writer.wasm", &report_writer());
    write(dir, "net-agent.wasm", &net_agent());
    write(dir, "sneaky-logger.wasm", &sneaky_logger());
    write(dir, "host-plugin.wasm", &host_plugin());
    write(dir, "object-file.wasm", &object_file());
    write(dir, "component.wasm", &ModuleBuilder::component_header());

    // A truncated upload: the hero module with its tail cut off.
    let full = report_writer();
    write(dir, "truncated.wasm", &full[..full.len() - 4_000]);

    // An HTML error page saved as a .wasm file.
    write(
        dir,
        "not-wasm.wasm",
        b"<!doctype html><html><head><title>404 Not Found</title></head></html>",
    );
}
