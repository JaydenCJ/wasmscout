//! Command-line surface: argument parsing, subcommand dispatch, exit codes.
//!
//! Exit codes: `0` — scan passed the gate; `1` — findings at or above the
//! gate, or a denied capability is present; `2` — usage error, unreadable
//! file, malformed binary, or a component (not audited in 0.1.0).

use crate::audit::{self, Finding, Severity, KNOWN_IDS};
use crate::caps::{analyze, Capability};
use crate::report;
use crate::wasm::{self, Module, Parsed};

const USAGE: &str = "\
wasmscout — audit a WebAssembly binary before you run it

USAGE:
    wasmscout <COMMAND> [OPTIONS] <FILE>...

COMMANDS:
    scan        full audit: identity, capabilities, findings, CI gate
    caps        one line per module: the granted capability list
    imports     every import with kind and signature
    exports     every export with kind and signature
    sections    per-section size breakdown

OPTIONS (scan):
    --format <text|json>    output format; json emits one object per module
    --fail-on <SEVERITY>    exit 1 at or above: high (default), medium, low, info, never
    --deny <CAPS>           comma-separated capabilities that force exit 1 if present
    --ignore <IDS>          comma-separated finding ids to suppress

GLOBAL:
    -h, --help              print this help
    -V, --version           print version
";

/// Print a line to stdout. When the reader has gone away (for example
/// `wasmscout scan dir/*.wasm | head`), exit like a SIGPIPE-terminated
/// process (128+13) instead of panicking mid-report.
fn emit(text: &str) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    if writeln!(stdout, "{text}").is_err() {
        std::process::exit(141);
    }
}

pub fn run(args: &[String]) -> i32 {
    let Some(command) = args.first() else {
        eprint!("{USAGE}");
        return 2;
    };
    let rest = &args[1..];
    match command.as_str() {
        "-V" | "--version" => {
            emit(&format!("wasmscout {}", crate::VERSION));
            0
        }
        "-h" | "--help" => {
            emit(USAGE.trim_end_matches('\n'));
            0
        }
        "scan" => cmd_scan(rest),
        "caps" => cmd_view(rest, View::Caps),
        "imports" => cmd_view(rest, View::Imports),
        "exports" => cmd_view(rest, View::Exports),
        "sections" => cmd_view(rest, View::Sections),
        other => {
            eprintln!("wasmscout: unknown command '{other}' (see --help)");
            2
        }
    }
}

fn usage_error(message: &str) -> i32 {
    eprintln!("wasmscout: {message}");
    2
}

/// Read and parse one file into a core module, or a printable error.
fn load_core(path: &str) -> Result<Module, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: cannot read: {e}"))?;
    match wasm::parse(&bytes) {
        Ok(Parsed::Core(module)) => Ok(*module),
        Ok(Parsed::Component { version }) => Err(format!(
            "{path}: component-model binary (layer 1, encoding version {version}) — wasmscout 0.1.0 audits core modules; component support is on the roadmap"
        )),
        Err(e) => Err(format!("{path}: parse error at {e}")),
    }
}

#[derive(Debug)]
struct ScanOpts {
    json: bool,
    /// `None` means `--fail-on never`.
    fail_on: Option<Severity>,
    deny: Vec<Capability>,
    ignore: Vec<String>,
    files: Vec<String>,
}

/// `-h`/`--help` after a subcommand prints the usage instead of tripping
/// the unknown-option error — asking for help must never exit non-zero.
fn wants_help(args: &[String]) -> bool {
    args.iter().any(|a| a == "-h" || a == "--help")
}

fn parse_scan_opts(args: &[String]) -> Result<ScanOpts, String> {
    let mut opts = ScanOpts {
        json: false,
        fail_on: Some(Severity::High),
        deny: Vec::new(),
        ignore: Vec::new(),
        files: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--format" => match it.next().map(String::as_str) {
                Some("text") => opts.json = false,
                Some("json") => opts.json = true,
                Some(other) => return Err(format!("--format must be text or json, got '{other}'")),
                None => return Err("--format needs a value".to_string()),
            },
            "--fail-on" => match it.next().map(String::as_str) {
                Some("never") => opts.fail_on = None,
                Some(s) => match Severity::parse(s) {
                    Some(sev) => opts.fail_on = Some(sev),
                    None => {
                        return Err(format!(
                            "--fail-on must be high, medium, low, info or never, got '{s}'"
                        ))
                    }
                },
                None => return Err("--fail-on needs a value".to_string()),
            },
            "--deny" => {
                let Some(value) = it.next() else {
                    return Err("--deny needs a value".to_string());
                };
                for name in value.split(',').filter(|s| !s.is_empty()) {
                    match Capability::from_name(name) {
                        Some(cap) => opts.deny.push(cap),
                        None => {
                            let valid: Vec<&str> =
                                Capability::all().iter().map(|c| c.name()).collect();
                            return Err(format!(
                                "--deny: unknown capability '{name}' (valid: {})",
                                valid.join(", ")
                            ));
                        }
                    }
                }
            }
            "--ignore" => {
                let Some(value) = it.next() else {
                    return Err("--ignore needs a value".to_string());
                };
                for id in value.split(',').filter(|s| !s.is_empty()) {
                    if !KNOWN_IDS.contains(&id) {
                        return Err(format!(
                            "--ignore: unknown finding id '{id}' (the full catalog is in docs/capabilities.md)"
                        ));
                    }
                    opts.ignore.push(id.to_string());
                }
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}' (see --help)"))
            }
            file => opts.files.push(file.to_string()),
        }
    }
    if opts.files.is_empty() {
        return Err("scan needs at least one .wasm file".to_string());
    }
    Ok(opts)
}

fn cmd_scan(args: &[String]) -> i32 {
    if wants_help(args) {
        emit(USAGE.trim_end_matches('\n'));
        return 0;
    }
    let opts = match parse_scan_opts(args) {
        Ok(opts) => opts,
        Err(message) => return usage_error(&message),
    };

    let mut had_error = false;
    let mut any_failed = false;
    let mut scanned = 0usize;
    let mut counts = [0usize; 4]; // info, low, medium, high
    let mut text_blocks: Vec<String> = Vec::new();

    for path in &opts.files {
        let module = match load_core(path) {
            Ok(m) => m,
            Err(message) => {
                eprintln!("wasmscout: {message}");
                had_error = true;
                continue;
            }
        };
        let analysis = analyze(&module);
        let findings: Vec<Finding> = audit::run(&module, &analysis)
            .into_iter()
            .filter(|f| !opts.ignore.iter().any(|ig| ig == f.id))
            .collect();

        let gated = match opts.fail_on {
            Some(gate) => findings.iter().any(|f| f.severity >= gate),
            None => false,
        };
        let denied: Vec<Capability> = opts
            .deny
            .iter()
            .copied()
            .filter(|cap| analysis.has(*cap))
            .collect();
        let pass = !gated && denied.is_empty();
        if !pass {
            any_failed = true;
        }
        scanned += 1;
        for f in &findings {
            counts[f.severity as usize] += 1;
        }

        if opts.json {
            emit(&report::render_scan_json(
                path,
                &module,
                &analysis,
                &findings,
                pass,
                &gate_label(opts.fail_on),
            ));
        } else {
            let mut block = report::render_scan(path, &module, &analysis, &findings);
            for cap in &denied {
                block.push_str(&format!(
                    "  deny: capability '{}' is present but denied by policy\n",
                    cap.name()
                ));
            }
            text_blocks.push(block);
        }
    }

    if !opts.json && scanned > 0 {
        emit(&text_blocks.join("\n"));
        emit(&format!(
            "summary: {scanned} module(s) scanned — {} high, {} medium, {} low, {} info · gate: fail-on {} → {}",
            counts[Severity::High as usize],
            counts[Severity::Medium as usize],
            counts[Severity::Low as usize],
            counts[Severity::Info as usize],
            gate_label(opts.fail_on),
            if any_failed { "FAIL" } else { "PASS" }
        ));
    }

    if had_error {
        2
    } else if any_failed {
        1
    } else {
        0
    }
}

fn gate_label(fail_on: Option<Severity>) -> String {
    match fail_on {
        Some(sev) => sev.label().to_string(),
        None => "never".to_string(),
    }
}

enum View {
    Caps,
    Imports,
    Exports,
    Sections,
}

fn cmd_view(args: &[String], view: View) -> i32 {
    if wants_help(args) {
        emit(USAGE.trim_end_matches('\n'));
        return 0;
    }
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if let Some(flag) = args.iter().find(|a| a.starts_with('-')) {
        return usage_error(&format!("unknown option '{flag}' (see --help)"));
    }
    if files.is_empty() {
        return usage_error("this command needs at least one .wasm file");
    }
    let mut had_error = false;
    let mut blocks: Vec<String> = Vec::new();
    for path in &files {
        match load_core(path) {
            Ok(module) => {
                let block = match view {
                    View::Caps => report::render_caps_line(path, &analyze(&module)),
                    View::Imports => report::render_imports(path, &module),
                    View::Exports => report::render_exports(path, &module),
                    View::Sections => report::render_sections(path, &module),
                };
                blocks.push(block.trim_end().to_string());
            }
            Err(message) => {
                eprintln!("wasmscout: {message}");
                had_error = true;
            }
        }
    }
    if !blocks.is_empty() {
        // caps is one line per module; the other views are multi-line blocks.
        let separator = if matches!(view, View::Caps) {
            "\n"
        } else {
            "\n\n"
        };
        emit(&blocks.join(separator));
    }
    if had_error {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scan_opts_defaults_are_text_and_fail_on_high() {
        let opts = parse_scan_opts(&strings(&["a.wasm"])).unwrap();
        assert!(!opts.json);
        assert_eq!(opts.fail_on, Some(Severity::High));
        assert!(opts.deny.is_empty());
        assert_eq!(opts.files, vec!["a.wasm"]);
    }

    #[test]
    fn scan_opts_parse_every_option() {
        let opts = parse_scan_opts(&strings(&[
            "--format",
            "json",
            "--fail-on",
            "medium",
            "--deny",
            "network,fs-write",
            "--ignore",
            "memory.unbounded",
            "a.wasm",
            "b.wasm",
        ]))
        .unwrap();
        assert!(opts.json);
        assert_eq!(opts.fail_on, Some(Severity::Medium));
        assert_eq!(opts.deny, vec![Capability::Network, Capability::FsWrite]);
        assert_eq!(opts.ignore, vec!["memory.unbounded"]);
        assert_eq!(opts.files.len(), 2);
    }

    #[test]
    fn scan_opts_reject_unknown_values_with_guidance() {
        let err = parse_scan_opts(&strings(&["--deny", "networking", "a.wasm"])).unwrap_err();
        assert!(err.contains("unknown capability"), "{err}");
        assert!(err.contains("network"), "must list valid names: {err}");

        let err = parse_scan_opts(&strings(&["--ignore", "wasi.bogus", "a.wasm"])).unwrap_err();
        assert!(err.contains("unknown finding id"), "{err}");

        let err = parse_scan_opts(&strings(&["--fail-on", "fatal", "a.wasm"])).unwrap_err();
        assert!(err.contains("high, medium, low, info or never"), "{err}");
    }

    #[test]
    fn scan_opts_fail_on_never_disables_the_gate_and_files_are_required() {
        let opts = parse_scan_opts(&strings(&["--fail-on", "never", "a.wasm"])).unwrap();
        assert_eq!(opts.fail_on, None);
        assert_eq!(gate_label(opts.fail_on), "never");
        let err = parse_scan_opts(&strings(&["--format", "json"])).unwrap_err();
        assert!(err.contains("at least one"), "{err}");
    }
}
