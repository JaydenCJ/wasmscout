//! Turns a parsed module plus its capability analysis into audit findings —
//! stable ids, severities, and messages that say why each one matters.

use crate::caps::{Analysis, Capability};
use crate::custom::{classify, is_debug, parse_source_mapping_url, CustomKind};
use crate::report::human_size;
use crate::wasi;
use crate::wasm::{ImportDesc, Module, PAGE_SIZE};

/// Finding severity, ordered so `>=` means "at least as severe".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s {
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub severity: Severity,
    pub message: String,
}

/// Every finding id wasmscout can emit; `--ignore` is validated against it.
pub const KNOWN_IDS: &[&str] = &[
    "wasi.fs-write",
    "wasi.network",
    "wasi.fs-read",
    "wasi.environment",
    "wasi.unknown-import",
    "wasi.mixed-targets",
    "host.imports",
    "module.start-function",
    "module.object-file",
    "module.dynamic-linking",
    "memory.shared",
    "memory.unbounded",
    "memory.imported",
    "memory.large-initial",
    "global.mutable-export",
    "section.debug-info",
    "section.source-map",
];

/// A memory this large at instantiation is worth calling out (64 MiB).
const LARGE_INITIAL_PAGES: u64 = 1024;

/// Render up to three items, then "(+N more)".
fn list3(items: &[String]) -> String {
    let shown: Vec<&str> = items.iter().take(3).map(String::as_str).collect();
    let mut s = shown.join(", ");
    if items.len() > 3 {
        s.push_str(&format!(" (+{} more)", items.len() - 3));
    }
    s
}

pub fn run(module: &Module, analysis: &Analysis) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut push = |id: &'static str, severity: Severity, message: String| {
        findings.push(Finding {
            id,
            severity,
            message,
        });
    };

    // --- capability findings -------------------------------------------------
    for hit in &analysis.hits {
        match hit.cap {
            Capability::FsWrite => {
                let msg = match &hit.inferred {
                    Some(reason) => format!(
                        "file-write capability inferred from {}: {reason}",
                        list3(&hit.via)
                    ),
                    None => format!(
                        "imports {} file-mutating WASI function(s) ({}) — the module can create, modify or delete files under every preopened directory",
                        hit.via.len(),
                        list3(&hit.via)
                    ),
                };
                push("wasi.fs-write", Severity::High, msg);
            }
            Capability::Network => push(
                "wasi.network",
                Severity::High,
                format!(
                    "imports socket function(s) ({}) — the module can talk on the network through host-provided sockets",
                    list3(&hit.via)
                ),
            ),
            Capability::FsRead => push(
                "wasi.fs-read",
                Severity::Medium,
                format!(
                    "imports {} file-reading WASI function(s) ({}) — the module can open and read everything under the runtime's preopens",
                    hit.via.len(),
                    list3(&hit.via)
                ),
            ),
            Capability::Environment => push(
                "wasi.environment",
                Severity::Medium,
                format!(
                    "reads host environment variables ({}) — environments routinely carry tokens and keys; pass a scrubbed one",
                    list3(&hit.via)
                ),
            ),
            Capability::Host => {
                let mut modules: Vec<String> = module
                    .imports
                    .iter()
                    .filter(|i| {
                        matches!(i.desc, ImportDesc::Func { .. })
                            && !wasi::is_wasi_module(&i.module)
                    })
                    .map(|i| format!("'{}'", i.module))
                    .collect();
                modules.dedup();
                push(
                    "host.imports",
                    Severity::Medium,
                    format!(
                        "imports {} function(s) from non-WASI module(s) {} — capabilities depend entirely on what the embedder wires in",
                        hit.via.len(),
                        list3(&modules)
                    ),
                );
            }
            _ => {} // low-risk capabilities appear in the table, not as findings
        }
    }

    if !analysis.unknown_wasi.is_empty() {
        push(
            "wasi.unknown-import",
            Severity::Low,
            format!(
                "{} import(s) look like WASI but are in no catalog ({}) — a typo, or a nonstandard runtime extension",
                analysis.unknown_wasi.len(),
                list3(&analysis.unknown_wasi)
            ),
        );
    }

    let uses = |module_name: &str| {
        module
            .imports
            .iter()
            .any(|i| i.module == module_name && matches!(i.desc, ImportDesc::Func { .. }))
    };
    if uses("wasi_snapshot_preview1") && uses("wasi_unstable") {
        push(
            "wasi.mixed-targets",
            Severity::Low,
            "imports from both wasi_snapshot_preview1 and wasi_unstable — a mixed toolchain built this; some runtimes will refuse one of them".to_string(),
        );
    }

    // --- structure findings ---------------------------------------------------
    if let Some(idx) = module.start {
        push(
            "module.start-function",
            Severity::Medium,
            format!(
                "has a start function (func #{idx}) — code runs at instantiation, before any export is called"
            ),
        );
    }

    for imp in &module.imports {
        if let ImportDesc::Memory { .. } = imp.desc {
            push(
                "memory.imported",
                Severity::Info,
                format!(
                    "memory is imported from '{}' — the host provides, and can observe, the module's entire address space",
                    imp.qualified()
                ),
            );
        }
    }
    for limits in module.all_memories() {
        if limits.shared {
            push(
                "memory.shared",
                Severity::Medium,
                "declares shared memory — the module expects threads and shared-memory concurrency"
                    .to_string(),
            );
        }
        if limits.max.is_none() {
            push(
                "memory.unbounded",
                Severity::Low,
                format!(
                    "memory has no declared maximum (starts at {} pages) — it can grow to the wasm32 limit of 4 GiB unless the runtime caps it",
                    limits.min
                ),
            );
        }
        if limits.min >= LARGE_INITIAL_PAGES {
            push(
                "memory.large-initial",
                Severity::Low,
                format!(
                    "memory starts at {} pages ({}) — allocated immediately at instantiation",
                    limits.min,
                    human_size(limits.min.saturating_mul(PAGE_SIZE))
                ),
            );
        }
    }

    let mutable_exports: Vec<String> = module
        .exports
        .iter()
        .filter(|e| {
            e.kind == crate::types::ExternKind::Global
                && module.global_mutability(e.index) == Some(true)
        })
        .map(|e| e.name.clone())
        .collect();
    if !mutable_exports.is_empty() {
        push(
            "global.mutable-export",
            Severity::Low,
            format!(
                "exports {} mutable global(s) ({}) — external code can rewrite module state directly",
                mutable_exports.len(),
                list3(&mutable_exports)
            ),
        );
    }

    // --- custom-section findings ----------------------------------------------
    let debug_bytes: usize = module
        .customs
        .iter()
        .filter(|c| is_debug(classify(&c.name)))
        .map(|c| c.data.len())
        .sum();
    if debug_bytes > 0 {
        let count = module
            .customs
            .iter()
            .filter(|c| is_debug(classify(&c.name)))
            .count();
        let percent = debug_bytes * 100 / module.file_size.max(1);
        push(
            "section.debug-info",
            Severity::Info,
            format!(
                "{} of debug metadata across {count} section(s) ({percent}% of the file) — strip it before distributing",
                human_size(debug_bytes as u64)
            ),
        );
    }

    if let Some(c) = module.custom("sourceMappingURL") {
        if let Ok(url) = parse_source_mapping_url(&c.data) {
            push(
                "section.source-map",
                Severity::Info,
                format!(
                    "sourceMappingURL points at '{url}' — build paths and internal hosts leak through source maps"
                ),
            );
        }
    }

    if module
        .customs
        .iter()
        .any(|c| matches!(classify(&c.name), CustomKind::Linking | CustomKind::Reloc))
    {
        push(
            "module.object-file",
            Severity::Low,
            "contains linking/reloc section(s) — this is a relocatable object file for a linker, not a finished module".to_string(),
        );
    }

    if module
        .customs
        .iter()
        .any(|c| classify(&c.name) == CustomKind::Dylink)
    {
        push(
            "module.dynamic-linking",
            Severity::Info,
            "contains a dylink section — the module expects a dynamic loader to provide part of itself".to_string(),
        );
    }

    // Highest severity first; stable sort keeps the generation order within
    // a severity level (capabilities before structure before sections).
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{ModuleBuilder, GLOBAL, I32};
    use crate::caps::analyze;
    use crate::wasm::{parse, Parsed};

    fn findings_of(b: &ModuleBuilder) -> Vec<Finding> {
        match parse(&b.build()).unwrap() {
            Parsed::Core(m) => {
                let a = analyze(&m);
                run(&m, &a)
            }
            _ => panic!("expected a core module"),
        }
    }

    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.id).collect()
    }

    #[test]
    fn a_pure_compute_module_has_zero_findings() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32], &[I32]);
        let f = b.add_function(t);
        b.add_memory(16, Some(32), false);
        b.export("apply", 0x00, f);
        assert!(findings_of(&b).is_empty());
    }

    #[test]
    fn fs_write_is_a_high_finding_with_the_import_names() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("path_unlink_file");
        b.import_wasi("path_rename");
        let f = findings_of(&b);
        assert_eq!(f[0].id, "wasi.fs-write");
        assert_eq!(f[0].severity, Severity::High);
        assert!(
            f[0].message.contains("path_unlink_file"),
            "{}",
            f[0].message
        );
    }

    #[test]
    fn inferred_fs_write_says_so_in_the_message() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("path_open");
        b.import_wasi("fd_write");
        let f = findings_of(&b);
        let fw = f.iter().find(|f| f.id == "wasi.fs-write").unwrap();
        assert!(fw.message.contains("inferred"), "{}", fw.message);
        assert!(fw.message.contains("path_open"), "{}", fw.message);
    }

    #[test]
    fn network_and_environment_are_flagged() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("sock_send");
        b.import_wasi("environ_get");
        let f = findings_of(&b);
        assert!(ids(&f).contains(&"wasi.network"));
        assert!(ids(&f).contains(&"wasi.environment"));
    }

    #[test]
    fn start_function_is_flagged_as_medium() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[], &[]);
        let f = b.add_function(t);
        b.set_start(f);
        let found = findings_of(&b);
        let sf = found
            .iter()
            .find(|f| f.id == "module.start-function")
            .unwrap();
        assert_eq!(sf.severity, Severity::Medium);
        assert!(sf.message.contains("instantiation"), "{}", sf.message);
    }

    #[test]
    fn memory_shape_findings_fire_only_when_deserved() {
        // A bounded, unshared, modest memory: nothing to report.
        let mut b = ModuleBuilder::new();
        b.add_memory(2, Some(4), false);
        assert!(findings_of(&b).is_empty());

        let mut b = ModuleBuilder::new();
        b.add_memory(2, Some(4), true);
        assert!(ids(&findings_of(&b)).contains(&"memory.shared"));

        let mut b = ModuleBuilder::new();
        b.add_memory(17, None, false);
        let f = findings_of(&b);
        let m = f.iter().find(|f| f.id == "memory.unbounded").unwrap();
        assert!(m.message.contains("17 pages"), "{}", m.message);

        let mut b = ModuleBuilder::new();
        b.add_memory(2048, Some(4096), false); // 128 MiB up front
        let f = findings_of(&b);
        let m = f.iter().find(|f| f.id == "memory.large-initial").unwrap();
        assert!(m.message.contains("128.0 MiB"), "{}", m.message);
    }

    #[test]
    fn imported_memory_is_an_info_finding() {
        let mut b = ModuleBuilder::new();
        b.import_memory("env", "memory", 16, Some(256), false);
        let f = findings_of(&b);
        let m = f.iter().find(|f| f.id == "memory.imported").unwrap();
        assert!(m.message.contains("env.memory"), "{}", m.message);
    }

    #[test]
    fn mutable_global_export_respects_the_index_space() {
        let mut b = ModuleBuilder::new();
        b.import_global("env", "imported_const", I32, false);
        b.add_global(I32, true);
        b.export("state", GLOBAL, 1); // the defined, mutable one
        let f = findings_of(&b);
        let g = f.iter().find(|f| f.id == "global.mutable-export").unwrap();
        assert!(g.message.contains("state"), "{}", g.message);

        // Exporting the immutable import instead: no finding.
        let mut b = ModuleBuilder::new();
        b.import_global("env", "imported_const", I32, false);
        b.add_global(I32, true);
        b.export("state", GLOBAL, 0);
        assert!(!ids(&findings_of(&b)).contains(&"global.mutable-export"));
    }

    #[test]
    fn debug_sections_are_aggregated_with_a_percentage() {
        let mut b = ModuleBuilder::new();
        b.custom(".debug_info", &[0u8; 6000]);
        b.custom(".debug_str", &[0u8; 2000]);
        let f = findings_of(&b);
        let d = f.iter().find(|f| f.id == "section.debug-info").unwrap();
        assert!(d.message.contains("7.8 KiB"), "{}", d.message);
        assert!(d.message.contains("2 section(s)"), "{}", d.message);
        assert!(d.message.contains("% of the file"), "{}", d.message);
    }

    #[test]
    fn source_map_url_is_surfaced() {
        let mut b = ModuleBuilder::new();
        b.source_mapping_url("http://127.0.0.1:8000/app.wasm.map");
        let f = findings_of(&b);
        let s = f.iter().find(|f| f.id == "section.source-map").unwrap();
        assert!(s.message.contains("127.0.0.1"), "{}", s.message);
    }

    #[test]
    fn object_files_and_dylink_are_identified() {
        let mut b = ModuleBuilder::new();
        b.custom("linking", &[2]);
        b.custom("reloc.CODE", &[0, 0]);
        assert!(ids(&findings_of(&b)).contains(&"module.object-file"));

        let mut b = ModuleBuilder::new();
        b.custom("dylink.0", &[0]);
        assert!(ids(&findings_of(&b)).contains(&"module.dynamic-linking"));
    }

    #[test]
    fn mixed_targets_and_unknown_wasi_imports_are_flagged() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("fd_read");
        b.import_wasi_from("wasi_unstable", "fd_write");
        assert!(ids(&findings_of(&b)).contains(&"wasi.mixed-targets"));

        let mut b = ModuleBuilder::new();
        b.import_wasi("fd_wirte");
        let f = findings_of(&b);
        let u = f.iter().find(|f| f.id == "wasi.unknown-import").unwrap();
        assert_eq!(u.severity, Severity::Low);
        assert!(u.message.contains("fd_wirte"), "{}", u.message);
    }

    #[test]
    fn findings_sort_by_severity_and_every_id_is_in_the_catalog() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[], &[]);
        b.import_wasi("path_unlink_file");
        b.import_wasi("path_open");
        b.import_wasi("sock_send");
        b.import_wasi("environ_get");
        b.import_wasi("nonsense_call");
        b.import_wasi_from("wasi_unstable", "fd_read");
        b.import_func("env", "hook", t);
        b.import_memory("env", "memory", 2048, None, true);
        let f = b.add_function(t);
        b.set_start(f);
        b.add_global(I32, true);
        b.export("g", GLOBAL, 0);
        b.custom(".debug_info", &[0u8; 64]);
        b.source_mapping_url("app.map");
        b.custom("linking", &[2]);
        b.custom("dylink.0", &[0]);
        let found = findings_of(&b);
        assert!(
            found.len() >= 12,
            "expected a rich finding set, got {}",
            found.len()
        );
        for f in &found {
            assert!(KNOWN_IDS.contains(&f.id), "{} missing from KNOWN_IDS", f.id);
        }
        let sevs: Vec<Severity> = found.iter().map(|f| f.severity).collect();
        let mut sorted = sevs.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(sevs, sorted, "findings must sort by severity, descending");
    }

    #[test]
    fn severity_parses_and_orders() {
        assert_eq!(Severity::parse("high"), Some(Severity::High));
        assert_eq!(Severity::parse("info"), Some(Severity::Info));
        assert_eq!(Severity::parse("fatal"), None);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Info);
    }
}
