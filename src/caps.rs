//! The capability model: what a module can touch, derived from its imports.
//!
//! Capabilities are ranked by risk and each hit remembers exactly which
//! imports grant it. One inference rule runs on top of the direct mapping:
//! `path_open` plus any descriptor-write primitive means the module can
//! write files, even when no `path_*` mutation function is imported.

use crate::wasi;
use crate::wasm::{ImportDesc, Module};

/// Everything a wasm module can be granted, ordered by display priority
/// (highest risk first — the derived `Ord` follows declaration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    FsWrite,
    Network,
    Host,
    FsRead,
    Environment,
    FdIo,
    Args,
    Clocks,
    Random,
    Process,
    Scheduling,
}

/// Risk rank used for report ordering and the severity of capability findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::High => "high",
            Risk::Medium => "medium",
            Risk::Low => "low",
        }
    }
}

impl Capability {
    pub fn all() -> [Capability; 11] {
        [
            Capability::FsWrite,
            Capability::Network,
            Capability::Host,
            Capability::FsRead,
            Capability::Environment,
            Capability::FdIo,
            Capability::Args,
            Capability::Clocks,
            Capability::Random,
            Capability::Process,
            Capability::Scheduling,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Capability::FsWrite => "fs-write",
            Capability::Network => "network",
            Capability::Host => "host",
            Capability::FsRead => "fs-read",
            Capability::Environment => "environment",
            Capability::FdIo => "fd-io",
            Capability::Args => "args",
            Capability::Clocks => "clocks",
            Capability::Random => "random",
            Capability::Process => "process",
            Capability::Scheduling => "scheduling",
        }
    }

    pub fn from_name(name: &str) -> Option<Capability> {
        Capability::all().into_iter().find(|c| c.name() == name)
    }

    pub fn risk(self) -> Risk {
        match self {
            Capability::FsWrite | Capability::Network => Risk::High,
            Capability::Host | Capability::FsRead | Capability::Environment => Risk::Medium,
            _ => Risk::Low,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Capability::FsWrite => {
                "create, modify or delete files and directories under the runtime's preopens"
            }
            Capability::Network => "accept, send or receive on host-provided sockets",
            Capability::Host => {
                "call custom host functions — power depends entirely on the embedder"
            }
            Capability::FsRead => "open paths and read files and directory listings",
            Capability::Environment => "read environment variables passed by the host",
            Capability::FdIo => "read/write already-open descriptors (stdio and preopens)",
            Capability::Args => "read the command-line arguments",
            Capability::Clocks => "read wall and monotonic clocks",
            Capability::Random => "obtain random bytes from the host",
            Capability::Process => "exit the instance or raise signals",
            Capability::Scheduling => "yield and wait on descriptors (poll)",
        }
    }
}

/// One granted capability with the imports that grant it.
#[derive(Debug, Clone)]
pub struct CapabilityHit {
    pub cap: Capability,
    /// Import names: bare field names for preview 1, `module.field` otherwise.
    pub via: Vec<String>,
    /// Set when the capability was inferred from a combination, with the reason.
    pub inferred: Option<String>,
}

/// The full capability analysis of one module.
#[derive(Debug, Default)]
pub struct Analysis {
    /// Granted capabilities, highest risk first.
    pub hits: Vec<CapabilityHit>,
    /// Imports that look like WASI but are not in any catalog.
    pub unknown_wasi: Vec<String>,
}

impl Analysis {
    pub fn has(&self, cap: Capability) -> bool {
        self.hits.iter().any(|h| h.cap == cap)
    }

    pub fn get(&self, cap: Capability) -> Option<&CapabilityHit> {
        self.hits.iter().find(|h| h.cap == cap)
    }
}

/// The descriptor-write primitives that, combined with `path_open`, add up
/// to a file-write capability.
const FD_WRITERS: [&str; 4] = [
    "fd_write",
    "fd_pwrite",
    "fd_allocate",
    "fd_filestat_set_size",
];

pub fn analyze(module: &Module) -> Analysis {
    use std::collections::BTreeMap;
    let mut via: BTreeMap<Capability, Vec<String>> = BTreeMap::new();
    let mut unknown = Vec::new();
    let mut p1_fields: Vec<String> = Vec::new();

    let record = |map: &mut BTreeMap<Capability, Vec<String>>, cap: Capability, name: String| {
        let list = map.entry(cap).or_default();
        if !list.contains(&name) {
            list.push(name);
        }
    };

    for imp in &module.imports {
        if !matches!(imp.desc, ImportDesc::Func { .. }) {
            continue; // memories/tables/globals are structural, not capabilities
        }
        if wasi::is_preview1_module(&imp.module) {
            p1_fields.push(imp.field.clone());
            match wasi::preview1_capability(&imp.field) {
                Some(cap) => record(&mut via, cap, imp.field.clone()),
                None => unknown.push(imp.qualified()),
            }
        } else if imp.module.starts_with("wasi:") {
            let caps = wasi::preview2_capabilities(&imp.module);
            if caps.is_empty() {
                unknown.push(imp.qualified());
            }
            for cap in caps {
                record(&mut via, cap, imp.qualified());
            }
        } else {
            record(&mut via, Capability::Host, imp.qualified());
        }
    }

    let mut hits: Vec<CapabilityHit> = via
        .into_iter()
        .map(|(cap, via)| CapabilityHit {
            cap,
            via,
            inferred: None,
        })
        .collect();

    // Inference: path_open chooses its rights at call time. Together with a
    // descriptor-write primitive the module can write any file it can open —
    // no path_unlink/path_rename import required.
    let has = |name: &str| p1_fields.iter().any(|f| f == name);
    if !hits.iter().any(|h| h.cap == Capability::FsWrite) && has("path_open") {
        if let Some(writer) = FD_WRITERS.iter().find(|w| has(w)) {
            hits.push(CapabilityHit {
                cap: Capability::FsWrite,
                via: vec!["path_open".to_string(), (*writer).to_string()],
                inferred: Some(format!(
                    "path_open chooses rights at call time; combined with {writer} the module can write any file it can open"
                )),
            });
            hits.sort_by_key(|h| h.cap);
        }
    }

    Analysis {
        hits,
        unknown_wasi: unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{ModuleBuilder, I32};
    use crate::wasm::{parse, Parsed};

    fn analyze_built(b: &ModuleBuilder) -> Analysis {
        match parse(&b.build()).unwrap() {
            Parsed::Core(m) => analyze(&m),
            _ => panic!("expected a core module"),
        }
    }

    #[test]
    fn fd_write_alone_is_fd_io_not_filesystem() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("fd_write");
        b.import_wasi("proc_exit");
        let a = analyze_built(&b);
        assert!(a.has(Capability::FdIo));
        assert!(!a.has(Capability::FsWrite));
        assert!(!a.has(Capability::FsRead));
    }

    #[test]
    fn path_mutation_grants_fs_write_directly() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("path_unlink_file");
        let a = analyze_built(&b);
        let hit = a.get(Capability::FsWrite).unwrap();
        assert_eq!(hit.via, vec!["path_unlink_file"]);
        assert!(hit.inferred.is_none());
    }

    #[test]
    fn path_open_plus_fd_write_infers_fs_write() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("path_open");
        b.import_wasi("fd_write");
        let a = analyze_built(&b);
        let hit = a.get(Capability::FsWrite).unwrap();
        assert!(hit.inferred.is_some(), "must be marked as inferred");
        assert!(hit.via.contains(&"path_open".to_string()));
        assert!(hit.via.contains(&"fd_write".to_string()));
    }

    #[test]
    fn path_open_alone_stays_read_only() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("path_open");
        b.import_wasi("fd_read");
        let a = analyze_built(&b);
        assert!(a.has(Capability::FsRead));
        assert!(!a.has(Capability::FsWrite));
    }

    #[test]
    fn non_wasi_function_imports_are_host_capability() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32], &[]);
        b.import_func("env", "host_log", t);
        b.import_func("env", "host_alloc", t);
        let a = analyze_built(&b);
        let hit = a.get(Capability::Host).unwrap();
        assert_eq!(hit.via, vec!["env.host_log", "env.host_alloc"]);
    }

    #[test]
    fn structural_imports_grant_no_capability() {
        let mut b = ModuleBuilder::new();
        b.import_memory("env", "memory", 16, None, false);
        b.import_global("env", "__stack_pointer", I32, true);
        b.import_table("env", "table", 4);
        let a = analyze_built(&b);
        assert!(a.hits.is_empty());
    }

    #[test]
    fn hits_are_ordered_by_risk_and_deduplicated() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("clock_time_get"); // low
        b.import_wasi("environ_get"); // medium
        b.import_wasi("sock_send"); // high
        let a = analyze_built(&b);
        let order: Vec<&str> = a.hits.iter().map(|h| h.cap.name()).collect();
        assert_eq!(order, vec!["network", "environment", "clocks"]);
        // Duplicate imports are legal wasm; the report should not stutter.
        let mut b = ModuleBuilder::new();
        b.import_wasi("random_get");
        b.import_wasi("random_get");
        let a = analyze_built(&b);
        assert_eq!(a.get(Capability::Random).unwrap().via, vec!["random_get"]);
    }

    #[test]
    fn unknown_wasi_names_are_collected_and_catalog_names_round_trip() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("fd_wirte"); // typo
        b.import_wasi_from("wasi:nn/inference@0.2.0", "compute");
        let a = analyze_built(&b);
        assert_eq!(a.unknown_wasi.len(), 2);
        assert!(a.hits.is_empty());
        for cap in Capability::all() {
            assert_eq!(Capability::from_name(cap.name()), Some(cap));
        }
        assert_eq!(Capability::from_name("filesystem"), None);
    }
}
