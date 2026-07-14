//! Knowledge of the WASI surface: the complete preview 1 function catalog,
//! preview 2 interface prefixes, and the capability each import grants.
//!
//! Preview 1 is mapped function-by-function (all 46 of them). Preview 2
//! imports in core modules use interface-qualified module names like
//! `wasi:filesystem/types@0.2.0`; those are mapped at interface granularity,
//! conservatively (the filesystem interface grants both read and write).

use crate::caps::Capability;

/// The two module names WASI preview 1 has shipped under.
pub fn is_preview1_module(name: &str) -> bool {
    name == "wasi_snapshot_preview1" || name == "wasi_unstable"
}

/// Any module name that belongs to WASI (preview 1 or 2).
pub fn is_wasi_module(name: &str) -> bool {
    is_preview1_module(name) || name.starts_with("wasi:")
}

/// All 46 WASI preview 1 functions and the capability each one grants.
///
/// Classification notes:
/// - `fd_read`/`fd_write` and friends are `fd-io`, not filesystem access:
///   on their own they only reach descriptors the host already opened
///   (stdio, preopens). The `path_*` family is what reaches new files.
/// - Sync/allocate/set-size/set-times mutate file state, so they count as
///   `fs-write` even though they take an fd.
pub const PREVIEW1: &[(&str, Capability)] = &[
    ("args_get", Capability::Args),
    ("args_sizes_get", Capability::Args),
    ("clock_res_get", Capability::Clocks),
    ("clock_time_get", Capability::Clocks),
    ("environ_get", Capability::Environment),
    ("environ_sizes_get", Capability::Environment),
    ("fd_advise", Capability::FdIo),
    ("fd_allocate", Capability::FsWrite),
    ("fd_close", Capability::FdIo),
    ("fd_datasync", Capability::FsWrite),
    ("fd_fdstat_get", Capability::FdIo),
    ("fd_fdstat_set_flags", Capability::FsWrite),
    ("fd_fdstat_set_rights", Capability::FdIo),
    ("fd_filestat_get", Capability::FdIo),
    ("fd_filestat_set_size", Capability::FsWrite),
    ("fd_filestat_set_times", Capability::FsWrite),
    ("fd_pread", Capability::FdIo),
    ("fd_prestat_dir_name", Capability::FsRead),
    ("fd_prestat_get", Capability::FsRead),
    ("fd_pwrite", Capability::FdIo),
    ("fd_read", Capability::FdIo),
    ("fd_readdir", Capability::FsRead),
    ("fd_renumber", Capability::FdIo),
    ("fd_seek", Capability::FdIo),
    ("fd_sync", Capability::FsWrite),
    ("fd_tell", Capability::FdIo),
    ("fd_write", Capability::FdIo),
    ("path_create_directory", Capability::FsWrite),
    ("path_filestat_get", Capability::FsRead),
    ("path_filestat_set_times", Capability::FsWrite),
    ("path_link", Capability::FsWrite),
    ("path_open", Capability::FsRead),
    ("path_readlink", Capability::FsRead),
    ("path_remove_directory", Capability::FsWrite),
    ("path_rename", Capability::FsWrite),
    ("path_symlink", Capability::FsWrite),
    ("path_unlink_file", Capability::FsWrite),
    ("poll_oneoff", Capability::Scheduling),
    ("proc_exit", Capability::Process),
    ("proc_raise", Capability::Process),
    ("random_get", Capability::Random),
    ("sched_yield", Capability::Scheduling),
    ("sock_accept", Capability::Network),
    ("sock_recv", Capability::Network),
    ("sock_send", Capability::Network),
    ("sock_shutdown", Capability::Network),
];

/// Capability of a preview 1 function, or `None` for names not in the spec.
pub fn preview1_capability(field: &str) -> Option<Capability> {
    PREVIEW1
        .iter()
        .find(|(name, _)| *name == field)
        .map(|(_, cap)| *cap)
}

/// Capabilities granted by a preview 2 interface import
/// (`wasi:namespace/interface@version`). Empty when the interface is not in
/// the catalog — the caller reports it as an unknown WASI import.
pub fn preview2_capabilities(module: &str) -> Vec<Capability> {
    let rest = match module.strip_prefix("wasi:") {
        Some(rest) => rest,
        None => return Vec::new(),
    };
    let iface = rest.split('@').next().unwrap_or(rest);
    match iface {
        i if i.starts_with("filesystem/") => vec![Capability::FsRead, Capability::FsWrite],
        i if i.starts_with("sockets/") => vec![Capability::Network],
        i if i.starts_with("http/") => vec![Capability::Network],
        "cli/environment" => vec![Capability::Environment],
        "cli/exit" => vec![Capability::Process],
        i if i.starts_with("cli/std") || i.starts_with("cli/terminal") => vec![Capability::FdIo],
        "cli/run" => vec![Capability::Process],
        i if i.starts_with("io/") => vec![Capability::FdIo],
        i if i.starts_with("clocks/") => vec![Capability::Clocks],
        i if i.starts_with("random/") => vec![Capability::Random],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preview1_catalog_is_complete_and_sorted() {
        // 46 functions in preview 1 — a wrong count means we dropped or
        // duplicated one, and some import would silently map to nothing.
        assert_eq!(PREVIEW1.len(), 46);
        let names: Vec<&str> = PREVIEW1.iter().map(|(n, _)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "catalog must be sorted and duplicate-free");
    }

    #[test]
    fn path_family_maps_to_filesystem_capabilities() {
        assert_eq!(preview1_capability("path_open"), Some(Capability::FsRead));
        assert_eq!(
            preview1_capability("path_unlink_file"),
            Some(Capability::FsWrite)
        );
        assert_eq!(
            preview1_capability("path_rename"),
            Some(Capability::FsWrite)
        );
        assert_eq!(
            preview1_capability("path_readlink"),
            Some(Capability::FsRead)
        );
    }

    #[test]
    fn descriptor_io_is_not_classified_as_filesystem_access() {
        // fd_write alone is how a module prints to stdout — calling that
        // "filesystem write" would make every hello-world look dangerous.
        assert_eq!(preview1_capability("fd_write"), Some(Capability::FdIo));
        assert_eq!(preview1_capability("fd_read"), Some(Capability::FdIo));
        // ...but state-mutating fd ops do count as writes.
        assert_eq!(
            preview1_capability("fd_allocate"),
            Some(Capability::FsWrite)
        );
        assert_eq!(
            preview1_capability("fd_filestat_set_size"),
            Some(Capability::FsWrite)
        );
    }

    #[test]
    fn sockets_map_to_network_and_unknown_names_are_not_guessed() {
        for f in ["sock_accept", "sock_recv", "sock_send", "sock_shutdown"] {
            assert_eq!(preview1_capability(f), Some(Capability::Network), "{f}");
        }
        assert_eq!(preview1_capability("fd_wirte"), None); // typo stays a typo
        assert_eq!(preview1_capability("open"), None);
    }

    #[test]
    fn both_preview1_module_names_are_recognized() {
        assert!(is_preview1_module("wasi_snapshot_preview1"));
        assert!(is_preview1_module("wasi_unstable"));
        assert!(!is_preview1_module("env"));
        assert!(is_wasi_module("wasi:clocks/wall-clock@0.2.0"));
        assert!(!is_wasi_module("wasix_32v1"));
    }

    #[test]
    fn preview2_interfaces_map_at_interface_granularity() {
        // The filesystem interface grants both directions, conservatively.
        let caps = preview2_capabilities("wasi:filesystem/types@0.2.0");
        assert!(caps.contains(&Capability::FsRead));
        assert!(caps.contains(&Capability::FsWrite));
        assert_eq!(
            preview2_capabilities("wasi:sockets/tcp@0.2.0"),
            vec![Capability::Network]
        );
        assert_eq!(
            preview2_capabilities("wasi:http/outgoing-handler@0.2.0"),
            vec![Capability::Network]
        );
        assert_eq!(
            preview2_capabilities("wasi:cli/environment@0.2.0"),
            vec![Capability::Environment]
        );
        assert_eq!(
            preview2_capabilities("wasi:random/random@0.2.0"),
            vec![Capability::Random]
        );
        assert_eq!(
            preview2_capabilities("wasi:io/streams@0.2.0"),
            vec![Capability::FdIo]
        );
        // Unknown interfaces return empty — reported, never guessed.
        assert!(preview2_capabilities("wasi:nn/inference@0.2.0").is_empty());
    }
}
