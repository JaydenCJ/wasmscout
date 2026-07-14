//! A minimal wasm binary writer used by tests, examples and the smoke
//! script: it produces small, valid, deterministic modules with exactly the
//! imports and sections each scenario needs — no toolchain required.
//!
//! Call `import_*` before `add_function` so index spaces come out right;
//! `build()` emits sections in the spec's required order.

/// Value type bytes, named for readability at call sites.
pub const I32: u8 = 0x7f;
pub const I64: u8 = 0x7e;
pub const F32: u8 = 0x7d;
pub const F64: u8 = 0x7c;
pub const FUNCREF: u8 = 0x70;

/// Export kind bytes.
pub const FUNC: u8 = 0x00;
pub const TABLE: u8 = 0x01;
pub const MEMORY: u8 = 0x02;
pub const GLOBAL: u8 = 0x03;

/// Append an unsigned LEB128 value.
pub fn leb(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Append a length-prefixed UTF-8 name.
pub fn write_name(out: &mut Vec<u8>, s: &str) {
    leb(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

#[derive(Default)]
pub struct ModuleBuilder {
    types: Vec<Vec<u8>>,
    imports: Vec<Vec<u8>>,
    imported_funcs: u32,
    functions: Vec<u32>,
    memories: Vec<Vec<u8>>,
    globals: Vec<Vec<u8>>,
    exports: Vec<Vec<u8>>,
    start: Option<u32>,
    data: Vec<Vec<u8>>,
    customs: Vec<(String, Vec<u8>)>,
    wasi_type: Option<u32>,
}

impl ModuleBuilder {
    pub fn new() -> ModuleBuilder {
        ModuleBuilder::default()
    }

    /// The 8-byte header of a component-model binary (version 13, layer 1).
    pub fn component_header() -> Vec<u8> {
        b"\0asm\x0d\x00\x01\x00".to_vec()
    }

    /// Add a function type; returns its type index.
    pub fn add_type(&mut self, params: &[u8], results: &[u8]) -> u32 {
        let mut e = vec![0x60];
        leb(&mut e, params.len() as u32);
        e.extend_from_slice(params);
        leb(&mut e, results.len() as u32);
        e.extend_from_slice(results);
        self.types.push(e);
        (self.types.len() - 1) as u32
    }

    pub fn import_func(&mut self, module: &str, field: &str, type_index: u32) {
        let mut e = Vec::new();
        write_name(&mut e, module);
        write_name(&mut e, field);
        e.push(0x00);
        leb(&mut e, type_index);
        self.imports.push(e);
        self.imported_funcs += 1;
    }

    /// Import a WASI preview 1 function. The signature is a generic
    /// `(i32, i32) -> i32` — wasmscout maps capabilities by name, not type.
    pub fn import_wasi(&mut self, field: &str) {
        self.import_wasi_from("wasi_snapshot_preview1", field);
    }

    pub fn import_wasi_from(&mut self, module: &str, field: &str) {
        let t = match self.wasi_type {
            Some(t) => t,
            None => {
                let t = self.add_type(&[I32, I32], &[I32]);
                self.wasi_type = Some(t);
                t
            }
        };
        self.import_func(module, field, t);
    }

    pub fn import_memory(
        &mut self,
        module: &str,
        field: &str,
        min: u32,
        max: Option<u32>,
        shared: bool,
    ) {
        let mut e = Vec::new();
        write_name(&mut e, module);
        write_name(&mut e, field);
        e.push(0x02);
        Self::write_limits(&mut e, min, max, shared);
        self.imports.push(e);
    }

    pub fn import_global(&mut self, module: &str, field: &str, valtype: u8, mutable: bool) {
        let mut e = Vec::new();
        write_name(&mut e, module);
        write_name(&mut e, field);
        e.push(0x03);
        e.push(valtype);
        e.push(u8::from(mutable));
        self.imports.push(e);
    }

    pub fn import_table(&mut self, module: &str, field: &str, min: u32) {
        let mut e = Vec::new();
        write_name(&mut e, module);
        write_name(&mut e, field);
        e.push(0x01);
        e.push(FUNCREF);
        Self::write_limits(&mut e, min, None, false);
        self.imports.push(e);
    }

    /// Define a trivial function (empty body); returns its index in the
    /// function index space (imports included).
    pub fn add_function(&mut self, type_index: u32) -> u32 {
        self.functions.push(type_index);
        self.imported_funcs + (self.functions.len() - 1) as u32
    }

    pub fn add_memory(&mut self, min: u32, max: Option<u32>, shared: bool) {
        let mut e = Vec::new();
        Self::write_limits(&mut e, min, max, shared);
        self.memories.push(e);
    }

    /// Define a global with a zero-value init expression matching its type.
    pub fn add_global(&mut self, valtype: u8, mutable: bool) {
        let mut e = vec![valtype, u8::from(mutable)];
        match valtype {
            I64 => e.extend_from_slice(&[0x42, 0x00]),
            F32 => {
                e.push(0x43);
                e.extend_from_slice(&[0; 4]);
            }
            F64 => {
                e.push(0x44);
                e.extend_from_slice(&[0; 8]);
            }
            _ => e.extend_from_slice(&[0x41, 0x00]),
        }
        e.push(0x0b);
        self.globals.push(e);
    }

    pub fn export(&mut self, name: &str, kind: u8, index: u32) {
        let mut e = Vec::new();
        write_name(&mut e, name);
        e.push(kind);
        leb(&mut e, index);
        self.exports.push(e);
    }

    pub fn set_start(&mut self, func_index: u32) {
        self.start = Some(func_index);
    }

    /// Add an active data segment at offset 0 of memory 0.
    pub fn add_data(&mut self, bytes: &[u8]) {
        self.data.push(bytes.to_vec());
    }

    pub fn custom(&mut self, name: &str, payload: &[u8]) {
        self.customs.push((name.to_string(), payload.to_vec()));
    }

    /// Emit a spec-shaped `producers` custom section.
    pub fn producers(&mut self, fields: &[(&str, &[(&str, &str)])]) {
        let mut p = Vec::new();
        leb(&mut p, fields.len() as u32);
        for (field, values) in fields {
            write_name(&mut p, field);
            leb(&mut p, values.len() as u32);
            for (name, version) in *values {
                write_name(&mut p, name);
                write_name(&mut p, version);
            }
        }
        self.custom("producers", &p);
    }

    /// Emit a `target_features` custom section (`+feature` / `-feature`).
    pub fn target_features(&mut self, features: &[(char, &str)]) {
        let mut p = Vec::new();
        leb(&mut p, features.len() as u32);
        for (prefix, name) in features {
            p.push(*prefix as u8);
            write_name(&mut p, name);
        }
        self.custom("target_features", &p);
    }

    /// Emit a `name` custom section with a module name and function names.
    pub fn name_section(&mut self, module_name: &str, func_names: &[(u32, &str)]) {
        let mut p = Vec::new();
        let mut sub0 = Vec::new();
        write_name(&mut sub0, module_name);
        p.push(0x00);
        leb(&mut p, sub0.len() as u32);
        p.extend_from_slice(&sub0);
        if !func_names.is_empty() {
            let mut sub1 = Vec::new();
            leb(&mut sub1, func_names.len() as u32);
            for (idx, name) in func_names {
                leb(&mut sub1, *idx);
                write_name(&mut sub1, name);
            }
            p.push(0x01);
            leb(&mut p, sub1.len() as u32);
            p.extend_from_slice(&sub1);
        }
        self.custom("name", &p);
    }

    /// Emit a `sourceMappingURL` custom section.
    pub fn source_mapping_url(&mut self, url: &str) {
        let mut p = Vec::new();
        write_name(&mut p, url);
        self.custom("sourceMappingURL", &p);
    }

    fn write_limits(out: &mut Vec<u8>, min: u32, max: Option<u32>, shared: bool) {
        let mut flags = 0u8;
        if max.is_some() {
            flags |= 0x01;
        }
        if shared {
            flags |= 0x02;
        }
        out.push(flags);
        leb(out, min);
        if let Some(max) = max {
            leb(out, max);
        }
    }

    fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
        out.push(id);
        leb(out, payload.len() as u32);
        out.extend_from_slice(payload);
    }

    fn vec_section(out: &mut Vec<u8>, id: u8, entries: &[Vec<u8>]) {
        if entries.is_empty() {
            return;
        }
        let mut payload = Vec::new();
        leb(&mut payload, entries.len() as u32);
        for e in entries {
            payload.extend_from_slice(e);
        }
        Self::section(out, id, &payload);
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = b"\0asm\x01\0\0\0".to_vec();
        Self::vec_section(&mut out, 1, &self.types);
        Self::vec_section(&mut out, 2, &self.imports);
        if !self.functions.is_empty() {
            let mut payload = Vec::new();
            leb(&mut payload, self.functions.len() as u32);
            for t in &self.functions {
                leb(&mut payload, *t);
            }
            Self::section(&mut out, 3, &payload);
        }
        Self::vec_section(&mut out, 5, &self.memories);
        Self::vec_section(&mut out, 6, &self.globals);
        Self::vec_section(&mut out, 7, &self.exports);
        if let Some(start) = self.start {
            let mut payload = Vec::new();
            leb(&mut payload, start);
            Self::section(&mut out, 8, &payload);
        }
        if !self.functions.is_empty() {
            // One trivial body per defined function: no locals, `end`.
            let mut payload = Vec::new();
            leb(&mut payload, self.functions.len() as u32);
            for _ in &self.functions {
                payload.extend_from_slice(&[0x02, 0x00, 0x0b]);
            }
            Self::section(&mut out, 10, &payload);
        }
        if !self.data.is_empty() {
            let mut payload = Vec::new();
            leb(&mut payload, self.data.len() as u32);
            for segment in &self.data {
                payload.push(0x00); // active, memory 0
                payload.extend_from_slice(&[0x41, 0x00, 0x0b]); // offset: i32.const 0
                leb(&mut payload, segment.len() as u32);
                payload.extend_from_slice(segment);
            }
            Self::section(&mut out, 11, &payload);
        }
        for (name, data) in &self.customs {
            let mut payload = Vec::new();
            write_name(&mut payload, name);
            payload.extend_from_slice(data);
            Self::section(&mut out, 0, &payload);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::{parse, Parsed};

    #[test]
    fn built_modules_round_trip_through_the_parser() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32], &[]);
        b.import_wasi("fd_write");
        let f = b.add_function(t);
        b.add_memory(4, Some(8), false);
        b.add_global(I64, true);
        b.export("run", FUNC, f);
        b.export("memory", MEMORY, 0);
        b.set_start(f);
        b.producers(&[("language", &[("Rust", "1.75.0")])]);
        let bytes = b.build();
        let m = match parse(&bytes).unwrap() {
            Parsed::Core(m) => m,
            _ => panic!("expected a core module"),
        };
        assert_eq!(m.imports.len(), 1);
        assert_eq!(m.functions.len(), 1);
        assert_eq!(m.memories.len(), 1);
        assert_eq!(m.globals.len(), 1);
        assert_eq!(m.exports.len(), 2);
        assert_eq!(m.start, Some(f));
        assert!(m.custom("producers").is_some());
    }

    #[test]
    fn builds_are_byte_deterministic() {
        let make = || {
            let mut b = ModuleBuilder::new();
            b.import_wasi("path_open");
            b.import_wasi("fd_write");
            b.name_section("fixture", &[(0, "open"), (1, "write")]);
            b.build()
        };
        assert_eq!(make(), make());
    }
}
