//! Parser for the core WebAssembly binary format, tolerant where an auditor
//! must be: unknown value types, post-MVP sections and undecodable constant
//! expressions are recorded and skipped, never fatal. Only structural lies —
//! section sizes past the end of the file, impossible vector counts, overlong
//! LEB128 — abort a parse, with the exact byte offset in the error.

use crate::reader::{ParseError, Reader, Result};
use crate::types::{section_name, ExternKind, FuncType, Limits, ValType};

/// wasm32 page size in bytes.
pub const PAGE_SIZE: u64 = 65_536;

/// What the 8-byte header said the file is.
#[derive(Debug)]
pub enum Parsed {
    /// A core module (version 1, layer 0), fully parsed.
    Core(Box<Module>),
    /// A component-model binary (layer 1); not analyzed in 0.1.0.
    Component { version: u16 },
}

#[derive(Debug, Clone)]
pub struct Import {
    pub module: String,
    pub field: String,
    pub desc: ImportDesc,
}

impl Import {
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.module, self.field)
    }
}

#[derive(Debug, Clone)]
pub enum ImportDesc {
    Func { type_index: u32 },
    Table { reftype: ValType, limits: Limits },
    Memory { limits: Limits },
    Global { valtype: ValType, mutable: bool },
    Tag { type_index: u32 },
}

impl ImportDesc {
    pub fn kind(&self) -> ExternKind {
        match self {
            ImportDesc::Func { .. } => ExternKind::Func,
            ImportDesc::Table { .. } => ExternKind::Table,
            ImportDesc::Memory { .. } => ExternKind::Memory,
            ImportDesc::Global { .. } => ExternKind::Global,
            ImportDesc::Tag { .. } => ExternKind::Tag,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub kind: ExternKind,
    pub index: u32,
}

/// One section as it appeared in the file, for the size breakdown.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub id: u8,
    pub custom_name: Option<String>,
    /// Offset of the section id byte.
    pub offset: usize,
    /// Payload size in bytes (excludes the id + size framing).
    pub size: usize,
}

impl SectionInfo {
    pub fn label(&self) -> String {
        match &self.custom_name {
            Some(name) => format!("custom \"{name}\""),
            None => section_name(self.id).to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CustomSection {
    pub name: String,
    pub offset: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalDecl {
    pub valtype: ValType,
    pub mutable: bool,
}

/// Everything the audit needs from a parsed core module.
#[derive(Debug, Default)]
pub struct Module {
    pub file_size: usize,
    pub sections: Vec<SectionInfo>,
    pub types: Vec<FuncType>,
    /// True when the type section contained post-MVP (GC) entries we skipped.
    pub types_partial: bool,
    pub imports: Vec<Import>,
    /// Type index of each function defined in this module.
    pub functions: Vec<u32>,
    pub table_count: u32,
    pub memories: Vec<Limits>,
    pub globals: Vec<GlobalDecl>,
    pub global_count: u32,
    /// True when a global's init expression used an opcode we do not decode.
    pub globals_partial: bool,
    pub exports: Vec<Export>,
    pub start: Option<u32>,
    pub element_count: Option<u32>,
    pub code_count: Option<u32>,
    pub data_count: Option<u32>,
    pub customs: Vec<CustomSection>,
}

impl Module {
    pub fn custom(&self, name: &str) -> Option<&CustomSection> {
        self.customs.iter().find(|c| c.name == name)
    }

    /// Memory limits of every memory the module touches: imported first
    /// (index space order), then defined.
    pub fn all_memories(&self) -> Vec<Limits> {
        let mut all: Vec<Limits> = self
            .imports
            .iter()
            .filter_map(|i| match i.desc {
                ImportDesc::Memory { limits } => Some(limits),
                _ => None,
            })
            .collect();
        all.extend(self.memories.iter().copied());
        all
    }

    /// Mutability of a global by its index in the global index space
    /// (imports first, then defined). `None` when the global section was
    /// only partially decoded and the index falls in the unknown tail.
    pub fn global_mutability(&self, index: u32) -> Option<bool> {
        let imported: Vec<bool> = self
            .imports
            .iter()
            .filter_map(|i| match i.desc {
                ImportDesc::Global { mutable, .. } => Some(mutable),
                _ => None,
            })
            .collect();
        let idx = index as usize;
        if idx < imported.len() {
            return Some(imported[idx]);
        }
        self.globals.get(idx - imported.len()).map(|g| g.mutable)
    }

    /// Signature of a function by its index in the function index space
    /// (imports first, then defined).
    pub fn func_signature(&self, index: u32) -> Option<&FuncType> {
        let imported: Vec<u32> = self
            .imports
            .iter()
            .filter_map(|i| match i.desc {
                ImportDesc::Func { type_index } => Some(type_index),
                _ => None,
            })
            .collect();
        let idx = index as usize;
        let type_index = if idx < imported.len() {
            imported[idx]
        } else {
            *self.functions.get(idx - imported.len())?
        };
        self.types.get(type_index as usize)
    }
}

/// Best-effort identification of a non-wasm file for a friendly error.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x7fELF") {
        return Some("an ELF executable");
    }
    if bytes.starts_with(b"MZ") {
        return Some("a Windows PE executable");
    }
    if bytes.starts_with(b"\x1f\x8b") {
        return Some("a gzip archive");
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return Some("a ZIP archive");
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
    let trimmed = head.trim_start();
    if trimmed.starts_with("(module") || trimmed.starts_with("(component") {
        return Some("WebAssembly text format (.wat) — compile it to a binary first");
    }
    if trimmed.starts_with('<') {
        return Some("an HTML/XML document (a saved error page?)");
    }
    None
}

/// Parse a wasm binary. Components are detected and returned unanalyzed;
/// anything that is not wasm at all is an error that says what it looks like.
pub fn parse(bytes: &[u8]) -> Result<Parsed> {
    if bytes.len() < 8 {
        return Err(ParseError::new(
            0,
            format!(
                "file is {} byte(s) — too small for the 8-byte wasm header",
                bytes.len()
            ),
        ));
    }
    if &bytes[0..4] != b"\0asm" {
        let hint = sniff(bytes)
            .map(|what| format!(" — this looks like {what}"))
            .unwrap_or_default();
        return Err(ParseError::new(
            0,
            format!(
                "bad magic {:02x} {:02x} {:02x} {:02x}, expected 00 61 73 6d (\"\\0asm\"){hint}",
                bytes[0], bytes[1], bytes[2], bytes[3]
            ),
        ));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    let layer = u16::from_le_bytes([bytes[6], bytes[7]]);
    if layer == 1 {
        return Ok(Parsed::Component { version });
    }
    if layer != 0 || version != 1 {
        return Err(ParseError::new(
            4,
            format!(
                "unsupported wasm version {version} (layer {layer}); wasmscout understands core modules (version 1, layer 0)"
            ),
        ));
    }

    let mut m = Module {
        file_size: bytes.len(),
        ..Module::default()
    };
    let mut r = Reader::new(bytes);
    r.skip(8).expect("header length checked above");

    while !r.is_empty() {
        let sec_offset = r.offset();
        let id = r.byte()?;
        let size = r.leb_u32()? as usize;
        if size > r.remaining() {
            return Err(ParseError::new(
                sec_offset,
                format!(
                    "{} section claims {size} byte(s) but only {} remain — the file is truncated",
                    section_name(id),
                    r.remaining()
                ),
            ));
        }
        let mut body = r.slice(size)?;
        let mut custom_name = None;
        match id {
            0 => {
                let name = body.name()?;
                custom_name = Some(name.clone());
                let data = body.bytes(body.remaining())?.to_vec();
                m.customs.push(CustomSection {
                    name,
                    offset: sec_offset,
                    data,
                });
            }
            1 => parse_types(&mut body, &mut m)?,
            2 => parse_imports(&mut body, &mut m)?,
            3 => parse_functions(&mut body, &mut m)?,
            4 => m.table_count = body.leb_u32()?,
            5 => parse_memories(&mut body, &mut m)?,
            6 => parse_globals(&mut body, &mut m)?,
            7 => parse_exports(&mut body, &mut m)?,
            8 => m.start = Some(body.leb_u32()?),
            9 => m.element_count = Some(body.leb_u32()?),
            10 => m.code_count = Some(body.leb_u32()?),
            11 => {
                if m.data_count.is_none() {
                    m.data_count = Some(body.leb_u32()?);
                }
            }
            12 => m.data_count = Some(body.leb_u32()?),
            _ => {} // post-MVP section: recorded below, contents skipped
        }
        m.sections.push(SectionInfo {
            id,
            custom_name,
            offset: sec_offset,
            size,
        });
    }
    Ok(Parsed::Core(Box::new(m)))
}

fn parse_types(r: &mut Reader, m: &mut Module) -> Result<()> {
    let count = r.leb_u32()?;
    r.check_count(count, 3, "type")?;
    for _ in 0..count {
        let tag = r.byte()?;
        if tag != 0x60 {
            // GC rec-groups and friends: signatures past this point are
            // unknown, but the audit continues — signatures render as "?".
            m.types_partial = true;
            r.skip(r.remaining())?;
            break;
        }
        let mut ft = FuncType::default();
        let params = r.leb_u32()?;
        r.check_count(params, 1, "param")?;
        for _ in 0..params {
            ft.params.push(ValType::from_byte(r.byte()?));
        }
        let results = r.leb_u32()?;
        r.check_count(results, 1, "result")?;
        for _ in 0..results {
            ft.results.push(ValType::from_byte(r.byte()?));
        }
        m.types.push(ft);
    }
    Ok(())
}

fn parse_limits(r: &mut Reader) -> Result<Limits> {
    let flags = r.byte()?;
    let has_max = flags & 0x01 != 0;
    let shared = flags & 0x02 != 0;
    let memory64 = flags & 0x04 != 0;
    let min = r.leb_u64()?;
    let max = if has_max { Some(r.leb_u64()?) } else { None };
    Ok(Limits {
        min,
        max,
        shared,
        memory64,
    })
}

fn parse_imports(r: &mut Reader, m: &mut Module) -> Result<()> {
    let count = r.leb_u32()?;
    r.check_count(count, 4, "import")?;
    for _ in 0..count {
        let module = r.name()?;
        let field = r.name()?;
        let kind = r.byte()?;
        let desc = match kind {
            0x00 => ImportDesc::Func {
                type_index: r.leb_u32()?,
            },
            0x01 => {
                let reftype = ValType::from_byte(r.byte()?);
                ImportDesc::Table {
                    reftype,
                    limits: parse_limits(r)?,
                }
            }
            0x02 => ImportDesc::Memory {
                limits: parse_limits(r)?,
            },
            0x03 => {
                let valtype = ValType::from_byte(r.byte()?);
                let mutable = r.byte()? == 1;
                ImportDesc::Global { valtype, mutable }
            }
            0x04 => {
                let _attribute = r.byte()?;
                ImportDesc::Tag {
                    type_index: r.leb_u32()?,
                }
            }
            other => {
                return Err(ParseError::new(
                    r.offset().saturating_sub(1),
                    format!("import '{module}.{field}' has unknown kind 0x{other:02x}"),
                ))
            }
        };
        m.imports.push(Import {
            module,
            field,
            desc,
        });
    }
    Ok(())
}

fn parse_functions(r: &mut Reader, m: &mut Module) -> Result<()> {
    let count = r.leb_u32()?;
    r.check_count(count, 1, "function")?;
    for _ in 0..count {
        m.functions.push(r.leb_u32()?);
    }
    Ok(())
}

fn parse_memories(r: &mut Reader, m: &mut Module) -> Result<()> {
    let count = r.leb_u32()?;
    r.check_count(count, 2, "memory")?;
    for _ in 0..count {
        let limits = parse_limits(r)?;
        m.memories.push(limits);
    }
    Ok(())
}

fn parse_globals(r: &mut Reader, m: &mut Module) -> Result<()> {
    let count = r.leb_u32()?;
    r.check_count(count, 3, "global")?;
    m.global_count = count;
    for _ in 0..count {
        let valtype = ValType::from_byte(r.byte()?);
        let mutable = r.byte()? == 1;
        if !skip_const_expr(r)? {
            // Unknown opcode in the init expression: keep the globals parsed
            // so far, skip to the section end (its length is known).
            m.globals_partial = true;
            r.skip(r.remaining())?;
            return Ok(());
        }
        m.globals.push(GlobalDecl { valtype, mutable });
    }
    Ok(())
}

/// Walk a constant expression. Returns `Ok(false)` on an opcode we do not
/// decode, in which case the caller abandons the rest of the section.
fn skip_const_expr(r: &mut Reader) -> Result<bool> {
    loop {
        let op = r.byte()?;
        match op {
            0x0b => return Ok(true), // end
            0x41 | 0x42 => {
                r.leb_s64()?; // i32.const / i64.const
            }
            0x43 => r.skip(4)?, // f32.const
            0x44 => r.skip(8)?, // f64.const
            0x23 => {
                r.leb_u32()?; // global.get
            }
            0xd0 => {
                r.leb_s64()?; // ref.null <heaptype>
            }
            0xd2 => {
                r.leb_u32()?; // ref.func
            }
            0x6a..=0x6c => {} // i32.add/sub/mul (extended const)
            0x7c..=0x7e => {} // i64.add/sub/mul (extended const)
            0xfd => {
                // v128.const is SIMD sub-opcode 12 followed by 16 bytes.
                if r.leb_u32()? == 12 {
                    r.skip(16)?;
                } else {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
}

fn parse_exports(r: &mut Reader, m: &mut Module) -> Result<()> {
    let count = r.leb_u32()?;
    r.check_count(count, 3, "export")?;
    for _ in 0..count {
        let name = r.name()?;
        let kind = ExternKind::from_byte(r.byte()?);
        let index = r.leb_u32()?;
        m.exports.push(Export { name, kind, index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{ModuleBuilder, I32, I64, MEMORY};

    fn core(bytes: &[u8]) -> Module {
        match parse(bytes).expect("parse failed") {
            Parsed::Core(m) => *m,
            Parsed::Component { .. } => panic!("unexpected component"),
        }
    }

    #[test]
    fn minimal_module_parses_with_zero_sections() {
        let m = core(b"\0asm\x01\0\0\0");
        assert!(m.sections.is_empty());
        assert!(m.imports.is_empty());
        assert_eq!(m.file_size, 8);
    }

    #[test]
    fn non_wasm_files_are_identified_not_just_rejected() {
        let err = parse(b"\x01asm\x01\0\0\0").unwrap_err();
        assert!(err.message.contains("bad magic"), "{}", err.message);
        assert!(err.message.contains("01 61 73 6d"), "{}", err.message);
        let err = parse(b"\0asm").unwrap_err();
        assert!(err.message.contains("4 byte(s)"), "{}", err.message);
        assert!(sniff(b"\x7fELF____").unwrap().contains("ELF"));
        assert!(sniff(b"\x1f\x8b______").unwrap().contains("gzip"));
        assert!(sniff(b"PK\x03\x04____").unwrap().contains("ZIP"));
        assert!(sniff(b"  <!doctype html>").unwrap().contains("HTML"));
        assert!(sniff(b"(module (func))").unwrap().contains(".wat"));
        assert_eq!(sniff(b"random junk bytes"), None);
    }

    #[test]
    fn component_layer_is_detected_not_parsed() {
        let bytes = ModuleBuilder::component_header();
        match parse(&bytes).unwrap() {
            Parsed::Component { version } => assert_eq!(version, 13),
            Parsed::Core(_) => panic!("component parsed as core module"),
        }
    }

    #[test]
    fn unsupported_core_version_is_rejected() {
        let err = parse(b"\0asm\x02\0\0\0").unwrap_err();
        assert!(err.message.contains("version 2"), "{}", err.message);
    }

    #[test]
    fn imports_parse_all_four_kinds_with_names() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32], &[I32]);
        b.import_func("env", "host_log", t);
        b.import_memory("env", "memory", 16, Some(256), false);
        b.import_global("env", "__stack_pointer", I32, true);
        b.import_table("env", "table", 4);
        let m = core(&b.build());
        assert_eq!(m.imports.len(), 4);
        assert_eq!(m.imports[0].qualified(), "env.host_log");
        assert!(matches!(m.imports[1].desc, ImportDesc::Memory { .. }));
        assert!(matches!(
            m.imports[2].desc,
            ImportDesc::Global { mutable: true, .. }
        ));
        assert_eq!(m.imports[3].desc.kind(), ExternKind::Table);
    }

    #[test]
    fn imported_function_signature_resolves_through_the_type_section() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32, I64], &[I32]);
        b.import_func("host", "f", t);
        let m = core(&b.build());
        assert_eq!(
            m.func_signature(0).unwrap().to_string(),
            "(i32, i64) -> i32"
        );
    }

    #[test]
    fn exports_parse_with_kind_and_index() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[], &[]);
        let f = b.add_function(t);
        b.add_memory(17, None, false);
        b.export("run", 0x00, f);
        b.export("memory", MEMORY, 0);
        let m = core(&b.build());
        assert_eq!(m.exports.len(), 2);
        assert_eq!(m.exports[0].name, "run");
        assert_eq!(m.exports[0].kind, ExternKind::Func);
        assert_eq!(m.exports[1].kind, ExternKind::Memory);
    }

    #[test]
    fn memory_limits_decode_min_max_and_shared() {
        let mut b = ModuleBuilder::new();
        b.add_memory(16, Some(32), false);
        b.add_memory(2, Some(4), true);
        let m = core(&b.build());
        assert_eq!(m.memories[0].max, Some(32));
        assert!(!m.memories[0].shared);
        assert!(m.memories[1].shared);
    }

    #[test]
    fn start_code_and_function_counts_are_recorded() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[], &[]);
        let f = b.add_function(t);
        b.add_function(t);
        b.set_start(f);
        let m = core(&b.build());
        assert_eq!(m.start, Some(f));
        assert_eq!(m.code_count, Some(2));
        assert_eq!(m.functions.len(), 2);
    }

    #[test]
    fn custom_sections_keep_name_offset_and_payload() {
        let mut b = ModuleBuilder::new();
        b.custom("build_id", &[0xde, 0xad, 0xbe, 0xef]);
        let m = core(&b.build());
        let c = m.custom("build_id").unwrap();
        assert_eq!(c.data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(m.sections[0].label(), "custom \"build_id\"");
    }

    #[test]
    fn truncation_and_trailing_garbage_are_errors() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("fd_write");
        let bytes = b.build();
        let cut = &bytes[..bytes.len() - 5];
        let err = parse(cut).unwrap_err();
        assert!(err.message.contains("truncated"), "{}", err.message);
        // A lone section id after the last section has no size byte.
        let mut padded = bytes.clone();
        padded.push(0x0a);
        let err = parse(&padded).unwrap_err();
        assert!(err.message.contains("unexpected end"), "{}", err.message);
    }

    #[test]
    fn impossible_vector_count_is_rejected() {
        // An import section claiming 1 million imports in 3 payload bytes.
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend_from_slice(&[0x02, 0x04, 0xc0, 0x84, 0x3d, 0x00]);
        let err = parse(&bytes).unwrap_err();
        assert!(err.message.contains("impossible"), "{}", err.message);
    }

    #[test]
    fn duplicate_sections_are_both_recorded() {
        // Two memory sections is not spec-legal, but an auditor should show
        // both rather than reject a file some runtime might still load.
        let mut b = ModuleBuilder::new();
        b.add_memory(1, Some(2), false);
        let bytes = b.build();
        let section = &bytes[8..]; // id + size + payload of the memory section
        let mut doubled = bytes.clone();
        doubled.extend_from_slice(section);
        let m = core(&doubled);
        assert_eq!(m.sections.len(), 2);
        assert_eq!(m.memories.len(), 2);
    }

    #[test]
    fn global_section_decodes_types_mutability_and_index_space() {
        let mut b = ModuleBuilder::new();
        b.import_global("env", "imported", I32, false);
        b.add_global(I32, false);
        b.add_global(I64, true);
        let m = core(&b.build());
        assert_eq!(m.globals.len(), 2);
        assert!(!m.globals[0].mutable);
        assert!(m.globals[1].mutable);
        // The global index space starts with imports.
        assert_eq!(m.global_mutability(0), Some(false)); // the import
        assert_eq!(m.global_mutability(2), Some(true)); // the second defined one
        assert_eq!(m.global_mutability(9), None);
    }

    #[test]
    fn post_mvp_content_degrades_to_partial_never_an_error() {
        // A global init expression using opcode 0x99 (unknown to us).
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend_from_slice(&[0x06, 0x07, 0x02, 0x7f, 0x00, 0x99, 0x00, 0x00, 0x0b]);
        let m = core(&bytes);
        assert!(m.globals_partial);
        assert_eq!(m.global_count, 2);
        assert!(m.globals.is_empty());
        // A type section whose first entry is a GC rec-group (0x4e).
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend_from_slice(&[0x01, 0x04, 0x01, 0x4e, 0x00, 0x00]);
        let m = core(&bytes);
        assert!(m.types_partial);
        assert!(m.types.is_empty());
    }
}
