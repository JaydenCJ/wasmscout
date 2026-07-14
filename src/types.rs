//! Core wasm vocabulary: value types, function signatures, limits, extern
//! kinds and section names — the displayable atoms every report is built on.

use std::fmt;

/// A wasm value type. Unknown bytes are preserved so post-MVP modules
/// (GC types, future proposals) still render instead of failing the audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
    Other(u8),
}

impl ValType {
    pub fn from_byte(b: u8) -> ValType {
        match b {
            0x7f => ValType::I32,
            0x7e => ValType::I64,
            0x7d => ValType::F32,
            0x7c => ValType::F64,
            0x7b => ValType::V128,
            0x70 => ValType::FuncRef,
            0x6f => ValType::ExternRef,
            other => ValType::Other(other),
        }
    }
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValType::I32 => write!(f, "i32"),
            ValType::I64 => write!(f, "i64"),
            ValType::F32 => write!(f, "f32"),
            ValType::F64 => write!(f, "f64"),
            ValType::V128 => write!(f, "v128"),
            ValType::FuncRef => write!(f, "funcref"),
            ValType::ExternRef => write!(f, "externref"),
            ValType::Other(b) => write!(f, "type(0x{b:02x})"),
        }
    }
}

/// A function signature: `(params) -> results`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

impl fmt::Display for FuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(")?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{p}")?;
        }
        write!(f, ") -> ")?;
        match self.results.as_slice() {
            [] => write!(f, "()"),
            [one] => write!(f, "{one}"),
            many => {
                write!(f, "(")?;
                for (i, r) in many.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{r}")?;
                }
                write!(f, ")")
            }
        }
    }
}

/// Memory/table limits, including the threads (`shared`) and memory64 flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub min: u64,
    pub max: Option<u64>,
    pub shared: bool,
    pub memory64: bool,
}

impl Limits {
    /// Render as memory pages (64 KiB each).
    pub fn describe_pages(&self) -> String {
        let mut s = match self.max {
            Some(max) => format!("{}..{} pages", self.min, max),
            None => format!("min {} pages, no max", self.min),
        };
        if self.shared {
            s.push_str(", shared");
        }
        if self.memory64 {
            s.push_str(", 64-bit");
        }
        s
    }

    /// Render as table elements.
    pub fn describe_elements(&self) -> String {
        match self.max {
            Some(max) => format!("{}..{} elements", self.min, max),
            None => format!("min {} elements", self.min),
        }
    }
}

/// What kind of thing an import or export refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternKind {
    Func,
    Table,
    Memory,
    Global,
    Tag,
    Other(u8),
}

impl ExternKind {
    pub fn from_byte(b: u8) -> ExternKind {
        match b {
            0x00 => ExternKind::Func,
            0x01 => ExternKind::Table,
            0x02 => ExternKind::Memory,
            0x03 => ExternKind::Global,
            0x04 => ExternKind::Tag,
            other => ExternKind::Other(other),
        }
    }

    pub fn label(&self) -> String {
        match self {
            ExternKind::Func => "func".into(),
            ExternKind::Table => "table".into(),
            ExternKind::Memory => "memory".into(),
            ExternKind::Global => "global".into(),
            ExternKind::Tag => "tag".into(),
            ExternKind::Other(b) => format!("kind(0x{b:02x})"),
        }
    }
}

/// Human name for a section id, per the core spec (13 = exception tags).
pub fn section_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data count",
        13 => "tag",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valtypes_and_functypes_display_every_arity() {
        assert_eq!(ValType::from_byte(0x7f).to_string(), "i32");
        assert_eq!(ValType::from_byte(0x7b).to_string(), "v128");
        assert_eq!(ValType::from_byte(0x6f).to_string(), "externref");
        // A GC heap type byte must render, not crash the report.
        assert_eq!(ValType::from_byte(0x64).to_string(), "type(0x64)");
        let f = FuncType {
            params: vec![],
            results: vec![],
        };
        assert_eq!(f.to_string(), "() -> ()");
        let f = FuncType {
            params: vec![ValType::I32, ValType::I64],
            results: vec![ValType::I32],
        };
        assert_eq!(f.to_string(), "(i32, i64) -> i32");
        let f = FuncType {
            params: vec![ValType::F32],
            results: vec![ValType::I32, ValType::I32],
        };
        assert_eq!(f.to_string(), "(f32) -> (i32, i32)");
    }

    #[test]
    fn limits_describe_pages_covers_all_flags() {
        let l = Limits {
            min: 16,
            max: Some(256),
            shared: false,
            memory64: false,
        };
        assert_eq!(l.describe_pages(), "16..256 pages");
        let l = Limits {
            min: 17,
            max: None,
            shared: false,
            memory64: false,
        };
        assert_eq!(l.describe_pages(), "min 17 pages, no max");
        let l = Limits {
            min: 1,
            max: Some(8),
            shared: true,
            memory64: true,
        };
        assert_eq!(l.describe_pages(), "1..8 pages, shared, 64-bit");
    }

    #[test]
    fn extern_kinds_and_section_names_cover_the_spec_range() {
        assert_eq!(ExternKind::from_byte(0x02), ExternKind::Memory);
        assert_eq!(ExternKind::from_byte(0x04).label(), "tag");
        assert_eq!(ExternKind::from_byte(0x09).label(), "kind(0x09)");
        assert_eq!(section_name(0), "custom");
        assert_eq!(section_name(10), "code");
        assert_eq!(section_name(12), "data count");
        assert_eq!(section_name(13), "tag");
        assert_eq!(section_name(200), "unknown");
    }
}
