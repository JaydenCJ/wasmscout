//! Decoders for well-known custom sections — `name`, `producers`,
//! `target_features`, `sourceMappingURL` — plus classification of the rest
//! (DWARF, linking/reloc, dylink, build ids, unknown).

use crate::reader::{ParseError, Reader, Result};

/// What a custom section is, judged by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomKind {
    Name,
    Producers,
    TargetFeatures,
    SourceMappingUrl,
    Dwarf,
    ExternalDebugInfo,
    BuildId,
    Linking,
    Reloc,
    Dylink,
    Unknown,
}

pub fn classify(name: &str) -> CustomKind {
    match name {
        "name" => CustomKind::Name,
        "producers" => CustomKind::Producers,
        "target_features" => CustomKind::TargetFeatures,
        "sourceMappingURL" => CustomKind::SourceMappingUrl,
        "external_debug_info" => CustomKind::ExternalDebugInfo,
        "build_id" => CustomKind::BuildId,
        "linking" => CustomKind::Linking,
        "dylink" | "dylink.0" => CustomKind::Dylink,
        n if n.starts_with("reloc.") => CustomKind::Reloc,
        n if n.starts_with(".debug_") => CustomKind::Dwarf,
        _ => CustomKind::Unknown,
    }
}

/// True for sections that exist only to support debugging: DWARF embedded
/// in the module and pointers to debug info kept elsewhere.
pub fn is_debug(kind: CustomKind) -> bool {
    matches!(kind, CustomKind::Dwarf | CustomKind::ExternalDebugInfo)
}

/// The parsed `producers` section: toolchain provenance.
#[derive(Debug, Default)]
pub struct Producers {
    /// `(field, [(name, version), ...])` — fields are `language`,
    /// `processed-by` and `sdk` per the tool-conventions spec.
    pub fields: Vec<(String, Vec<(String, String)>)>,
}

impl Producers {
    /// One-line summary: `language Rust · processed-by rustc 1.75.0`.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for (field, values) in &self.fields {
            let rendered: Vec<String> = values
                .iter()
                .map(|(name, version)| {
                    if version.is_empty() {
                        name.clone()
                    } else {
                        format!("{name} {version}")
                    }
                })
                .collect();
            parts.push(format!("{field} {}", rendered.join(", ")));
        }
        parts.join(" · ")
    }
}

pub fn parse_producers(data: &[u8]) -> Result<Producers> {
    let mut r = Reader::new(data);
    let count = r.leb_u32()?;
    r.check_count(count, 2, "producers field")?;
    let mut p = Producers::default();
    for _ in 0..count {
        let field = r.name()?;
        let value_count = r.leb_u32()?;
        r.check_count(value_count, 2, "producers value")?;
        let mut values = Vec::new();
        for _ in 0..value_count {
            let name = r.name()?;
            let version = r.name()?;
            values.push((name, version));
        }
        p.fields.push((field, values));
    }
    Ok(p)
}

/// The parsed `target_features` section: `('+', "simd128")` style entries.
pub fn parse_target_features(data: &[u8]) -> Result<Vec<(char, String)>> {
    let mut r = Reader::new(data);
    let count = r.leb_u32()?;
    r.check_count(count, 2, "target feature")?;
    let mut features = Vec::new();
    for _ in 0..count {
        let prefix = r.byte()?;
        if prefix != b'+' && prefix != b'-' {
            return Err(ParseError::new(
                r.offset().saturating_sub(1),
                format!("target feature prefix must be '+' or '-', got 0x{prefix:02x}"),
            ));
        }
        features.push((prefix as char, r.name()?));
    }
    Ok(features)
}

/// What we extract from the `name` section.
#[derive(Debug, Default)]
pub struct NameInfo {
    pub module_name: Option<String>,
    pub function_names: u32,
}

pub fn parse_name_section(data: &[u8]) -> Result<NameInfo> {
    let mut r = Reader::new(data);
    let mut info = NameInfo::default();
    while !r.is_empty() {
        let id = r.byte()?;
        let size = r.leb_u32()? as usize;
        if size > r.remaining() {
            return Err(ParseError::new(
                r.offset(),
                format!(
                    "name subsection {id} claims {size} byte(s), only {} remain",
                    r.remaining()
                ),
            ));
        }
        let mut sub = r.slice(size)?;
        match id {
            0 => info.module_name = Some(sub.name()?),
            1 => info.function_names = sub.leb_u32()?,
            _ => {} // locals, labels, etc. — not needed for the audit
        }
    }
    Ok(info)
}

/// The `sourceMappingURL` payload: a single length-prefixed URL.
pub fn parse_source_mapping_url(data: &[u8]) -> Result<String> {
    Reader::new(data).name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ModuleBuilder;
    use crate::wasm::{parse, Parsed};

    fn custom_payload(b: &ModuleBuilder, name: &str) -> Vec<u8> {
        match parse(&b.build()).unwrap() {
            Parsed::Core(m) => m.custom(name).unwrap().data.clone(),
            _ => panic!("expected a core module"),
        }
    }

    #[test]
    fn producers_round_trips_through_the_builder() {
        let mut b = ModuleBuilder::new();
        b.producers(&[
            ("language", &[("Rust", "1.75.0")]),
            ("processed-by", &[("rustc", "1.75.0"), ("wasm-opt", "116")]),
        ]);
        let p = parse_producers(&custom_payload(&b, "producers")).unwrap();
        assert_eq!(p.fields.len(), 2);
        assert_eq!(p.fields[0].0, "language");
        assert_eq!(
            p.summary(),
            "language Rust 1.75.0 · processed-by rustc 1.75.0, wasm-opt 116"
        );
        // An empty version renders as the bare tool name.
        let mut b = ModuleBuilder::new();
        b.producers(&[("sdk", &[("Emscripten", "")])]);
        let p = parse_producers(&custom_payload(&b, "producers")).unwrap();
        assert_eq!(p.summary(), "sdk Emscripten");
    }

    #[test]
    fn malformed_producers_is_an_error_not_a_panic() {
        // Claims 5 fields, provides none.
        assert!(parse_producers(&[0x05]).is_err());
    }

    #[test]
    fn target_features_parse_and_reject_bad_prefixes() {
        let mut b = ModuleBuilder::new();
        b.target_features(&[('+', "simd128"), ('-', "threads")]);
        let f = parse_target_features(&custom_payload(&b, "target_features")).unwrap();
        assert_eq!(
            f,
            vec![('+', "simd128".to_string()), ('-', "threads".to_string())]
        );
        let err = parse_target_features(&[0x01, b'*', 0x01, b'x']).unwrap_err();
        assert!(err.message.contains("prefix"), "{}", err.message);
    }

    #[test]
    fn name_section_yields_module_name_and_function_count() {
        let mut b = ModuleBuilder::new();
        b.name_section("image_filter", &[(0, "apply"), (1, "resize")]);
        let info = parse_name_section(&custom_payload(&b, "name")).unwrap();
        assert_eq!(info.module_name.as_deref(), Some("image_filter"));
        assert_eq!(info.function_names, 2);
    }

    #[test]
    fn name_subsection_overrun_is_an_error() {
        // Subsection 0 claims 100 bytes with 1 available.
        let err = parse_name_section(&[0x00, 0x64, 0x01]).unwrap_err();
        assert!(err.message.contains("claims 100"), "{}", err.message);
    }

    #[test]
    fn classify_recognizes_the_conventional_names() {
        assert_eq!(classify("name"), CustomKind::Name);
        assert_eq!(classify("producers"), CustomKind::Producers);
        assert_eq!(classify(".debug_info"), CustomKind::Dwarf);
        assert_eq!(classify(".debug_str"), CustomKind::Dwarf);
        assert_eq!(classify("reloc.CODE"), CustomKind::Reloc);
        assert_eq!(classify("linking"), CustomKind::Linking);
        assert_eq!(classify("dylink.0"), CustomKind::Dylink);
        assert_eq!(classify("build_id"), CustomKind::BuildId);
        assert_eq!(classify("my-metadata"), CustomKind::Unknown);
        assert!(is_debug(classify("external_debug_info")));
        assert!(!is_debug(classify("name")));
    }

    #[test]
    fn source_mapping_url_parses() {
        let mut b = ModuleBuilder::new();
        b.source_mapping_url("http://127.0.0.1:8000/app.wasm.map");
        let url = parse_source_mapping_url(&custom_payload(&b, "sourceMappingURL")).unwrap();
        assert_eq!(url, "http://127.0.0.1:8000/app.wasm.map");
    }
}
