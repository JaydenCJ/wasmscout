//! Renderers: the human `scan`/`caps`/`imports`/`exports`/`sections` text
//! views and the machine JSON object — everything the CLI prints.

use crate::audit::Finding;
use crate::caps::Analysis;
use crate::custom::{parse_name_section, parse_producers};
use crate::json::Json;
use crate::wasi;
use crate::wasm::{ImportDesc, Module};

/// `1234` → `1.2 KiB`; whole bytes below 1 KiB.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 3] = ["KiB", "MiB", "GiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = "";
    for u in UNITS {
        value /= 1024.0;
        unit = u;
        if value < 1024.0 {
            break;
        }
    }
    format!("{value:.1} {unit}")
}

/// The one-line identity header shared by every text view.
fn header(label: &str, m: &Module) -> String {
    format!(
        "{label}: core wasm module · {} · {} section(s) · {} import(s) · {} export(s)",
        human_size(m.file_size as u64),
        m.sections.len(),
        m.imports.len(),
        m.exports.len()
    )
}

/// Provenance and target lines shown under the header when available.
fn identity_lines(m: &Module) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(c) = m.custom("name") {
        if let Ok(info) = parse_name_section(&c.data) {
            if let Some(name) = info.module_name {
                lines.push(format!("  module name: \"{name}\""));
            }
        }
    }
    if let Some(c) = m.custom("producers") {
        if let Ok(p) = parse_producers(&c.data) {
            let summary = p.summary();
            if !summary.is_empty() {
                lines.push(format!("  producers: {summary}"));
            }
        }
    }
    let func_imports: Vec<&crate::wasm::Import> = m
        .imports
        .iter()
        .filter(|i| matches!(i.desc, ImportDesc::Func { .. }))
        .collect();
    if func_imports.is_empty() {
        lines.push("  target: no function imports (pure compute module)".to_string());
    } else {
        let mut targets = Vec::new();
        for name in ["wasi_snapshot_preview1", "wasi_unstable"] {
            if func_imports.iter().any(|i| i.module == name) {
                targets.push(format!("WASI preview 1 ({name})"));
            }
        }
        if func_imports.iter().any(|i| i.module.starts_with("wasi:")) {
            targets.push("WASI preview 2 interfaces".to_string());
        }
        if func_imports
            .iter()
            .any(|i| !wasi::is_wasi_module(&i.module))
        {
            targets.push("custom host functions".to_string());
        }
        lines.push(format!("  target: {}", targets.join(" + ")));
    }
    lines
}

/// The full `scan` text block for one module (without the batch summary).
pub fn render_scan(label: &str, m: &Module, analysis: &Analysis, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&header(label, m));
    out.push('\n');
    for line in identity_lines(m) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');

    out.push_str("capabilities\n");
    if analysis.hits.is_empty() {
        out.push_str("  (none — the module cannot touch the host at all)\n");
    } else {
        for hit in &analysis.hits {
            let shown: Vec<&str> = hit.via.iter().take(3).map(String::as_str).collect();
            let mut vias = shown.join(", ");
            if hit.via.len() > 3 {
                vias.push_str(&format!(" (+{} more)", hit.via.len() - 3));
            }
            if hit.inferred.is_some() {
                vias.push_str(" [inferred]");
            }
            out.push_str(&format!(
                "  {:<12} {:<7} {}\n",
                hit.cap.name(),
                hit.cap.risk().label(),
                vias
            ));
        }
    }
    out.push('\n');

    out.push_str("findings\n");
    if findings.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for f in findings {
            out.push_str(&format!(
                "  {}[{}]: {}\n",
                f.severity.label(),
                f.id,
                f.message
            ));
        }
    }
    out
}

/// One `caps` line: capabilities sorted by risk, or `(none)`.
pub fn render_caps_line(label: &str, analysis: &Analysis) -> String {
    if analysis.hits.is_empty() {
        return format!("{label}: (none)");
    }
    let names: Vec<&str> = analysis.hits.iter().map(|h| h.cap.name()).collect();
    format!("{label}: {}", names.join(" "))
}

fn import_detail(m: &Module, desc: &ImportDesc) -> String {
    match desc {
        ImportDesc::Func { type_index } => m
            .types
            .get(*type_index as usize)
            .map(|t| t.to_string())
            .unwrap_or_else(|| format!("type #{type_index} (not decoded)")),
        ImportDesc::Table { reftype, limits } => {
            format!("{reftype}, {}", limits.describe_elements())
        }
        ImportDesc::Memory { limits } => limits.describe_pages(),
        ImportDesc::Global { valtype, mutable } => {
            format!("{} {valtype}", if *mutable { "mutable" } else { "const" })
        }
        ImportDesc::Tag { type_index } => format!("tag type #{type_index}"),
    }
}

/// Render an aligned two-margin table: `left  kind  detail`.
fn table(rows: &[(String, String, String)]) -> String {
    let w0 = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    let w1 = rows.iter().map(|r| r.1.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (a, b, c) in rows {
        out.push_str(format!("  {a:<w0$}  {b:<w1$}  {c}").trim_end());
        out.push('\n');
    }
    out
}

pub fn render_imports(label: &str, m: &Module) -> String {
    let mut out = header(label, m);
    out.push('\n');
    if m.imports.is_empty() {
        out.push_str("  (no imports — pure compute module)\n");
        return out;
    }
    let rows: Vec<(String, String, String)> = m
        .imports
        .iter()
        .map(|i| {
            (
                i.qualified(),
                i.desc.kind().label(),
                import_detail(m, &i.desc),
            )
        })
        .collect();
    out.push_str(&table(&rows));
    out
}

pub fn render_exports(label: &str, m: &Module) -> String {
    let mut out = header(label, m);
    out.push('\n');
    if m.exports.is_empty() {
        out.push_str("  (no exports)\n");
        return out;
    }
    let rows: Vec<(String, String, String)> = m
        .exports
        .iter()
        .map(|e| {
            let detail = match e.kind {
                crate::types::ExternKind::Func => m
                    .func_signature(e.index)
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| format!("func #{}", e.index)),
                crate::types::ExternKind::Global => match m.global_mutability(e.index) {
                    Some(true) => "mutable".to_string(),
                    Some(false) => "const".to_string(),
                    None => format!("global #{}", e.index),
                },
                _ => format!("index {}", e.index),
            };
            (e.name.clone(), e.kind.label(), detail)
        })
        .collect();
    out.push_str(&table(&rows));
    out
}

pub fn render_sections(label: &str, m: &Module) -> String {
    let mut out = format!(
        "{label}: {} across {} section(s)\n",
        human_size(m.file_size as u64),
        m.sections.len()
    );
    let total = m.file_size.max(1);
    let mut rows: Vec<(String, usize)> = m.sections.iter().map(|s| (s.label(), s.size)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1));
    let w = rows.iter().map(|r| r.0.len()).max().unwrap_or(0);
    for (name, size) in rows {
        let percent = size as f64 * 100.0 / total as f64;
        let filled = ((percent / 5.0).round() as usize).min(20);
        let bar: String = "#".repeat(filled) + &".".repeat(20 - filled);
        out.push_str(&format!(
            "  {name:<w$}  {:>9}  {percent:>5.1}%  {bar}\n",
            human_size(size as u64)
        ));
    }
    out
}

/// The machine-readable scan result: one compact JSON object.
pub fn render_scan_json(
    label: &str,
    m: &Module,
    analysis: &Analysis,
    findings: &[Finding],
    pass: bool,
    gate: &str,
) -> String {
    let sections = m
        .sections
        .iter()
        .map(|s| {
            Json::Obj(vec![
                ("name".into(), Json::s(s.label())),
                ("offset".into(), Json::Uint(s.offset as u64)),
                ("size".into(), Json::Uint(s.size as u64)),
            ])
        })
        .collect();
    let imports = m
        .imports
        .iter()
        .map(|i| {
            Json::Obj(vec![
                ("module".into(), Json::s(&i.module)),
                ("name".into(), Json::s(&i.field)),
                ("kind".into(), Json::s(i.desc.kind().label())),
                ("detail".into(), Json::s(import_detail(m, &i.desc))),
            ])
        })
        .collect();
    let exports = m
        .exports
        .iter()
        .map(|e| {
            Json::Obj(vec![
                ("name".into(), Json::s(&e.name)),
                ("kind".into(), Json::s(e.kind.label())),
                ("index".into(), Json::Uint(u64::from(e.index))),
            ])
        })
        .collect();
    let capabilities = analysis
        .hits
        .iter()
        .map(|h| {
            Json::Obj(vec![
                ("name".into(), Json::s(h.cap.name())),
                ("risk".into(), Json::s(h.cap.risk().label())),
                ("via".into(), Json::Arr(h.via.iter().map(Json::s).collect())),
                ("inferred".into(), Json::Bool(h.inferred.is_some())),
            ])
        })
        .collect();
    let findings_json = findings
        .iter()
        .map(|f| {
            Json::Obj(vec![
                ("id".into(), Json::s(f.id)),
                ("severity".into(), Json::s(f.severity.label())),
                ("message".into(), Json::s(&f.message)),
            ])
        })
        .collect();
    Json::Obj(vec![
        ("file".into(), Json::s(label)),
        ("format".into(), Json::s("core-module")),
        ("size".into(), Json::Uint(m.file_size as u64)),
        ("sections".into(), Json::Arr(sections)),
        ("imports".into(), Json::Arr(imports)),
        ("exports".into(), Json::Arr(exports)),
        ("capabilities".into(), Json::Arr(capabilities)),
        ("findings".into(), Json::Arr(findings_json)),
        ("gate".into(), Json::s(gate)),
        ("pass".into(), Json::Bool(pass)),
    ])
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;
    use crate::builder::{ModuleBuilder, I32, MEMORY};
    use crate::caps::analyze;
    use crate::wasm::{parse, Parsed};

    fn module_of(b: &ModuleBuilder) -> Module {
        match parse(&b.build()).unwrap() {
            Parsed::Core(m) => *m,
            _ => panic!("expected a core module"),
        }
    }

    #[test]
    fn human_size_covers_the_unit_boundaries() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn scan_renders_capability_rows_and_findings() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("sock_send");
        b.import_wasi("fd_write");
        let m = module_of(&b);
        let a = analyze(&m);
        let f = audit::run(&m, &a);
        let text = render_scan("mod.wasm", &m, &a, &f);
        assert!(text.contains("network      high    sock_send"), "{text}");
        assert!(text.contains("fd-io        low     fd_write"), "{text}");
        assert!(text.contains("high[wasi.network]"), "{text}");
        assert!(text.contains("target: WASI preview 1"), "{text}");
    }

    #[test]
    fn scan_marks_inferred_capabilities() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("path_open");
        b.import_wasi("fd_write");
        let m = module_of(&b);
        let a = analyze(&m);
        let f = audit::run(&m, &a);
        let text = render_scan("mod.wasm", &m, &a, &f);
        assert!(text.contains("[inferred]"), "{text}");
    }

    #[test]
    fn a_pure_module_says_so() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32], &[I32]);
        let f = b.add_function(t);
        b.export("apply", 0x00, f);
        let m = module_of(&b);
        let a = analyze(&m);
        let text = render_scan("pure.wasm", &m, &a, &[]);
        assert!(text.contains("pure compute module"), "{text}");
        assert!(
            text.contains("(none — the module cannot touch the host at all)"),
            "{text}"
        );
        assert!(text.contains("findings\n  (none)"), "{text}");
    }

    #[test]
    fn imports_view_shows_signatures_and_limits() {
        let mut b = ModuleBuilder::new();
        let t = b.add_type(&[I32, I32], &[I32]);
        b.import_func("env", "host_log", t);
        b.import_memory("env", "memory", 16, Some(256), false);
        let m = module_of(&b);
        let text = render_imports("mod.wasm", &m);
        assert!(text.contains("env.host_log"), "{text}");
        assert!(text.contains("(i32, i32) -> i32"), "{text}");
        assert!(text.contains("16..256 pages"), "{text}");
    }

    #[test]
    fn exports_view_resolves_signatures_through_imports() {
        let mut b = ModuleBuilder::new();
        let t_imp = b.add_type(&[I32], &[]);
        let t_def = b.add_type(&[], &[I32]);
        b.import_func("env", "cb", t_imp);
        let f = b.add_function(t_def);
        b.export("answer", 0x00, f);
        b.add_memory(1, Some(2), false);
        b.export("memory", MEMORY, 0);
        let m = module_of(&b);
        let text = render_exports("mod.wasm", &m);
        assert!(text.contains("answer"), "{text}");
        assert!(text.contains("() -> i32"), "{text}");
    }

    #[test]
    fn sections_view_sorts_by_size_with_bars() {
        let mut b = ModuleBuilder::new();
        b.custom("big", &[0u8; 600]);
        b.custom("small", &[0u8; 30]);
        let m = module_of(&b);
        let text = render_sections("mod.wasm", &m);
        let big_pos = text.find("custom \"big\"").unwrap();
        let small_pos = text.find("custom \"small\"").unwrap();
        assert!(big_pos < small_pos, "sections must sort by size:\n{text}");
        assert!(text.contains('#'), "{text}");
        assert!(text.contains('%'), "{text}");
    }

    #[test]
    fn caps_line_is_compact_and_risk_ordered() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("clock_time_get");
        b.import_wasi("path_unlink_file");
        let m = module_of(&b);
        let a = analyze(&m);
        assert_eq!(render_caps_line("m.wasm", &a), "m.wasm: fs-write clocks");

        let empty = analyze(&module_of(&ModuleBuilder::new()));
        assert_eq!(render_caps_line("m.wasm", &empty), "m.wasm: (none)");
    }

    #[test]
    fn json_scan_contains_the_load_bearing_fields() {
        let mut b = ModuleBuilder::new();
        b.import_wasi("sock_send");
        let m = module_of(&b);
        let a = analyze(&m);
        let f = audit::run(&m, &a);
        let json = render_scan_json("mod.wasm", &m, &a, &f, false, "high");
        assert!(json.contains(r#""file":"mod.wasm""#), "{json}");
        assert!(json.contains(r#""name":"network","risk":"high""#), "{json}");
        assert!(json.contains(r#""id":"wasi.network""#), "{json}");
        assert!(json.contains(r#""pass":false"#), "{json}");
        assert!(json.contains(r#""gate":"high""#), "{json}");
        assert!(!json.contains('\n'), "must be a single line");
    }
}
