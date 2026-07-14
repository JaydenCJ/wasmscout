//! A minimal JSON value and serializer — std-only, escapes everything the
//! RFC requires, emits one compact line per value.

use std::fmt;

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Uint(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Shorthand for a string value.
    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }
}

/// Escape a string per RFC 8259 (quotes, backslash, control characters).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Json::Null => write!(f, "null"),
            Json::Bool(b) => write!(f, "{b}"),
            Json::Uint(n) => write!(f, "{n}"),
            Json::Str(s) => write!(f, "\"{}\"", escape(s)),
            Json::Arr(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            Json::Obj(pairs) => {
                write!(f, "{{")?;
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "\"{}\":{v}", escape(k))?;
                }
                write!(f, "}}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_handles_the_rfc_required_cases() {
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("a\nb\tc"), "a\\nb\\tc");
        assert_eq!(escape("\u{1}"), "\\u0001");
        // Non-ASCII passes through unescaped (UTF-8 output is valid JSON).
        assert_eq!(escape("モジュール名"), "モジュール名");
    }

    #[test]
    fn values_serialize_compactly_with_escaped_keys() {
        let v = Json::Obj(vec![
            ("name".into(), Json::s("fd_write")),
            ("count".into(), Json::Uint(3)),
            (
                "flags".into(),
                Json::Arr(vec![Json::Bool(true), Json::Null]),
            ),
        ]);
        assert_eq!(
            v.to_string(),
            r#"{"name":"fd_write","count":3,"flags":[true,null]}"#
        );
        let v = Json::Obj(vec![("we\"ird".into(), Json::Uint(1))]);
        assert_eq!(v.to_string(), r#"{"we\"ird":1}"#);
        assert_eq!(Json::Arr(vec![]).to_string(), "[]");
        assert_eq!(Json::Obj(vec![]).to_string(), "{}");
    }
}
