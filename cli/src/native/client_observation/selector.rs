// Copyright (c) Microsoft Corporation.
// Licensed under the Apache License, Version 2.0.
//
// The lexical scanner is a Rust adaptation of Playwright 1.64.1's
// packages/isomorphic/selectorParser.ts, parseSelectorString. See
// selector-NOTICE.md for provenance and the deliberate bounded subset.

/// A parsed selector step. Bodies remain authored source, not interpolated code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Part<'a> {
    pub engine: &'a str,
    pub body: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ParseError {
    Invalid,
    Unsupported,
    Limit,
}

/// Parse Playwright chain boundaries, then validate the native engine subset.
/// Quotes and backslash escapes protect `>>`; a raw text engine's apostrophe
/// is not a string opener after its body has started, as in Playwright.
pub(super) fn parse(selector: &str) -> Result<Vec<Part<'_>>, ParseError> {
    if selector.len() > 65_536 {
        return Err(ParseError::Limit);
    }
    let mut parts = Vec::new();
    let mut capture = None;
    let mut start = 0;
    let mut quote = None;
    let mut chars = selector.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        if ch == '\\' && chars.peek().is_some() {
            chars.next();
        } else if Some(ch) == quote {
            quote = None;
        } else if quote.is_none()
            && matches!(ch, '\'' | '"' | '`')
            && !ignore_text_quote(&selector[start..index])
        {
            quote = Some(ch);
        } else if quote.is_none() && ch == '>' && chars.peek().is_some_and(|(_, c)| *c == '>') {
            append(&selector[start..index], &mut parts, &mut capture)?;
            chars.next();
            start = index + 2;
        }
    }
    append(&selector[start..], &mut parts, &mut capture)?;
    if capture.is_some_and(|index| index + 1 != parts.len()) {
        return Err(ParseError::Invalid);
    }
    for part in &parts {
        match part.engine {
            "css" | "css:light" | "xpath" | "xpath:light" => {}
            // Playwright uses JavaScript Number + Array.slice here, including
            // fractional, non-finite and out-of-range inputs. The renderer
            // owns that coercion; Rust must not invent a different index rule.
            "nth" => {}
            // Playwright 1.64.1 attribute engines read one exact attribute
            // value and differ only in whether they pierce open shadow roots.
            // The body stays authored source: no unquoting or unescaping.
            "id" | "id:light" | "data-testid" | "data-testid:light" | "data-test-id"
            | "data-test-id:light" | "data-test" | "data-test:light" => {}
            // These Playwright engines are not CSS. Never pass their source
            // to Element.matches or silently reinterpret their semantics.
            "text"
            | "text:light"
            | "role"
            | "_react"
            | "_vue"
            | "visible"
            | "internal:has"
            | "internal:has-not"
            | "internal:has-text"
            | "internal:has-not-text"
            | "internal:and"
            | "internal:or"
            | "internal:chain"
            | "internal:role"
            | "internal:text"
            | "internal:label"
            | "internal:attr"
            | "internal:testid"
            | "internal:control"
            | "left-of"
            | "right-of"
            | "above"
            | "below"
            | "near" => return Err(ParseError::Unsupported),
            _ => return Err(ParseError::Invalid),
        }
    }
    Ok(parts)
}

// JavaScript String.trim and /\s/ differ from Rust's Unicode whitespace:
// ECMAScript includes BOM but excludes NEXT LINE U+0085.
fn js_whitespace(ch: char) -> bool {
    matches!(ch, '\u{0009}'..='\u{000d}' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

fn ignore_text_quote(prefix: &str) -> bool {
    let Some(rest) = prefix
        .trim_start_matches(js_whitespace)
        .strip_prefix("text")
    else {
        return false;
    };
    rest.trim_start_matches(js_whitespace)
        .strip_prefix('=')
        .is_some_and(|body| {
            !body.is_empty() && !body.contains(['\n', '\r', '\u{2028}', '\u{2029}'])
        })
}

fn append<'a>(
    source: &'a str,
    parts: &mut Vec<Part<'a>>,
    capture: &mut Option<usize>,
) -> Result<(), ParseError> {
    if parts.len() == 256 {
        return Err(ParseError::Limit);
    }
    let source = source.trim_matches(js_whitespace);
    if source.is_empty() {
        return Err(ParseError::Invalid);
    }
    let named = source.find('=').and_then(|index| {
        let name = source[..index].trim_matches(js_whitespace);
        (!name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-+:*".contains(&b)))
        .then_some((name, &source[index + 1..]))
    });
    let (mut engine, body) = named.unwrap_or_else(|| {
        let quoted = source.len() > 1
            && ((source.starts_with('"') && source.ends_with('"'))
                || (source.starts_with('\'') && source.ends_with('\'')));
        let engine = if quoted {
            "text"
        } else if source.trim_start_matches('(').starts_with("//") || source.starts_with("..") {
            "xpath"
        } else {
            "css"
        };
        (engine, source)
    });
    if let Some(name) = engine.strip_prefix('*') {
        if capture.replace(parts.len()).is_some() {
            return Err(ParseError::Invalid);
        }
        engine = name;
    }
    // Playwright's attribute engines accept an empty body, which matches an
    // empty attribute value. Every other engine rejects one.
    let attribute_engine = engine.strip_suffix(":light").unwrap_or(engine);
    if body.trim_matches(js_whitespace).is_empty()
        && engine != "nth"
        && !matches!(
            attribute_engine,
            "id" | "data-testid" | "data-test-id" | "data-test"
        )
    {
        return Err(ParseError::Invalid);
    }
    parts.push(Part { engine, body });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_chain_and_final_capture() {
        assert_eq!(
            parse(r#"css=ul[data-testid="items"] >> *css=li"#).unwrap(),
            vec![
                Part {
                    engine: "css",
                    body: r#"ul[data-testid="items"]"#
                },
                Part {
                    engine: "css",
                    body: "li"
                },
            ]
        );
        assert_eq!(
            parse(r#"[data-testid="row"] >> nth=2 >> [data-testid="conditions"] > div"#)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn quotes_escapes_and_unicode_are_not_chain_boundaries() {
        for selector in [
            r#"[data-x="a >> b"] >> span"#,
            r#"[data-x='a >> b'] >> span"#,
            r#"[data-x="a\" >> b"] >> span"#,
            r#"#a\>\>b >> span"#,
            r#"[data-x="日本 >> 文"] >> span"#,
        ] {
            let parts = parse(selector).unwrap();
            assert_eq!(parts.len(), 2, "{selector}");
            assert_eq!(parts[1].body, "span");
        }
    }

    #[test]
    fn capture_is_rejected_before_unsupported_engine_classification() {
        for selector in [
            "*css=article >> text=Hello",
            "css=ul >> *css=li >> nth=0",
            "*css=ul >> *css=li",
        ] {
            assert_eq!(parse(selector), Err(ParseError::Invalid));
        }
        assert!(parse("*").is_ok());
        assert!(parse("css=*").is_ok());
    }

    #[test]
    fn xpath_detection_and_negative_positions() {
        for selector in [
            "//div",
            "(//div)[2]",
            "..",
            "xpath=.//li",
            "css=ul >> xpath=//li >> nth=-1",
            "li >> nth=-2",
        ] {
            assert!(parse(selector).is_ok(), "{selector}");
        }
        assert_eq!(parse("((//div)[2])").unwrap()[0].engine, "xpath");
        for selector in ["css=", "", " ", "div >>", ">> div", "div >> >> span"] {
            assert_eq!(parse(selector), Err(ParseError::Invalid), "{selector}");
        }
    }

    #[test]
    fn positions_preserve_javascript_coercion_for_the_renderer() {
        for selector in [
            "li >> nth=NaN",
            "li >> nth=1.5",
            "li >> nth=0x2",
            "li >> nth=Infinity",
            "li >> nth=",
            "li >> nth=9007199254740992",
        ] {
            assert!(parse(selector).is_ok(), "{selector}");
        }
    }

    #[test]
    fn javascript_whitespace_is_not_rust_whitespace() {
        assert_eq!(
            parse("\u{feff}css=li\u{feff} >> nth=\u{3000}-1\u{00a0}").unwrap(),
            vec![
                Part {
                    engine: "css",
                    body: "li"
                },
                Part {
                    engine: "nth",
                    body: "\u{3000}-1"
                }
            ]
        );
        assert_eq!(parse("\u{0085}div").unwrap()[0].body, "\u{0085}div");
    }

    #[test]
    fn unsupported_engines_are_not_misclassified_as_css() {
        assert_eq!(
            parse("text=Bob's >> css=span"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            parse("text=\"hello >> there\" >> css=span"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(parse("role=button"), Err(ParseError::Unsupported));
        assert_eq!(parse("not-an-engine=button"), Err(ParseError::Invalid));
    }

    #[test]
    fn attribute_engines_keep_authored_bodies_literal() {
        for selector in [
            "id=row",
            "id:light=row",
            "data-testid=row",
            "data-testid:light=row",
            "data-test-id=row",
            "data-test-id:light=row",
            "data-test=row",
            "data-test:light=row",
        ] {
            let parts = parse(selector).unwrap();
            assert_eq!(parts.len(), 1, "{selector}");
            assert_eq!(parts[0].engine, selector.split('=').next().unwrap());
            assert_eq!(parts[0].body, "row");
        }
        for (body, expected_engine) in [
            (r#""a\"b""#, "data-testid"),
            (r#"a\\b"#, "data-testid"),
            (r#"x[y"#, "data-test-id"),
            ("日本", "data-test"),
            (r#""a >> b""#, "data-test:light"),
        ] {
            let selector = format!("{expected_engine}={body}");
            assert_eq!(parse(&selector).unwrap()[0].body, body, "{selector}");
        }
    }

    #[test]
    fn attribute_bodies_are_trimmed_exactly_like_every_other_engine() {
        // parseSelectorString trims the whole part before splitting on the
        // first `=`, so trailing whitespace disappears while whitespace right
        // after `=` stays in the body. A part that is only whitespace becomes
        // the same empty body as `attr=`, and U+0085 is not JavaScript
        // whitespace, matching String.prototype.trim.
        for (selector, body) in [
            ("data-testid=\u{00a0}", ""),
            ("data-testid= \u{3000} ", ""),
            ("data-testid=\u{0085}", "\u{0085}"),
            ("data-testid=  row  ", "  row"),
            ("data-testid= row", " row"),
        ] {
            assert_eq!(parse(selector).unwrap()[0].body, body, "{selector}");
        }
    }

    #[test]
    fn attribute_engines_accept_empty_bodies_but_other_engines_do_not() {
        for engine in [
            "id",
            "id:light",
            "data-testid",
            "data-testid:light",
            "data-test-id",
            "data-test-id:light",
            "data-test",
            "data-test:light",
        ] {
            let selector = format!("{engine}=");
            assert_eq!(parse(&selector).unwrap()[0].body, "", "{selector}");
        }
        for selector in ["css=", "css:light=", "xpath=", "text="] {
            assert_eq!(parse(selector), Err(ParseError::Invalid), "{selector}");
        }
    }

    #[test]
    fn attribute_engines_still_reject_capture_inputs_and_foreign_engines() {
        // Capture placement is independent of the engine, so the existing
        // final-only rule keeps applying to attribute parts.
        assert!(parse("*data-testid=row").is_ok());
        assert!(parse("css=div >> *data-testid:light=row").is_ok());
        assert_eq!(
            parse("*data-testid=row >> css=div"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse("data-testid=row >> *css=div >> nth=0"),
            Err(ParseError::Invalid)
        );
        assert_eq!(
            parse("data-testid=row >> css=div >> *nth=0 >> css=div"),
            Err(ParseError::Invalid)
        );
        assert_eq!(parse("role=button"), Err(ParseError::Unsupported));
        assert_eq!(parse("data-k=row"), Err(ParseError::Invalid));
    }

    #[test]
    fn parser_work_is_bounded() {
        assert_eq!(parse(&"x".repeat(65_537)), Err(ParseError::Limit));
        assert_eq!(
            parse(&vec!["div"; 257].join(" >> ")),
            Err(ParseError::Limit)
        );
        assert_eq!(parse(&vec!["div"; 256].join(" >> ")).unwrap().len(), 256);
    }
}
