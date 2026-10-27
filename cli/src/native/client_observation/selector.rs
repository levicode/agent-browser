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
            // Playwright's visible engine takes no arguments but accepts any
            // authored body: `_createVisibleEngine` compares it to the exact
            // string "true", so `visible=`, `visible=false` and `visible=TRUE`
            // are all "not visible". The empty body is therefore legal.
            "visible" => {}
            // These Playwright engines are not CSS. Never pass their source
            // to Element.matches or silently reinterpret their semantics.
            "text"
            | "text:light"
            | "role"
            | "_react"
            | "_vue"
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
    // Playwright 1.64.1 refuses every top-level `nth` when the selector also
    // captures (`Can't query n-th element in a request with the capture.`).
    // It does so in InjectedScript.querySelectorAll, after engine-name
    // resolution and before the capture rewrite, so position, sign, repetition
    // and the captured part itself do not matter. Only a parsed `nth` engine
    // counts: a CSS body, an attribute body or a quoted text body that happens
    // to contain the characters `nth` stays literal data.
    //
    // This runs after the engine allowlist on purpose. Engines this adapter
    // does not implement must keep returning unsupported-capability rather than
    // being relabelled as an invalid locator, because that distinction drives
    // capability reporting. Pinned Playwright would execute those engines and
    // then hit the nth refusal, so a spec-native selector with an unsupported
    // engine still fails here, only with the adapter's own classification.
    if capture.is_some() && parts.iter().any(|part| part.engine == "nth") {
        return Err(ParseError::Invalid);
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
    // empty attribute value. The visible engine compares its body to "true",
    // so an empty body is meaningful there too. Every other engine rejects one.
    let attribute_engine = engine.strip_suffix(":light").unwrap_or(engine);
    if body.trim_matches(js_whitespace).is_empty()
        && engine != "nth"
        && engine != "visible"
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
    fn visible_engine_preserves_playwright_body_equality() {
        // Playwright's visible engine compares the authored body to the exact
        // string "true", so every other body (including empty) means false.
        // The shared part trim still runs before the split, as for any engine.
        for (selector, body) in [
            ("visible=true", "true"),
            ("visible=false", "false"),
            ("visible=", ""),
            ("visible=TRUE", "TRUE"),
            ("visible= true", " true"),
            ("visible=true ", "true"),
            ("visible=\u{00a0}", ""),
            ("visible= 日本", " 日本"),
            ("visible=\"true\"", "\"true\""),
        ] {
            let parts = parse(selector).unwrap();
            assert_eq!(parts.len(), 1, "{selector}");
            assert_eq!(parts[0].engine, "visible", "{selector}");
            assert_eq!(parts[0].body, body, "{selector}");
        }
        assert_eq!(parse("div >> visible=true").unwrap()[1].body, "true");
        assert_eq!(parse("visible=true >> visible=false").unwrap().len(), 2);
    }

    #[test]
    fn visible_engine_keeps_final_capture_and_chain_boundaries() {
        assert!(parse("*visible=true").is_ok());
        assert!(parse("div >> *visible=false").is_ok());
        assert_eq!(parse("*visible=true >> css=div"), Err(ParseError::Invalid));
        assert_eq!(
            parse("div >> *visible=true >> nth=0"),
            Err(ParseError::Invalid)
        );
        // A bare word with no `=` is still CSS, exactly as Playwright parses it.
        assert_eq!(parse("div >> visible").unwrap()[1].engine, "css");
        assert_eq!(
            parse("div >> visible=true >> >> span"),
            Err(ParseError::Invalid)
        );
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
    fn capture_refuses_every_nth_position_and_neighbour_engine() {
        // Pinned 1.64.1 InjectedScript.querySelectorAll rejects any top-level
        // `nth` once the selector captures, before the capture rewrite runs.
        // Position does not matter: before, after, negative, repeated, and the
        // captured part itself are all refused.
        for selector in [
            "css=li >> nth=0 >> *visible=true",
            "css=li >> nth=0 >> *visible=false",
            "css=li >> nth=0 >> *css=div",
            "css=li >> nth=0 >> *css:light=div",
            "css=li >> nth=0 >> *xpath=//li",
            "css=li >> nth=0 >> *data-testid=row",
            "css=li >> nth=0 >> *data-testid:light=row",
            "css=li >> nth=-1 >> *visible=true",
            "css=li >> nth=-2 >> *data-testid=row",
            "css=li >> *css=div >> nth=0",
            "css=li >> *visible=true >> nth=0",
            "css=li >> nth=0 >> nth=1 >> *css=div",
            "css=li >> nth=NaN >> *css=div",
            "css=li >> nth= >> *css=div",
            "css=li >> nth=Infinity >> *css=div",
            "li >> *nth=0",
            "*nth=0",
            "nth=0 >> *css=li",
            "xpath=//li >> nth=0 >> *css=div",
        ] {
            assert_eq!(parse(selector), Err(ParseError::Invalid), "{selector}");
        }
    }

    #[test]
    fn nth_without_capture_and_capture_without_nth_are_unchanged() {
        for selector in [
            "li >> nth=0",
            "li >> nth=-1",
            "li >> nth=0 >> nth=1",
            "css=ul >> nth=2 >> div",
            "section >> nth=NaN",
            "css=ul >> xpath=//li >> nth=-1",
        ] {
            assert!(parse(selector).is_ok(), "{selector}");
        }
        for selector in [
            "*css=li",
            "ul >> *css=li",
            "*visible=true",
            "div >> *visible=false",
            "*data-testid=row",
            "css=div >> *data-test-id:light=cell",
            "*xpath=//li",
            "css=ul >> *visible=true",
        ] {
            assert!(parse(selector).is_ok(), "{selector}");
        }
        // The existing final-only rule and the single-capture rule still
        // reject their own inputs.
        assert_eq!(parse("*css=li >> css=div"), Err(ParseError::Invalid));
        assert_eq!(parse("*css=a >> *css=b"), Err(ParseError::Invalid));
        assert_eq!(
            parse("css=div >> *css=span >> css=b"),
            Err(ParseError::Invalid)
        );
    }

    #[test]
    fn nth_text_never_participates_in_the_capture_rule() {
        // Only a parsed `nth` engine counts. Characters inside a CSS body, an
        // attribute body or a quoted text body stay literal data. A bare `nth`
        // has no `=`, so Playwright parses it as CSS with body "nth", not as
        // the nth engine; a naive substring check would wrongly reject it.
        assert!(parse("div:nth-child(1) >> *css=span").is_ok());
        assert!(parse("div[data-x=\"nth=0\"] >> *css=span").is_ok());
        assert!(parse("data-testid=nth=0 >> *css=span").is_ok());
        assert!(parse("*css=nth").is_ok());
        assert!(parse("css=ul >> nth-child >> *css=li").is_ok());
        assert!(parse("nth >> *css=div").is_ok());
        assert_eq!(parse("nth >> *css=div").unwrap()[0].engine, "css");
        assert_eq!(parse("css=li >> nth >> *css=div").unwrap()[1].engine, "css");
        // A quoted text part is still unsupported, not an nth capture refusal.
        assert_eq!(
            parse("css=li >> \"nth=0\" >> *css=div"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(parse("text=nth >> *css=div"), Err(ParseError::Unsupported));
        // Unsupported and unknown engines keep their existing classification
        // instead of being relabelled by the new capture rule.
        assert_eq!(
            parse("css=li >> nth=0 >> role=button >> *css=div"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            parse("css=li >> nth=0 >> text=Hello >> *css=div"),
            Err(ParseError::Unsupported)
        );
        assert_eq!(
            parse("css=li >> nth=0 >> bogus=1 >> *css=div"),
            Err(ParseError::Invalid)
        );
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
