# Selector parser provenance

`selector.rs` adapts `parseSelectorString` from Playwright 1.64.1, `packages/isomorphic/selectorParser.ts`.

Playwright
Copyright (c) Microsoft Corporation

Licensed under the Apache License, Version 2.0. The repository's `LICENSE` contains the license. The Playwright distribution also gives this notice:

This software contains code derived from the Puppeteer project (https://github.com/puppeteer/puppeteer), available under the Apache 2.0 license (https://github.com/puppeteer/puppeteer/blob/master/LICENSE).

The source was read from the pinned `playwright-core@1.64.1` development dependency, `lib/coreBundle.js`. SHA-256 of the `parseSelectorString` function through the line before `parseAttributeSelector`:

`75d1d55b9c31acbb40f9c63f6f1d93db593d73164d96330649f1d82d2fa16001`

The Rust port keeps named-engine detection, quoted text and XPath detection, escapes, chain boundaries, and capture parsing. Native validation adds a 65,536-byte input limit, a 256-part limit, final-only capture, and an explicit engine allowlist. CSS, css:light, XPath, xpath:light, nth, and the attribute engines below are implemented by this change. Positions retain Playwright's JavaScript Number and Array.slice coercion. Other known Playwright engines return unsupported-capability rather than being interpreted as CSS. This is not a copy of the Playwright browser runtime.

`selector_query.js` is the native chain interpreter. Its CSS calls use browser CSS semantics, not Playwright's custom CSS evaluator. Playwright-only pseudo-classes and cross-shadow CSS combinators remain separate compatibility work. CSS chain steps search open roots; XPath does not pierce shadow roots. Neither crosses a closed root.

## Attribute engines

`id`, `data-testid`, `data-test-id`, `data-test` and their `:light` variants follow `_createAttributeEngine` in the same pinned bundle. SHA-256 of that function through the line before `_createCSSEngine`:

`91e247b3de8f9d7928cc9039209df1e49d854eb76304d13bbea18fa68ecc5e17`

Playwright builds `[<attribute>=${JSON.stringify(body)}]` and evaluates it with its CSS parser, piercing open roots unless the engine is a `:light` variant. The native interpreter reproduces that string bridge exactly, so the body is data and never re-parsed as a selector:

- The body is the authored text after the first `=` with no unquoting or unescaping. `data-testid="a"` looks for the three-character value `"a"` including the quotes.
- An empty body is legal and matches an empty attribute value; an absent attribute never matches. Native validation therefore accepts an empty body only for these engines.
- `JSON.stringify` escapes then CSS decodes, so a newline body `a\nb` searches for `anb`, `a\fb` searches for `a` plus U+00FB, and `a\u0000b` searches for `au0000b`. A literal backslash body `a\b` still searches for `a\b`, and `a\\b` searches for two backslashes.
- Bodies are case sensitive. The shared chain parser trims the whole part first, so trailing whitespace after the body disappears and whitespace directly after `=` remains part of the value, exactly as `parseSelectorString` behaves for every named engine.
- Plain engines pierce open roots through the existing traversal; `:light` variants stay in the light tree. No variant enters a closed root.

The Playwright public locator layer additionally rejects a `:light` match as a deprecated selector. That refusal lives above the engine and is not reproduced here, so this adapter returns the engine result.

This change affects the negotiated E2E session adapter. It does not change the legacy CLI or MCP selector parser, so their command help is unchanged.
