# Selector parser provenance

`selector.rs` adapts `parseSelectorString` from Playwright 1.64.1, `packages/isomorphic/selectorParser.ts`.

Playwright
Copyright (c) Microsoft Corporation

Licensed under the Apache License, Version 2.0. The repository's `LICENSE` contains the license. The Playwright distribution also gives this notice:

This software contains code derived from the Puppeteer project (https://github.com/puppeteer/puppeteer), available under the Apache 2.0 license (https://github.com/puppeteer/puppeteer/blob/master/LICENSE).

The source was read from the pinned `playwright-core@1.64.1` development dependency, `lib/coreBundle.js`. SHA-256 of the `parseSelectorString` function through the line before `parseAttributeSelector`:

`75d1d55b9c31acbb40f9c63f6f1d93db593d73164d96330649f1d82d2fa16001`

The Rust port keeps named-engine detection, quoted text and XPath detection, escapes, chain boundaries, and capture parsing. Native validation adds a 65,536-byte input limit, a 256-part limit, final-only capture, and an explicit engine allowlist. CSS, css:light, XPath, xpath:light, and nth are implemented by this change. Positions retain Playwright's JavaScript Number and Array.slice coercion. Other known Playwright engines return unsupported-capability rather than being interpreted as CSS. This is not a copy of the Playwright browser runtime.

`selector_query.js` is the native chain interpreter. Its CSS calls use browser CSS semantics, not Playwright's custom CSS evaluator. Playwright-only pseudo-classes and cross-shadow CSS combinators remain separate compatibility work. CSS chain steps search open roots; XPath does not pierce shadow roots. Neither crosses a closed root.

This change affects the negotiated E2E session adapter. It does not change the legacy CLI or MCP selector parser, so their command help is unchanged.
