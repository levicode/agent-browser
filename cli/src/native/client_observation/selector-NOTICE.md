# Selector parser provenance

`selector.rs` adapts `parseSelectorString` from Playwright 1.64.1, `packages/isomorphic/selectorParser.ts`.

Playwright
Copyright (c) Microsoft Corporation

Licensed under the Apache License, Version 2.0. The repository's `LICENSE` contains the license. The Playwright distribution also gives this notice:

This software contains code derived from the Puppeteer project (https://github.com/puppeteer/puppeteer), available under the Apache 2.0 license (https://github.com/puppeteer/puppeteer/blob/master/LICENSE).

The source was read from the pinned `playwright-core@1.64.1` development dependency, `lib/coreBundle.js`. SHA-256 of the `parseSelectorString` function through the line before `parseAttributeSelector`:

`75d1d55b9c31acbb40f9c63f6f1d93db593d73164d96330649f1d82d2fa16001`

The Rust port keeps named-engine detection, quoted text and XPath detection, escapes, chain boundaries, and capture parsing. Native validation adds a 65,536-byte input limit, a 256-part limit, final-only capture, the pinned nth-with-capture refusal, and an explicit engine allowlist. CSS, css:light, XPath, xpath:light, nth, the attribute engines below, and `visible` are implemented; the bounded raw `text`/`text:light` slice below is also implemented. Positions retain Playwright's JavaScript Number and Array.slice coercion. Other known Playwright engines return unsupported-capability rather than being interpreted as CSS. This is not a copy of the Playwright browser runtime.

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

The Playwright public locator layer additionally rejects selected `:light` projections as deprecated. `selector_public_check.js` reproduces that separate public check, retaining unchecked nested engine use and original projection timing; CSS `:light` is not deprecated.

## Visible engine

`visible` follows `_createVisibleEngine` in the same pinned bundle. SHA-256 of that method through the line before `_createInternalChainEngine`:

`31fd112748a2f2c0cf1ff20c2a8fec40efa8c967c3430e3d0ad6d9c2ef5eb02a`

It is a `queryAll` engine with no `matches`/`query` form: for each current chain root it returns that root when `isElementVisible(root)` equals `body === "true"`, and nothing otherwise. Three consequences are reproduced exactly:

- The body is compared to the exact string `true`. `visible=false`, `visible=`, `visible=TRUE`, `visible= true` and `visible="true"` all ask for invisible roots; only `visible=true` asks for visible ones. Native validation therefore accepts an empty body for this engine.
- A document/root node that is not an Element never survives, in either direction. `visible=true` and `visible=false` are both empty as the first chain part.
- The step filters the roots already selected by the previous part. It is not a descendant search, does not re-enter open shadow roots, and cannot enter a closed root.

The pinned helpers this depends on, each hashed through the line before the next symbol:

- `computeBox` through the line before `isElementVisible`: `4bf7c24ead72290045e62662cee6c68783d293a315ac257653cdd8f31fc86a0d`
- `isElementVisible` through the line before `var kTextNodeRange`: `125d32f1ee4e56e756167ba9643f6a2cf154a3044399245266934ec5172ba70c`
- `isVisibleTextNode` through the line before `function elementSafeTagName`: `4d1130355e08deeada248df05fd5f73d90d405f39b06bf4ae307f8a37c7012aa`
- `isElementStyleVisibilityVisible` through the line before `function isListBoxSelect`: `c23401047f83bc9a9f95092af0710d091fae187b5de26689d2be1cfe39a2b10b`

`selector_query.js` inlines the subset those helpers read. `getElementComputedStyle` becomes the document's `getComputedStyle`; the cache and the WebKit `<option>` workaround are omitted because this adapter does not negotiate WebKit. The result:

- `display: contents` has no box for `checkVisibility`. The element is visible when a light-tree element child is visible or a direct text node range has positive width and height. Its own `visibility` is not consulted, and its shadow root is not inspected.
- Every other element needs `checkVisibility()` (called with no arguments, so content-visibility and flat-tree state participate) and a computed `visibility` of `visible`, then a client rect with positive width and height. `opacity` is ignored.
- Zero-area boxes are invisible. `content-visibility: hidden` boxes that still have a positive rect are visible in Chromium, matching the pinned implementation rather than a semantic "hidden" reading.

This is Playwright rendering visibility, not the E2E reader's semantic `hidden` state and not the native `renderVisible` observation helper. It reads no input value, attribute, accessible name or closed-root inventory, and every root check charges the existing `matcherStep` budget. The `display: contents` walk reuses that same budget and adds the existing 256-level depth bound, so a pathological nesting chain is refused as a resource limit where Playwright would recurse without one. A final-only capture (`*visible=true` as the last part) stays a no-op, which is also what Playwright's capture rewrite produces when the capture is at the last part.

### Root matching in a chain

`visible` can return the very element a chain started from, as CSS `:scope` already can. Playwright's `has` engine evaluates its inner selector with the candidate element as scope and accepts that element as a match, so `locator('#row').filter({ has: locator('visible=true') })` keeps `#row` when it is visible. The native chain therefore admits the root it was given; every other result still has to be one of the issued elements, so this cannot widen the candidate inventory, read a closed root, or fabricate a node outside the acquisition.

## Capture and nth

Pinned Playwright refuses any `nth` combined with a capture. The refusal lives in `InjectedScript.querySelectorAll` in the same pinned bundle, whose opening capture branch runs before the capture rewrite and before any engine dispatch. SHA-256 of that method through the line before `_queryEngineAll(part, root) {`:

`bd3afc7f2ce001bc6292b19bda832a29d75b2a5f608322ab448cd35da606c3ec`

The relevant pinned source is:

```js
if (selector.capture !== void 0) {
  if (selector.parts.some((part) => part.name === "nth"))
    throw this.createStacklessError(`Can't query n-th element in a request with the capture.`);
```

Three consequences are reproduced:

- The predicate is over every *top-level* parsed part, matched on the resolved engine name `nth`. Position is irrelevant: `nth` before the capture, after it, on the captured part itself and repeated all fail. Sign and value are irrelevant too, so `nth=-1`, `nth=NaN`, `nth=Infinity` and the empty `nth=` body all fail when a capture is present.
- The check is structural, not textual. `div:nth-child(2)`, `div[data-x="nth=0"]`, `data-testid=nth=0`, `*css=nth`, and a bare `nth` word (which Playwright parses as CSS with body `nth`) do not name the engine and stay legal alongside a capture.
- Nested selectors are separate parser results. A capture in the outer chain with an `nth` only inside a nested engine body keeps the outer chain's parts free of `nth`, so pinned Playwright accepts it; a capture inside a nested body is refused there on its own. The native adapter does not implement those nested engines at all, so this only documents why the rule is evaluated per parser result and never over raw text.

Native ordering: the rule runs after the engine allowlist because an engine this adapter does not implement must keep returning unsupported-capability rather than being relabelled as an invalid locator. For a selector containing only implemented engines the result matches pinned Playwright exactly: `INVALID_LOCATOR`. A chain that mixes an unimplemented engine with `nth` plus a capture is still refused, only under the adapter's own classification.

Capture placement itself is unchanged. The adapter still requires the single capture to be the final part, which is stricter than pinned Playwright's capture rewrite; that bounded-subset difference is recorded in the provenance summary above and is not widened here.

This change affects the negotiated E2E session adapter. It does not change the legacy CLI or MCP selector parser, so their command help is unchanged.


## Bounded raw text slice (original baseline 40663028464)

`selector_text_matcher.js` derives the raw/internal text matcher primitive from pinned1.64.1 `createTextMatcher`/`cssUnquote`; `selector_text_query.js` implements raw root/self/child matching using existing issued CSS inventory and private text acquisition. Original public baseline confirms normalized lax text, quoted immediate-text equality, full-text regexp, implicit quoted input, Element-root inclusion and nonempty public `text:light` rejection. Exact original identities/error taxonomy, not semantic getByText approximations, are the paired gate.

No new value/read authority: full text remains `matcherText`, with the existing secure/protected subtree refusal, no closed-root discovery and no editable value reads. Immediate facts read only direct text nodes after successful full-text policy checks and charge the existing per-root1MiB/aggregate8MiB/work/depth budgets. Noneditable submit/button/reset labels reuse the already acquired full text, not a second value read. A protected/unknown parent is not proof that ordinary descendants fail; lax pruning is only applied to a proven nonmatch. Raw text matcher syntax failures have a private opaque sentinel mapped to backend failure, preserving original public engine failure without returning selector/error payloads. Structural selector errors remain distinct typed InvalidLocator.

Limits remain explicit: empty raw bodies still follow existing local refusal pending a dedicated original/candidate boundary matrix; internal:text and other raw internal/extendedCSS engines remain unsupported, and raw role is implemented in its own section below. This six-observation slice does not close #30/#12, nor claim complete Unicode, malformedbody, nestedframe, security or resource-limit parity solely from source tests. Shared quote/capture/part limits remain in selector.rs; typed wire AST is unchanged. Actual public candidate acceptance is required after integration.

### Bounded raw internal composition increment

`selector_internal_query.js` derives the nested-body lexical parser, five composition engines and shadow-aware DOM ordering from installed Playwright 1.64.1. It runs only inside the existing private MATCH_QUERY realm and returns indices from the existing issued inventory. `internal:has` / `has-not` preserve relative-root checked-query light deprecation; `and` / `or` / `chain` use unchecked nested query-all. `and` retains RHS order, `or` uses the pinned DOM ordering rather than inventory order. JSON bodies are decoded in JavaScript without changing UTF-16 data. Malformed JSON becomes an opaque backend failure, matching the measured original public baseline; no authored body is returned in diagnostics.

Adaptations are bounded input (64 KiB), aggregate 256 compiled parts, 64 nested levels, shared matcher work and 256 DOM-order ancestor depth; compiled arrays are frozen and cached per query, not across queries. Ancestors visited for ordering are never admitted as matches. Capture, frame control/prefix and unavailable nested engines remain explicit unsupported capabilities. This is NOT complete raw-internal support: internal text/role/label/attr/testid, extended CSS parsing, malformed non-JSON taxonomy and nested capture still require implementation/paired acceptance. No new AX/public-name approximation or editable-value acquisition is introduced.

The actual original acquisition run 40663028464 supplies five ordered-ID outcomes and one count-stage nonretryable ENGINE_FAILURE. Production DOM-double tests and source comparisons are not native/browser/public acceptance; the same strict six-observation public fixture must run on original and candidate.

### Finite extended CSS production wiring

The complete pinned CSS parser classifies every CSS part before DOM traversal. ASTs containing text/text-is/text-matches/has-text/visible/nth-match/light/layout functions (including nested functions) execute as complete ASTs in the guarded evaluator. Existing ordinary native CSS remains on its existing path. This is syntax capability dispatch, never regex stripping, parser-error swallowing, or fallback after policy refusal. Ordinary :is/:not/etc without these extensions has not been globally rewritten; full CSS parity remains open.

The new owner adapter uses this MATCH_QUERY's selected document, issued Element inventory, native structural interfaces and shared work/character limits. Complete authorized light/open structure is proven before native CSS atoms; no query Element grants another root/frame/closed-shadow lease. Text/geometry/output require issued elements, protected text is unavailable through negation, and private values are never newly authorized. Unknown/missing DOM interfaces refuse except the explicit standard absence of shadowRoot on non-Elements. Syntax/invalid-engine-output is opaque backend failure; unavailable and resource-limit remain distinct. Fractional nth-match public taxonomy still needs original measurement, even though undefined output is now rejected as opaque engine failure, never admitted.

Preserve selector-css-NOTICE with the full installed upstream Microsoft/Puppeteer notice and existing attribution. Generated source, source hashes, TS5.9.3/PW1.64.1 generators and pure tests are shipped. Production MATCH_QUERY DOM doubles and module source comparisons are not actual native/browser/public acceptance.

## Raw role engine (original gate e2e#31)

`selector_role_query.js` ports the pinned Playwright 1.64.1 raw `role=` engine. The parser accepts the engine name in `selector.rs`; the typed body stays authored source and is parsed in the renderer exactly like `parseAttributeSelector(body, true)`. The body parser, query, ARIA role computation, hidden rule, accessible name/description computation, state attributes and generated-content contribution are derived from these pinned modules. Hashes are SHA-256 of the injected source string carried by `lib/coreBundle.js`, each segment from the named start through the line before the named end:

- `roleSelectorEngine.ts` through the line before `selectorEvaluator.ts`: `e7e2d574d5f66939343ca0ba40ffe3a1aededb4cbc1506fe219df51e07e6b7cd`
- `roleUtils.ts` through the line before `ariaSnapshot.ts`: `53516eb98fe2f670364146bb29e9e88bae68b3a77bb254a5e0f2395eb34f8aca`
- `parseAttributeSelector` through the line before `locatorGenerators.ts`: `8a8e4896d8e483131ec711dee37d181486138c0c68b6fbd8f79b25bcab213677`
- `matchesAttributePart` through the line before `shouldSkipForTextMatching`: `24ec046319297747e7e10596efd9930667bab1ed4dffc72ab61ea7fa4b1da5c5`
- `domUtils.ts` through the line before `roleUtils.ts`: `5e3019d0d9457029e663cec92c24884ea83bbc7c2c8d8fb76e6e871104718557`
- `normalizeWhiteSpace` through the line before `normalizeEscapedRegexQuotes`: `6676d7a20fc579904a9d7eeaffcc0125beaf08ed654beda0fc187a87039d8109`

The engine is registered by Playwright as `role` with `internal=false`: a name string is matched exactly after whitespace normalization unless the `i` flag or a regular expression says otherwise, and only `internal:role` lowers `=` to a substring test. The native adapter implements the public `role` engine; `internal:role` stays an unsupported capability.

### Parsed form and typed body

- `role=<name>` uses the pinned agent lowercase; an empty role name is an invalid locator.
- The typed body accepts `[selected]`, `[checked]`, `[pressed]`, `[expanded]`, `[level=…]`, `[disabled]`, `[name=…]`, `[description=…]` and `[include-hidden]`, with the pinned `true`/`false`/`mixed` value and operator validation. Unknown attributes, unknown operators, a truthy `name`/`description`, a non-numeric level and a malformed quoted/regexp value are invalid locators, matching the pinned parser's refusals.
- Quoted strings and regular expressions keep the pinned escaping and flag rules. The body is never interpolated into CSS or code.

### ARIA matching and root rules

- A role part is a descendant query over each current chain root, so `role=button` never returns the document, and `css=section >> role=button` searches inside each section only. This is the pinned "root" rule; Playwright 1.64.1 exposes no `root=` typed attribute, so none is accepted.
- The query walks light descendants in document order and then each discovered open shadow root, recursively. A host's shadow root is searched even when the chain root is the host element (`css=[data-id=host] >> role=button`). Closed roots are never entered, and a match outside the issued inventory is not admitted.
- Explicit `role` tokens are intersected with the pinned valid-role list, implicit roles come from the same tag map, and `none`/`presentation` resolve exactly as the pinned conflict rule.
- With `include-hidden` absent, an element hidden from the accessibility tree (ignored tags, `display:none`, `visibility:hidden`, zero-area, `aria-hidden`, non-slotted shadow content, `display:contents`) does not match. `include-hidden=true` keeps it and also expands the name computation, as pinned.
- States are read from the pinned native/ARIA rules: `selected`, `checked` (including `mixed` and indeterminate), `pressed`, `expanded`, native/ARIA `disabled`, and `level`. `description` reads `aria-describedby`, `aria-description` then `title`.

### Accessible name

The accessible-name computation is the pinned `getTextAlternativeInternal` graph: `aria-labelledby`, `aria-label`, associated labels, native input/fieldset/figure/table/svg/img alternatives, name from content with non-inline spacing, slot assignment, `aria-owns`, and generated `::before`/`::after` content. Generated content accepts only the token shapes the pinned parser accepts (strings and `attr(<ident>)` after an optional `/` alternative); any other token stream contributes nothing, which is the pinned result. Names are whitespace-normalized before comparison.

### Bounded differences

- This adapter targets Chromium only, so the pinned WebKit listbox-`option` visibility workaround is omitted, matching the existing `visible` engine note.
- Accessible-name acquisition refuses text and editable values under an existing secure field or a protected ancestor (the same policy `matcherText` already enforces). Playwright would read them. A page that puts a password value or protected text inside a name-bearing element can therefore disagree; the ledger fixture contains no such case and no private value is newly authorized.
- Recursion is bounded by the existing matcher work budget and a 256-level structural depth; a pathological tree is a resource limit where Playwright has no such bound.
- The role engine runs only in the existing isolated query realm over already-issued elements; it creates no frame, root, closed-shadow or value authority.
- `role` is a plain leaf in the existing private raw-chain compiler (`rawInternalPlainEngines`). It is not an `internal:` composition engine, so `internal:role` stays an unsupported capability while a nested `internal:has="role=…"` compiles like any other supported leaf.
