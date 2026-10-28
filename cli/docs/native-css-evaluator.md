# Guarded Playwright CSS evaluator — source-only increment

## Provenance and regeneration

Derived from Microsoft Playwright 1.64.1, Apache-2.0, installed `playwright-core/lib/coreBundle.js` injected source. Source modules: `selectorEvaluator.ts`, `layoutSelectorUtils.ts`, `parentElementOrShadowHost` from selector utilities, and `normalizeWhiteSpace`. Generator manifest pins the entire decoded injected source and extracted slice. The helper retains the Microsoft copyright/license notice. Upstream license: https://github.com/microsoft/playwright/blob/v1.64.1/LICENSE . No runtime dynamic evaluation: source decoding/evaluation is confined to generator/test tooling.

```
PLAYWRIGHT_CORE_DIR=/path/to/playwright-core TYPESCRIPT_LIB=/path/to/typescript/lib/typescript.js node cli/scripts/generate-native-css-evaluator.cjs
PLAYWRIGHT_CORE_DIR=/path/to/playwright-core node cli/tests/fixtures/native-css-evaluator.cjs
```

Requires exactly PW 1.64.1 and TS 5.9.3. `RAW_CSS_PACKET_ROOT` optionally overrides repository output root. Regeneration changes only evaluator and manifest. Policy is handwritten and independently reviewed. Parser dependency is the separate `createRawCssParser(sharedStep, matcherLimit)` increment; pass its `.selector` AST, not an arbitrary unbounded object.

The AST transform charges 74 function entries (depth 256), 12 loops, redirects 27 structural property reads, exactly 3 native atom call sites (only `root.querySelectorAll` / `element.matches`, never engine.matches), and 2 rectangle calls. Exact custom-pseudo algorithms and query-local caching remain upstream. Native CSS atoms remain native qSA/matches with unchanged CSS, never regex-stripped or replaced by per-element filtering.

## Integration contract

`createRawCssPolicy(authority, native, sharedStep, matcherLimit, unavailable)` yields the policy for `createRawCssEvaluator(policy, sharedStep, matcherLimit, unavailable)`.

Evaluator exposes `query(context, ast)` and `matches(element, ast, context)`. Context is the upstream `{scope, pierceShadow, originalScope?}` shape. Every top-level call creates a fresh upstream evaluator and revokes the proof in finally, including failures. Caller preserves malformed/backend errors, private unavailable, and matcherLimit as distinct sentinels; no catch-to-false/empty. The shared budget must not reset during recursion.

Authority requires captured owner `document`, predicates `isAuthorizedNode`, `isAuthorizedRoot`, `isIssued`, and existing bounded `textFacts`, `textMatch`, `isVisible`, `skipText` callbacks. Structural document authority is not inferred from Element query scope. Predicates must use existing ownership/custody; a blanket true callback is invalid. Geometry and text require issued nodes in addition to structural proof. `textMatch` accepts only none/self/selfAndChildren; existing protected is converted to unavailable. Null or invalid text facts likewise fail, including inside :not. Callback implementations must preserve their existing descendant text privacy/work bounds.

Native primitives `read`, `querySelectorAll`, `matches`, `rect` must be trusted isolated-realm accessors/methods, not attacker-overridden properties. `read` supplies constant DOM links including firstChild/nextSibling/previousSibling. Element sibling navigation is implemented as charged link walks, not uncharged native firstElementChild/nextElementSibling/previousElementSibling scanning. documentElement uses the bounded first-element walk.

Complete structural preflight covers the already owner-authorized document, ancestors/light tree and authorized open shadow roots. Each node is authorized before read; parent and document identity are checked. No iframe document/closed root/payload reads. Proof is committed only when complete, max 100000 nodes and depth 256. If full authority/completeness cannot be established, private unavailable is required, with no native scan or output expansion. Final output must already be issued. Structural-only authorized nodes do not grant geometry/text access.

Each native CSS call prepays all proof nodes plus authored CSS character work (64KiB UTF8 limit). This bounds admission/work accounting, **not browser CPU instructions** or native RegExp CPU. Retain the enclosing owner operation deadline and source budgets. qSA iterator materialization is also bounded and authorized. Proof/cache never survives a query; asynchronous DOM mutation or reentrancy requires the caller's existing isolated execution boundary.

## Evidence and remaining gates

Pure JS differential fixture: 58 evaluator comparisons, 12 matches comparisons, 10 parser-rejected inputs (not evaluator passes), six explicit original public baseline identities, 10 authority/privacy controls, repeated-native-scan charging, failure restoration, and a 30-comment sibling traversal fresh-budget negative control. Test uses exact installed upstream algorithms and explicit DOM/CSS/text/rendering primitives; it is **not real browser/native runtime evidence**. Its native nth-child-of-scope case proves unchanged qSA delegation only, not full browser semantics. The separate parser's 67 comparisons are not included in this evaluator count.

All required custom engines are represented, including layout and shadow-order cases. Source review/integration and same-fixture original/candidate real public gates are still required; this increment alone does not close #32. Initial development found and corrected an overbroad generator rewrite of engine.matches; receiver-specific rewrite plus differential/explicit six-ID checks prevents silently shared failures. Historical module-only packet e492 did not edit production/shared parser or query files. This producer integration does edit MATCH_QUERY and selector_query.js, registers the owner adapter, and requires its own review and public runtime acceptance.

## Combined parser packet

This packet includes the exact tokenizer/parseCSS generator and production createRawCssParser. Generate with the same env pins using cli/scripts/generate-native-css-parser.cjs; test cli/tests/fixtures/native-css-parser.cjs. Pure parser67AST/error comparisons+4limits. The combined evaluator test now feeds candidate parser AST into58evaluation/12matches and all6actual original baseline cases, while expected outcomes use pinned parser/evaluator. This narrow test-wiring delta does not change evaluator production bytes. No real DOM/runtime acceptance from these doubles.

## Upstream NOTICE and finite error boundary

`cli/src/native/client_observation/selector-css-NOTICE` carries the complete unmodified installed Playwright1.64.1 NOTICE (Microsoft and Puppeteer attribution), SHA256 `6d602191187b35b9b01d2cffa01c8469c2c8d9de8a96f1bf868e0f264f51c81d`. Keep it alongside distributed derived CSS code and the host Apache-2.0 LICENSE. This increment does not replace/remove the existing `selector-NOTICE.md`; exact native base tree0bc8 has no root NOTICE and its existing selector notice is retained unchanged. Rebase/packaging must preserve both notices, never overwrite unrelated attribution.

The finite source contract concerns valid issued-node outputs. An added reviewer case `:nth-match(.row,1.5)` exposes upstream evaluator `[undefined]`, which the historical module-only e492 wrapper rejected as private unavailable rather than admitting invalid output. The producer integration now rejects nullish engine output and private DOM-operation receivers as opaque engine errors before authority checks; genuine-node authority failures and legitimate absent property values are unchanged. Original public-layer behavior/error taxonomy for this case remains unmeasured; do not claim full malformed/invalid-output parity or close this #32 edge. No authority checks were weakened to imitate undefined output.

Production integration delta (separate from module-source GO): the owner wrapper now rejects undefined/null engine output and all private DOM-operation receiver inputs with an opaque engine error before issuance/authority checks. It never returns invalid nodes; original public fractional-nth classification remains pending a baseline observation. This narrow generated-wrapper change must be reviewed with producer integration, not inferred from module GO.
