# Maintained e2e CLI contract

This repository is a downstream fork of `vercel-labs/agent-browser`, not a replacement official distribution. The upstream baseline, native version, adapter contract and consumer replay epoch are recorded in `upstream.json`. Builds consumed by e2e are pinned to an immutable fork commit and tree; `main` is not a floating production dependency.

## Why these native changes remain

The ordinary upstream snapshot/reference/action loop already discovers and clicks unnamed controls. The current implementation depends on native extensions for its selected strict contract, not because agent-browser usage in general requires a fork. Which extensions remain is a design decision subject to upstream comparison and explicit compatibility tradeoffs. Exact node identity, no hidden second click, pre-dispatch versus uncertain input classification, and immutable target/context lifetime cannot be enforced equivalently by an external pre-check while the native implementation can still rebind or retry internally. CLI bridges such as label/index selection and pointer-state reads are implementation conveniences with specified semantics, not inherently necessary reasons to fork.

The complete necessity audit, current default-impact differences, test names and retirement conditions are in [NATIVE_CHANGE_INVENTORY.md](NATIVE_CHANGE_INVENTORY.md). Do not remove tests or weaken safety merely to reduce diff size. Keep request routing, screenshot protection, state orchestration and test reporting in e2e rather than growing a second framework here.

## CLI-only extension surface

- `--cdp-dedicated --cdp-target TARGET --cdp-context CONTEXT` scopes an externally attached native daemon to one dedicated endpoint and immutable context. The scope pair requires explicit `--cdp` and `--cdp-dedicated`. The dedicated flag is the caller’s ownership declaration, not proof that an arbitrary endpoint has no other clients. The literal `default` context is not a wildcard. Every later command must retain the same pair.
- `ref BACKEND_NODE_ID --frame FRAME_ID` imports a live, document-bound reference for the adapter's locator result. Stale or AX-only references do not resolve to same-name replacement nodes.
- `snapshot --exact-refs` requests no-semantic-fallback identities through the existing upstream exact-ref primitive. Ordinary snapshots retain semantic references through that same reference map.
- `snapshot --allowed-frame-documents JSON` and `snapshot --preserve-refs` preserve child-loader policy and existing exact identities during trace capture. They do not authorize shared-browser usage.
- `keyboard type --physical -- TEXT` requests physical mapped key events with trusted insertion for unmapped Unicode. Ordinary keyboard typing and element typing retain insertion semantics through the shared primitive; CDP scope never implicitly changes typing semantics.
- `click` and `dblclick` support `--modifiers`; `select` supports explicit `--value`, `--label` and `--index` modes. Use the parser's literal `--` data boundary for values that resemble flags.
- `tab TARGET --no-activate` supports trace binding without focus changes. `mouse state` reports native held-button state without generating input.
- A failure explicitly carrying `data.dispatched: false` and a recognized closed native error code is pre-input failure proof. All other failures after an input may be uncertain; consumers must not automatically retry them.

These adapter extensions are intentionally omitted from the MCP tool schema. e2e owns the endpoint, scope and companion lifecycle; a second MCP owner is outside the supported contract. Existing MCP commands continue delegating to the shared CLI parser. Internal target ownership remains outside the MCP surface.

## CDP ownership

For the dedicated endpoint the e2e companion is the sole owner of target pause/resume, Fetch/auth, route policy and provider lifecycle. Native may establish its own non-pausing observation sessions, including OOPIF auto-attachment with `waitForDebuggerOnStart:false`, and enable the read protocols it needs. This is distinct from controlling pause/resume. Scoped native attachment must not respond to Fetch or authentication events, resume paused targets, or install competing network controls. Conflicting native network-control options fail closed. Diagnostics must not activate tabs, clear references or modify held input state. Native scope checks fence its own actions; they do not claim to sandbox unrelated clients on a shared browser.

## Retry and side-effect boundaries

Native no-silent-rebinding is different from the e2e core intentionally re-observing and relocating after a proven pre-dispatch `NODE_STALE`. The adapter can retain the latter recovery without replaying an uncertain input. At-most-once native input dispatch is also not business-operation idempotence: one click can trigger multiple application requests, and application handlers can have their own retries. The implementation does not guarantee exactly-once business effects.

## One implementation and explicit operation semantics

The binary exposes one compiled `e2e-exact-1` contract. `capabilities --json` does not start or touch a browser. `--expect-contract e2e-exact-1` validates compatibility, including the live daemon; it does not select another runtime or retain an old implementation.

Ordinary upstream operations share their implementation with the extensions. `snapshot --exact-refs` requests refs with the existing no-role-fallback identity property. The imported `ref` command uses that same primitive. Selection arguments identify the intended value, label or index. Normal text fill follows the upstream input path, with narrowly supported value-setter types, not a blanket synthetic DOM/textContent replacement. Precise operation parameters are not separate stock/strict versions.

The official baseline is built separately for comparison tests. It is not embedded or selected by a runtime switch. Superseded patch loading and duplicate implementation are removed after cutover; historical recovery belongs in Git history.

## What exact references do not guarantee

Exact references prevent semantic rebinding to a same-name replacement. Coordinate-based input is still resolved and dispatched in separate CDP operations; animation, overlays or DOM changes between them can affect the eventual hit target. The contract does not claim an atomic browser-side node click or elimination of all time-of-check/time-of-use races. Preserve actionability tests and treat uncertain side effects conservatively.

## Compatibility and verification boundary

Only dedicated Chromium endpoints are supported by the consuming e2e adapter. Native contract CI runs upstream plus extension Rust tests and builds Linux x64, macOS ARM64 and macOS Intel artifacts. Ignored upstream browser/Obscura tests remain visibly ignored and are not counted as runtime acceptance. Full real-browser, privacy, video, state and installed-package acceptance runs in `levicode/e2e` against the exact fork SHA. macOS currently uses the narrower operation/replay/installation matrix; it is not full Linux-matrix parity.

No npm package or GitHub release is automatically published by this fork. CI artifacts include source provenance and hashes. Repository history and CI artifacts are not private-application UAT. See [UPSTREAM_SYNC.md](UPSTREAM_SYNC.md) for explicit candidate upgrades and release gates.
