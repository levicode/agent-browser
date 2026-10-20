# Maintain agent-browser as an independently pinned dependency

This design separates the formal agent-browser fork from its e2e consumer. It maintains one implementation with additive operation contracts and makes future upstream integration reviewable. The official comparison build is a separate source checkout, not a second runtime mode.

## Branch and change model

- The fork branch `upstream/main` is a visible mirror of the selected official upstream commit, with no downstream edits. A local checkout may additionally configure an `upstream` remote; distinguish `origin/upstream/main` (the fork mirror) from `upstream/main` (the official remote-tracking ref).
- The fork's `main` is the maintained integration line: upstream plus the reviewed native extension. Do not reset it to upstream or rewrite published history to perform upgrades.
- Build an `upgrade/upstream-<short-sha>` review branch from maintained main, merge one exact upstream commit, resolve semantic conflicts, and run both upstream and consumer gates. Move maintained main only through the repository's normal reviewed process.
- Keep extension work in focused families: exact refs/errors; scoped target lifetime/passive attachment; snapshot identity/completeness/policy; action semantics; CLI bridges; build/provenance/docs. One mixed patch may be retained as a generated export, but it must not remain the authoritative source.
- Do not couple an e2e upgrade to an agent-browser upgrade. Each repository gets its own upstream baseline and evidence. The current e2e `UPSTREAM_SYNC.md` wording about an upstream-tracking main must be reconciled with the branch policy actually chosen, rather than leaving two meanings of main.

## Migration and independent upgrades

1. Retain original provenance in Git history: upstream `1165952d74ceed98fdc2dd97190ad41f44dd0e24` and the former e2e patch. The maintained baseline is pinned in `upstream.json`.
2. Keep one shared implementation. Reuse upstream primitives; precise references and selection forms are explicit operation arguments, not a stock/strict execution switch. Remove superseded implementation and runtime patch application after cutover.
3. Guard inherited npm/release publication for the fork. CI produces provenance-bearing artifacts only.
4. Resolve semantic conflicts while preserving upstream changes, especially lossless method taps and blocked-document handling. Compilation is not behavioral proof.
5. Run native gates, independent official-baseline browser comparison, maintained-contract browser cases, and installed-consumer gates. Then promote the exact reviewed commit and update e2e's immutable source lock in its own review change.

## Source lock and build identity

Add one machine-readable source lock in e2e, consumed by its build script, compatibility preflight, packaging script, and CI. At minimum record:

- Canonical fork repository URL and full immutable fork commit SHA.
- Full upstream base SHA, extension contract version, and displayed CLI version.
- Pinned Rust toolchain, target triple, build profile and Cargo.lock digest; retain `--locked`.
- Supported/tested platform set and the Chromium revision/package pin used by the acceptance fixture.

Fetch the exact fork commit into an isolated checkout, verify it equals the lock, and reject a modified tracked or untracked source tree that could affect the build. Do not clean or overwrite an arbitrary developer checkout to make it fit. Build into an isolated target directory. The current script validates upstream HEAD and whether the patch can be applied or reversed; unrelated source edits can still coexist. That is weaker than proving the exact reviewed fork tree.

Artifact provenance should separately name:

- `nativeSourceRepository` and `nativeSourceCommit`, plus upstream base and contract.
- `consumerSourceRepository` and `consumerSourceCommit` when e2e validates/packages the native binary.
- Cargo.lock/toolchain/target, OS/libc, actual Chromium version, workflow run and attempt.
- Binary and archive hashes, architecture and mode, test-suite identity and results.

The existing packaging script already checks ELF/Mach-O architecture and emits hashes, OS, compiler and browser information. Preserve those checks. Replace its hard-coded upstream HEAD and e2e-patch hash dependency with the native source lock; do not merely relabel the old e2e commit as the native fork source. Source-reproducible does not mean byte-for-byte reproducible unless archive metadata, timestamps and build environment are also normalized and verified.

## Capability and version detection

The compiled `e2e-exact-1` contract is immutable for a binary, not a selectable mode. `capabilities --json` is browser-free. The consumer verifies the complete capability bundle and exact locked implementation version before input; each daemon command carries `expectedContract`. An incompatible live daemon must fail rather than silently reinterpret a request or restart into a different behavior.

Use implementation version and source SHA for provenance, contract version for compatibility, and e2e engine identity for replay semantics. Incompatible observation/action behavior advances the engine epoch (`agent-browser-exact-6` for this migration). Capability negotiation permits reviewed upgrades, never floating production binaries.

## One implementation, additive operation contracts

Keep upstream ordinary commands on shared upstream primitives. Exact references use the existing no-fallback ref property, requested by `snapshot --exact-refs` or an imported backend-node reference; do not maintain separate ref engines. Explicit selection forms express which option identity the caller means. Fill uses a single shared implementation, preserving normal text input and restricting DOM value setters to input types that need them; never use blanket contenteditable `textContent` replacement.

There is no stock/strict profile switch, old-patch fallback, or parallel runtime version in the delivered code. Official comparison tests build the pinned official commit into a separate isolated executable and compare observable results against the maintained executable. Keep behavioral contract tests after this migration; remove obsolete transition code.

The e2e companion owns target pause/resume, Fetch/auth and lifecycle setup for its dedicated endpoint. Scoped native attachment is passive; diagnostic trace only reads and must not reset refs, steal focus or modify input state. Scope checks do not justify shared-browser use.

## Regression matrix and upgrade gates

| Gate | Required evidence | Boundary |
| --- | --- | --- |
| Upstream repository health | Version sync, Rust format/clippy and native tests, launcher tests, and relevant upstream docs/MCP tests. Keep ordinary CLI/default paths covered, not only extension fixtures. | The existing e2e build script runs native binary tests but does not replace all inherited upstream CI. Never suppress newly failing upstream tests merely because e2e passes. |
| Native extension contracts | Exact-ref failure proofs; post-input uncertainty; literal parsing; scope latching; default-context proof; foreign-session no-touch; passive resume ownership; revoked/dead-probe cleanup; snapshot loader/ref behavior. | Inventory test names are listed next to each contract. Track ignored tests by identity/reason, not only their count. Retain actionable ignored browser tests in a separate explicitly invoked lane where their prerequisites are available. |
| Linux full consumer | Adapter build/typecheck/lint/units, every mandatory real Chromium integration file, focused unnamed-icon smoke, real ffmpeg test and fresh installed-package smoke. | Require zero skipped mandatory cases and preserve exactly-once external fixture mutation and zero-model-call proof. Repeat the complete suite on the same commit after the first green run. |
| macOS ARM64 and Intel | Native tests, adapter units, current locator/runner browser tests and fresh installed-package smoke on each architecture; verify binary architecture and manifests. | Current macOS workflows do not establish full pixel/state/network/video parity. Either retain that limited claim or add and pass those suites before expanding the support claim. |
| Privacy and lifecycle | Protected popup/OOPIF first requests, decoded PNG mask pixels, no screenshot fallback, callback expiration, exact scope refusal, lost input acknowledgment, state/reset/probe recovery. | These gates have historically caught failures after an initial green run. Do not substitute a mocked CDP test for real-renderer proof. |
| Consumer/source packaging | Clean checkout of locked native SHA; package install outside workspace; frozen reinstall; public types/imports; matching source hashes and native artifact hashes. | Do not mix the latest native artifact with an older e2e package merely because their display versions match. |

For each upgrade record the old/new upstream and native SHAs, reviewed conflict families, contract compatibility decision, test evidence, ignored-test changes, platform limitations, and any replay epoch change. A clean textual merge is only the start of review.

Do not infer hosted-provider acceptance, private-application acceptance, Windows support, older OS compatibility, Apple notarization, or shared-browser safety from these gates. Keep those boundaries visible in the install/compatibility documents.

## Patch retirement and release

Maintain a short registry keyed by guarantee, not by file. Each entry names its purpose, contract version, tests, upstream issue/PR if one exists, and exact removal condition. Prefer small upstream proposals: literal argument handling; non-mutating snapshot capture; at-most-once checkbox behavior; structured pre-input errors; passive scoped attachment.

When upstream lands an equivalent feature, test the upstream implementation with the existing strict negative cases, switch to it, remove only the redundant fork code, and run official-baseline comparison and maintained-contract acceptance again. Retain tests as durable contracts even after the implementation disappears. Do not count a renamed option or a new target-selection flag as an equivalent safety boundary.

Release remains an explicit decision after the exact commit has passed its gates. Do not publish the fork to upstream's unscoped npm package name or reuse upstream release credentials. A native-source migration can ship as source-pinned consumer evidence without changing package publishing identity at all.
