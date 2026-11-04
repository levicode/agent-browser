# Initial navigation containment: separate contracts

## Required release gates

- `e2e_managed_blank_initialization_failure_prevents_navigation_request`: the managed native lifecycle creates `about:blank`, completes enrollment/settings, then navigates. Failed initialization must produce **zero application HTTP requests**.
- `e2e_popup_initial_request_is_contained_when_configuration_fails`: an initialized opener uses actual `window.open(initialUrl)`. The new target must be observed with the exact opener identity and fail its own configuration before resume. Failed configuration must produce **zero application HTTP requests**.
- Both tests require real hosted Chromium. Synthetic protocol tests alone do not establish either browser guarantee.

## External direct-URL ingress is not a containment guarantee

A different CDP actor can call `Target.createTarget({url: applicationUrl})` directly. Browser-managed navigation may begin before the page target is reported to enrollment. Enrollment cannot retroactively intercept an HTTP request already sent. It is not a context-wide firewall against another actor controlling the browser.

The raw direct-URL diagnostic retains the original zero-request assertion as a deliberately failing reproducer, not a release acceptance test. It must not be reported as a passing containment test, silently changed to allow favicon traffic, or used to claim that an observed request was prevented.

## Observed evidence

Hosted run `39582711985`, job `119163964694`, used official Chrome **156.0.8078.47** on Linux. The filtered trace recorded:

- HTTP `GET /must-not-start` at 100.754685 ms.
- `Target.attachedToTarget` for that URL at 108.496522 ms, with `waitingForDebugger=true`.
- Favicon HTTP traffic at 293.349805 ms.
- No native Continue decision before the initial HTTP request; the owned entry remained unresumed when configuration failed.
- The original zero-request assertion failed. The earlier request-read count was also two; no favicon exemption is applied.

This ordering distinguishes external navigation ingress from a separate, fixed native race in which a queued route callback could Continue before a later configuration ACK. The latter has deterministic held-ACK red/green tests covering registered and empty route lists, but those tests do not eliminate the external ingress boundary.

## Source grounding

Chrome 156.0.8078.47's `TargetHandler::CreateTarget` invokes `Navigate` before obtaining the target's DevTools agent identity:

https://raw.githubusercontent.com/chromium/chromium/156.0.8078.47/chrome/browser/devtools/protocol/target_handler.cc

Chromium's content handler separately documents renderer-side throttling for `window.open` and requires a waiting page/tab session for browser-side initial-request throttling:

https://raw.githubusercontent.com/chromium/chromium/main/content/browser/devtools/protocol/target_handler.cc

The second link is current source, not a pinned revision of the hosted binary. The new hosted fixtures print their actual browser product/revision and retain bounded, sanitized request traces.

Original Playwright 1.64.1 creates managed Chromium pages at `about:blank` before initialization. The negotiated native lifecycle follows that same blank-first boundary. The legacy native CLI tab-creation path is separate and is not advertised as having this new containment contract.

## Manual diagnostic invocation

Run only when deliberately reproducing the limitation, not as an acceptance gate:

```sh
cargo test native::client_enrollment::tests::diagnostic_external_direct_url_ingress_precedes_enrollment -- --ignored --exact --nocapture
```

Expected result for the observed Chrome build: **failure** of the zero-request assertion, with initial HTTP preceding attachment in the trace. This expected diagnostic failure is not a skipped supported capability or a passing test. The two release gates listed above remain required and must not be skipped.
