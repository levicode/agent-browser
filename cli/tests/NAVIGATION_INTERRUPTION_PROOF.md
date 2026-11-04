# Pending navigation interruption proof

Scope: only the original `Page.navigate` response still pending after submission.
The existing retained producer and journal own both that response and the fixed
`Page.stopLoading` cleanup. No second producer, retry loop, fresh application lease,
or generic cleanup envelope is introduced. Reload, history navigation and the
post-response lifecycle/network-idle waits are unchanged.

## Evidence and limits

A successful private receipt requires all of:

- The same generation, operation, owner ledger, scope permit and target attachment.
- A bounded subscription with contiguous subscription-local sequence, no overflow,
  and a post-trigger `frameStartedNavigating` witness for the exact frame, requested
  URL and a loader distinct from the previous loader. Known pre-trigger starts
  cannot witness this request; previous-loader lifecycle events may be queued.
- The original navigation's exact tracked response acknowledging that frame and
  loader with `net::ERR_ABORTED` and boolean `isDownload: false`.
- The same journal's fixed stop-loading command acknowledged, then a drained
  stopped-loading event boundary without conflicting navigation or detach.
- No input/object debt or accounting integrity loss in the operation journal at
  final classification. Existing target-settlement integrity checks still apply.

A stop ACK alone, a successful control cancel, or zero scalar debt alone proves
none of this. Missing/optional/malformed loader or download evidence stays Unknown.
The receipt means the interrupted command and cleanup have terminal evidence, not
that navigation had no business effects, rolled back, or may safely be replayed.

The bound is the earlier of the existing producer retirement deadline and two
seconds from cleanup entry. The websocket sender checks that absolute bound and
exact ledger again while holding writer ownership, immediately before submission.
The public 250 ms result grace is unchanged. A result already fixed Unknown is
never rewritten when cleanup finishes later. Dropping the RPC waiter does not
abort the retained producer. Missing original/stop responses retain their debt.

The cause is captured once before cleanup. A cancellation observed before the
original operation deadline remains Cancelled even if cleanup crosses it. If the
original deadline has already elapsed at observation, DeadlineExceeded takes
precedence; this does not claim the undifferentiated cancel signal reveals whether
the caller or transport initiated it. No other operation's mapping changes.

## Exact Chrome source basis

The CI browser version is Chrome 156.0.8078.47. Its official Chromium tag resolves
to commit `1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775`:
https://chromium.googlesource.com/chromium/src/+/refs/tags/156.0.8078.47

`PageHandler::DispatchNavigateCallback` returns the navigation token as loader
for a started, cross-document navigation, its net error and `IsDownload()` boolean.
The unstarted/no-handle paths can omit loader/download fields and deliberately
cannot satisfy this proof. `NavigationReset` resolves the callback by exact token.
`DidStartNavigating` publishes the frame, URL and loader; loading-state changes
publish stopped-loading. These source details motivate the strict predicate,
not a claim that every valid Chrome response will satisfy it:
https://raw.githubusercontent.com/chromium/chromium/156.0.8078.47/content/browser/devtools/protocol/page_handler.cc

The protocol schema marks loader, error and download fields optional, so omission
must remain unknown rather than be coerced to false:
https://raw.githubusercontent.com/chromium/chromium/1d17a2e2ee147bb7d6ae2ab6abdb3a2510c17775/third_party/blink/public/devtools_protocol/domains/Page.pdl

`WebContentsImpl::Stop` requests frame-tree stopping; its command acknowledgement
is not substituted for the exact original navigation response:
https://raw.githubusercontent.com/chromium/chromium/156.0.8078.47/content/browser/web_contents/web_contents_impl.cc

## Validation status

Added source tests use the real retained producer, debt journal and CDP reader
with a mock websocket peer, plus closed predicate and writer-deadline negatives.
They are not a real Chromium proof, public CLI/adapter test, or timing guarantee.
No Cargo compilation, test execution, browser run or new CI was performed while
writing this change. Formatting/source checks are reported separately.
