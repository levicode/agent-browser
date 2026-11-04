# Bounded production cleanup and failure diagnostics

This is a default-off production diagnostic, not an acceptance-fault capability,
public protocol, cleanup proof, or change to error semantics. The existing
acceptance phase file remains separately opt-in and feature-gated at its callers.

## Activation and transport

The controlled test harness may set `AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE` to an
already-created absolute regular file before starting the native daemon. Native
startup reads that variable once. An absent, invalid, relative, missing, symlink,
or nonregular destination disables capture. Native does not create, truncate,
reopen, repair, or retry the file. Never derive this path from website content.

The existing append sink is reused: in-process `try_lock`, nonwaiting OS file
lock, Unix `O_NOFOLLOW | O_NONBLOCK`, at most 2,048 lines / 256 KiB across all
processes sharing the file, and at most 512 bytes per line. Lock contention drops
observations. The last available slot is a `CaptureLimitReached` marker. A partial
write or prior partial artifact stops that sink without altering the artifact.
Regular-file I/O itself is synchronous, so no claim of a filesystem latency bound
is made. Cleanup hooks and retained cleanup workers perform no diagnostic I/O;
completed snapshots are emitted by awaiting lifecycle wrappers after receiving
the retained result. A dropped waiter, hung cleanup, process death, failed write,
limit, overflow, or incomplete snapshot is unknown, never a cleanup success.

No new task, cleanup obligation, owner registry, retry, timeout, or protocol field
is introduced. The owner-local cell and immutable observer tokens retain only
numeric diagnostics, not a browser/client, native identity, task, or authority.
Dropping a diagnostic attempt resets only that attempt's cell. Late observers
cannot attribute a former attempt's failure to a newer attempt.

The same default-off production sink also accepts one `ScreenshotFirstFailure` record per failed trace-purpose screenshot that reaches observation dispatch. Preparation failures emit immediately when no work has begun. Running requests retain their first failure locally, then emit only after the run and any mandatory restoration reach a terminal result, including failed restoration. Diagnostic I/O is therefore after that settlement and before the worker returns its result, not inside restoration. No diagnostic lock is held across an await. Disabled diagnostics, successful screenshots, and non-trace screenshots emit no screenshot records. A nonterminal restoration or process death can leave no record; absence remains unknown.

`ReadonlyPrepareFailure` uses the same sink only for failed read-only Swipe preparation that entered `center` without any application mutation submission. One local cell retains scalar timing observations and is consumed once after the action's existing release/input cleanup and final result mapping. It is not active for Tap, does not change the one-second caller budget or the 250 + 16 ms classification floor, and supplies no scheduling, receipt, or settlement authority. Disabled capture, successful actions, and paths that submit an application mutation emit no such record. Earlier admission failures and nonterminal cleanup have no record and remain unknown.

## Frozen JSONL schema

Every record has exactly these base keys:

`schemaVersion: 2`, `source: "native"`, `pid`, `record`, `operationSeq`, `phase`,
`droppedBefore`, `emittedBefore`, `suppressedBefore`, `overflow`.

`record` and the three counters start at zero and are process-local. All numeric
ordinals are bounded by 2^53 - 1. `cleanupOwner` and `cleanupAttempt` start at one;
owner exhaustion disables diagnostics, and attempt exhaustion disables subsequent
attempts rather than aliasing prior ordinals. Attempt capacity is 2^45 - 1.

- `CaptureStarted`: emitted once after a successful startup open; base keys only,
  `operationSeq: 0`.
- `CleanupStarted`: base keys plus `generation`, `cleanupOwner`, `cleanupAttempt`,
  `cleanupLifecycle` (`"scope-end"` or `"restart"`). This is a retrospective
  snapshot header, not a live entry timestamp.
- `CleanupFirstFailure`: the same facts plus `cleanupComponent`.
- `CleanupResult`: the same identity facts plus `cleanupResult` (`"passed"` or
  `"failed"`). Failed results also contain `error`, serialized through the
  existing closed `ProtocolError` scalar serializer. Successful results omit it.
- `ScreenshotFirstFailure`: base keys plus `generation`, `screenshotStage`, `capturePhase`, `inventoryAfterFailure`, and closed scalar `error`. `operationSeq` is positive. This independent record has no cleanup owner, attempt, or lifecycle and is not a cleanup result.
- `FrameInventoryRejection`: base keys plus `generation`, `pass`, `sealed`, `revisionMismatch`, `reservations`, `exact`, `lastEvent`, and `lastTarget`; optional `delta` and seven-element `events` are omitted when unobserved. It is an independent companion to the same operation's `ScreenshotFirstFailure`, not a cleanup result.
- `ReadonlyPrepareFailure`: base keys plus `generation`, `entryUs`, `ack`, `window`, `deadline`, `zeroInput`, `cleanup`, and closed final action `error`; optional `ackUs`, `wakeUs`, and `failUs` are omitted when unobserved. `operationSeq` is positive. It has no cleanup owner/attempt/lifecycle and is not a cleanup result.
- `CaptureLimitReached`: base keys only, `operationSeq: 0`.

Only the following component values exist: `callback`, `dialog`, `interception`,
`script`, `detach`, `recording`, `upload`, `containment`, `release`, `input`,
`download`, `blob`, `enrollment-fallback`, `retained-task-fallback`,
`owner-fallback`. No payload, raw error description, URL, DOM, header, token,
request ID, target, session, frame, context, script ID, or arbitrary string enters
these records. No other optional settlement-trace fields are emitted by this sink.

Screenshot stages are the closed dispatch enum: `prepare-scope`, `prepare-permit`, `prepare-policy`, `prepare-owner`, `prepare-fence`, `run-scope`, `debt-admission`, `ui-admission`, `publication-admission`, `producer-reservation`, `initial-frames`, `frame-inventory-fence`, `protected-barrier`, `animation-stabilization`, `protected-frames`, `geometry`, `trace-metadata`, `capture`, `restoration`, `final-geometry`, `final-barrier`, `final-frames`, `final-viewport`, `blob-publication`, and `publication`. They identify the first rejecting instrumented boundary, not the cause of invalidation. `capturePhase` is `not-entered` except when the existing capture error supplies `admission`, `independent-coverage`, `source-protection`, `raw-capture`, or `post-capture-validation`.

`inventoryAfterFailure` is `not-sampled` when no revision was retained from an existing inventory read, `unavailable` when the later inventory read fails, or `unchanged` / `changed` relative to that earlier read. The comparison is sampled after failure and restoration, not at the atomic rejecting check. No extra baseline read or raw revision is recorded. This relationship cannot attribute a popup, navigation, target, or session as the cause. The original first internal error can differ from the final public error after cancellation or cleanup precedence; diagnostics never replace that result.

`FrameInventoryRejection` freezes all three original rejection predicates under the same registry lock as the rejecting check. At least one of `sealed`, `revisionMismatch`, or `reservations` is true; `reservations` means a creation reservation exists, not its count. `pass` is `initial`, `protected`, or `final`, identifying which existing frame-inventory pass rejected. The unchanged whole-registry gate protects owned-target and privacy coverage; these facts do not relax it to the selected page.

When enabled, seven fixed counters increment under that same lock only after successful revision increments. The entry snapshot comes from the original inventory read, with no extra baseline command. `events` is the entry-to-rejection difference in the fixed order attach, detach, Target.targetInfoChanged (`info`), Page.frameNavigated (`navigate`), same-document navigation, frame detach, and unknown. `delta` is current minus expected revision. Each serialized value saturates at 65,535. `exact` is true only for a complete same-registry window, with no unknown bucket, overflow, clamping, or missing increment, and sum(events) equal to delta. Missing entry/history, reset identity, arithmetic underflow/overflow, or an unobserved counter window cannot become zero: unavailable fields are omitted and `exact` is false. An unknown bucket is retained as observed but makes `exact` false.

`lastEvent` uses the seven names `attach`, `detach`, `info`, `navigate`, `same-document`, `frame-detach`, `unknown`, plus `none` for a known zero-revision interval. It is usable only when its recorded revision is the rejecting current revision within the observed window. `lastTarget` is `same`, `other`, or `unknown` by the existing selected attachment-tenure token, not raw native identity or inferred logical page ancestry. Missing history or an unavailable last event means unknown. The last event is not necessarily the sole event or root cause. A target-info event does not prove which target-info field changed.

The original screenshot first-failure row remains unchanged. Its atomic companion is retained with that first failure, cannot be overwritten by restoration, and is emitted once after the same terminal restoration boundary, without a diagnostic lock held during sink I/O. The two rows share positive operation sequence, generation, and process identity only; missing, duplicated, or mismatched companions remain unknown and do not manufacture cleanup or public-case coverage. Capture drops, nonterminal restoration, or process death may omit either row. All cumulative tracking is disabled with the existing sink. This phase retains no payload, URL, title, or raw target/session ID; its maximal closed row is 507 bytes including the newline, under the unchanged 512-byte cap.

Read-only preparation timings are monotonic microseconds, truncated to whole microseconds and saturated at 60,000,000; the cap denotes at least that duration, not an exact value. `entryUs` samples remaining operation budget at first `center` entry. `ackUs` samples remaining budget only where the original exact no-box reply, auxiliary release accounting, and authority check have completed and the current refusal is recorded. `ack` is `none`, `current`, or `retired`; a new preparation attempt immediately retires the old ACK, and final disqualification also reports it retired. Historical `ackUs` is never proof for a later pending read. `wakeUs` measures the latest retry from its probe start to the existing pause future's return, including probe work and the actual wake delay; it is not pure sleep time or an inferred timer ACK. `failUs` samples remaining budget at the existing failed `perform_node` result, before exact-node release; it does not time a later cleanup or final-fence failure.

`window` is `entered` only when the original current-receipt classification-window branch executes, before its authority check; otherwise it is `not-entered`. It does not mean successful classification. `deadline` is sampled after cleanup/final action result mapping, so true alone cannot prove the original failure exhausted its budget. Compare the independently observed `failUs`, `ackUs`, and `window` without reconstructing authority from rounded time values. `zeroInput: true` means this action submitted no application mutation according to its existing dispatch flag; it does not mean no cleanup commands occurred or no other browser task acted. `cleanup` is `failure-observed` or `not-observed` from the existing final action flag; `not-observed` is not a clean-state certificate. A missing ACK does not establish that a no-box reply occurred. The original action result, cleanup priority, and any later retained-operation normalization remain unchanged.

The first successful atomic observation wins. It identifies the first observed
failing obligation during that attempt, not chronological browser causality or
root cause. Concurrent observations may have either first component. A command
can fail admission before submission; a component is not evidence of submission.
The original lifecycle result and error are recorded separately and never
replaced by the component. A failed restart without a component can be a body or
readiness failure, not evidence of failed cleanup. A handled cleanup-command
failure can coexist with a successful overall result; neither implies a retry is
safe.

Correlation requires `(source, pid, cleanupOwner, cleanupAttempt)` and matching
`generation`, `operationSeq`, and lifecycle. These are process-local ordinals, not
public identity or PID attestation. Suite source/runtime binding does not by
itself bind a daemon to one test case. Ambiguous or reused PIDs and missing joins
must remain ambiguous. The harness must preserve original test-body and public
cleanup results separately from this diagnostic artifact, including on failures.

## Instrumented boundaries and known gaps

- `scope.end`: retained task drainage, action recording/upload cleanup,
  enrollment drainage, containment/release, download directory and blob cleanup;
  an unattributed error uses an explicit fallback.
- `restart`: input release, recording page closing, uploads, lower cleanup
  commands, and a fallback for reported replacement cleanup-integrity loss.
- Closed CDP cleanup commands: dialog dismissal, Fetch/auth/network release,
  script removal, session detach, autoattach/debugger release, and containment
  inventory. The original `Result<Value, String>` is returned untouched.
- Borrowed containment: input, interception, and script obligations, including
  failures before a lower command is dispatched.
- Network callback drainage: noncancelled callback-task join failures only.
  Ordinary cancellation is not newly classified as failure. Existing ignored
  callback-body errors remain unchanged.
- Trace screenshots: observation-dispatch preparation, protected read/capture, restoration, revalidation, and publication. The frame-inventory revision rejection has an explicit stage; deeper checks retain their enclosing stage and existing capture phase. Browser-manager rejection before observation dispatch is not instrumented.

Admission failures before the lifecycle attempt begins, missing native ledgers,
startup/reset/reconnect/shutdown outside these two windows, cached failures from
before the window, persistent probe internals, some route/reader/fence failures,
and generic retained-task or enrollment errors are not assigned a deeper cause.
They yield an explicit fallback or no completed snapshot. In particular, this
does not resolve the beforeunload candidate's command-submitted / reader-ACK /
pending-key-removal ordering. No dialog race fix is claimed.

## Validation status

Ten source-authored tests in `client_cleanup_diagnostic_tests.rs` cover disabled
zero output; exact schema and original-error preservation; separate owners and
attempts; stale observer / dropped waiter and a deterministic Drop/publication race; simultaneous obligations; limits,
contention and write failure with unchanged terminal ledger state; unsafe paths
and partial artifacts; ordinal exhaustion and maximal record sizes; and an actual
closed-CDP-command path using a bounded local WebSocket error peer.

Existing sink tests retain shared-file count/byte bounds, file locking, unsafe
FIFO/symlink refusal, and write-failure terminal behavior. Existing protocol,
focus, recovery, cleanup outcomes, and public assertions are unchanged. This
change was checked with rustfmt, diff checks, and static source assertions only.
No Cargo, Rust compilation/linking, test execution, browser, or CI run is claimed.

Screenshot tests are source-authored, not executed here: opt-out/non-trace/success silence; first-failure preservation through a later cleanup failure; one-time consumption; exact production-sink schema and maximal record bounds; and a closed local WebSocket peer injecting preparation rejection and inventory invalidation with clean or failing animation restoration. The sink test and dispatch peer test are separate checks, not proof of a complete production CLI run. The focused Node collector suite passes 23 tests, including failed-assertion evidence retention, closed screenshot fields, and unknown coverage for gaps, overflow, and dropped records. Attribution still requires the unchanged public P01 case with the production binary in the standard cloud harness.

Read-only preparation tests are also source-authored only: disabled/Tap/success/mutated silence, old-ACK retirement, below-floor refusal without classification, observed-window preservation through authority/cleanup failure, unknown timing omission, one-time consumption, and production-sink schema. Native and collector maximal-row assertions use 505 bytes including the newline, within the unchanged 512-byte limit. The expanded focused Node collector suite passes 26 tests, including failed-assertion retention of preparation timing without inventing cleanup, case association, or deadline causality. Neither unit-carrier composition nor hosted preparation tests establish original P27 runtime cause; the unchanged public case must run against the production binary.

Atomic frame-inventory tests are source-authored only: all eight rejection-predicate combinations; each of seven revision classes; multi-event and other-attachment windows; missing, reset, underflow/overflow and clamped observations; disabled history; first-failure preservation and one-time consumption; and the existing production sink schema and 507-byte bound. The witness and sink tests are separate checks, not a whole CLI execution proof. The focused Node suite passes 39 tests, retaining the original 33 and adding strict atomic schema, unknown-window, pairing, failed-assert artifact, and line-limit cases. Native test execution and original public-case attribution remain for the standard cloud run.
