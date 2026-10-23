# Bounded production cleanup diagnostics

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
- `CaptureLimitReached`: base keys only, `operationSeq: 0`.

Only the following component values exist: `callback`, `dialog`, `interception`,
`script`, `detach`, `recording`, `upload`, `containment`, `release`, `input`,
`download`, `blob`, `enrollment-fallback`, `retained-task-fallback`,
`owner-fallback`. No payload, raw error description, URL, DOM, header, token,
request ID, target, session, frame, context, script ID, or arbitrary string enters
these records. No other optional settlement-trace fields are emitted by this sink.

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
