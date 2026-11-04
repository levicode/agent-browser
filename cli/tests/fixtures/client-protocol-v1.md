# Closed keyboard refusal codes

The coordinated native-session decoder now accepts `fill-unsupported-target` and `no-editable-focus`. These contain no renderer text, input values, selectors, or node identities. The CLI and MCP command grammar is unchanged.

`fill-unsupported-target` refines only a live, clean, read-only fill preflight refusal on an element that is neither an input, textarea, nor contenteditable. Disabled, readonly, and unsupported input types retain generic `not-actionable`. A race after preflight keeps the original mutation uncertainty.

`no-editable-focus` refines only a clean focused-typing preflight with no eligible key receiver in the current frames. It must not hide stale authority, cancellation, timeout, or handle/input cleanup failure.

Consumers may restore the existing keyboard fallback wording only with `effects: not-dispatched` and `scopeState: usable`. A reason never overrides an unknown outcome or grants retry authority. Older closed decoders intentionally reject the two new codes, so native and Web artifacts must be published together.

## Exact tap receiver replaced after hover

`tap-target-replaced-before-press` is a coordinated native-session error for an unmodified single primary tap only. The exact receiver was detached after an acknowledged pointer hover but before any button press. Native keeps the original opaque reference and does not choose or click a replacement.

The error is emitted only with `effects: completed` after the original realm and operation authority, fully settled exact-handle release, mandatory input cleanup, and zero operation input/object debt have been checked. Completed describes the already-acknowledged scroll/hover preparation, not a successful tap, no side effects, or rollback. The Web adapter maps only this code with `completed`, `usable`, and original action kind `tap` to `NODE_STALE` so core's existing bounded descriptor relocation can capture a new reference. It is never classified as native not-dispatched. Unknown effects, a dirty/closed scope, cancellation, a retired realm, any press attempt, or another action kind do not receive this permission.

Node tap, double-tap and secondary-tap all recheck the same exact receiver and the same point's target/ancestor hit testing after hover. This introduces no second hover, selector fallback or opaque-ref re-resolution. The new relocation receipt is deliberately narrower than those safety checks. Bare-point input retains its original sequence; long-press and checked-state actions are unchanged by this packet.

# Failed recording delivery

`recording.stop` can return `{ identityScope, segments, missingSegment }` when an owned segment could not be read but other segments were finalized. `missingSegment` is optional; the closed result contains no other fields. Consumers retain the included handles before reporting the missing part, and never issue another stop to recover that batch. The CLI and MCP command grammar is unchanged.

A negotiated terminal recording lane is available after any failed non-callback request whose scoped receipt is quarantined and offers no recovery. It remains bound to that receipt's generation, identity scope, and operation sequence. Collection moves only previously read bytes with independently successful, joined encoder output; it performs no stop, file read, capture, connection, or mutation. Safe prior segments survive a failed current segment or remote stop acknowledgment. Unsettled recording attachments and private files remain in their original cleanup journal: delivered bytes are not a `Closed` or reusable-scope receipt. A transport EOF without a validated scoped failure grants no collection authority.
