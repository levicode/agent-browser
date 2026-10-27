# Closed keyboard refusal codes

The coordinated native-session decoder now accepts `fill-unsupported-target` and `no-editable-focus`. These contain no renderer text, input values, selectors, or node identities. The CLI and MCP command grammar is unchanged.

`fill-unsupported-target` refines only a live, clean, read-only fill preflight refusal on an element that is neither an input, textarea, nor contenteditable. Disabled, readonly, and unsupported input types retain generic `not-actionable`. A race after preflight keeps the original mutation uncertainty.

`no-editable-focus` refines only a clean focused-typing preflight with no eligible key receiver in the current frames. It must not hide stale authority, cancellation, timeout, or handle/input cleanup failure.

Consumers may restore the existing keyboard fallback wording only with `effects: not-dispatched` and `scopeState: usable`. A reason never overrides an unknown outcome or grants retry authority. Older closed decoders intentionally reject the two new codes, so native and Web artifacts must be published together.
