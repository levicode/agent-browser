# Upload preflight diagnostic

With the existing `AGENT_BROWSER_CLEANUP_DIAGNOSTIC_FILE` opt-in, an existing typed upload refusal can emit `UploadPreflightRefusal` with the closed `uploadRefusal` enum: target-resolution, label, text-node, not-file-input, disabled, directory-mismatch, multiple-mismatch, or unknown. No tag strings, values, file paths, references, control associations, selectors, or error prose are read for output.

The JavaScript retains the exact original upload admission predicate and return status. It only separates its already-refused branches. The record describes that preflight read, not the final action result, cleanup success, retry permission, or a guarantee that a label should be retargeted. `zeroInput` describes this local dispatch tracker only. No action result or protocol error mapping reads diagnostic state.

The existing sink remains bounded: at most 2048 records, 256 KiB total, 512 bytes per record; lock contention drops observations and does not wait. A missing record, capture-limit marker, drop, or absent opt-in is unknown, not evidence the preflight did not execute. For reliable original-consumer diagnosis use a separate sink for the focused agent-act-verbs process and keep the actual consumer assertions and timeouts unchanged.
