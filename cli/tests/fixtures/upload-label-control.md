# Exact label upload compatibility

`browser.perform` with `setInputFiles` preserves the former E2E action target's HTML label association: a connected exact `HTMLLabelElement` can supply its associated connected file input. The association is captured once in the original isolated realm and session. The derived input handle replaces only the local action handle; it does not mint a public reference or perform another locator query.

Non-labels, text nodes, labels with no associated file input, and other controls retain the existing admission result. A detached or foreign-document label/control is stale. The file-input, disabled, directory, cardinality, blob lease, path, staging, and final dispatch checks remain unchanged. This restores one existing action contract; no CLI/MCP parser, public wire field, fallback reason, or permission changes.

The original label handle and the derived control handle both remain accounted. Authority is checked after the read-only reply and again after releasing the label. Cleanup failure is never a clean refusal; an acknowledged upload followed by failed cleanup retains dispatched/unknown effects. No upload is retried.

`native-upload-label-control.test.cjs` executes the production capture and preflight JavaScript with scripted DOM objects. It covers direct input, explicit/nested association, detached/foreign documents, rejected labels, disabled controls, and cardinality/directory constraints. This is not Chromium verification.

The `native::client_actions::tests::upload_label_controls` tests use the existing transport fixture to cover exact dispatch target, one release per handle, unchanged direct input, refused preflight, original release failure, exception handles, authority retirement, post-dispatch cleanup failure, and opaque scope/revision rejection. These tests do not prove provider upload behavior; the unchanged E2E `agent-act-verbs` upload and record/replay consumers must run against the new native binary.
