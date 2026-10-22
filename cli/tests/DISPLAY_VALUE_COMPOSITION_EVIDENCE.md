# Display-value composition acceptance matrix

The native `validate_expression` function is the rejection authority. Query nodes validate their optional scope, then derive effective display-value provenance from their own query kind. Filter, index, and frame nodes inherit source provenance. Selector nodes do not carry it. A display-value scope or `has` operand returns the existing protocol `unsupported-capability` category through a typed observation error.

`ObservationDispatch` calls this same validator after scope, cancellation, deadline, and read-policy checks, before UI admission, publication staging, frame acquisition, or CDP. The direct query and retained live-query paths also keep their existing validator calls. This patch does not change matching, ordering, secure-field policy, reference identity, or reference retirement.

## Native matrix

| Input | Expected result | Source coverage |
| --- | --- | --- |
| Direct display-value scope or `has` operand | Typed `UnsupportedCapability` | `client_observation/composition_tests.rs` |
| Display value wrapped in first, last, numeric index, hasText, ordinary has, frame, or filter after index, then used as scope or has | Same refusal | `unsupported_expressions`, 128 shapes including outer wrappers |
| A refused composition nested under ordinary filter, index, or frame | Same refusal | Same 128-shape matrix |
| Plain display value, position, hasText, ordinary has, frame, filter after position | Admitted, effective provenance true | `display_value_query_resets_provenance_and_preserves_allowed_refinements` |
| Display value scoped under ordinary selector, role, or exact-label roots and their refinements | Admitted, effective provenance true | Same admission test |
| Ordinary selector, role, exact-label scopes, has operands, and refinements | Admitted, effective provenance false | Same admission test |
| Empty selector, role regexp, excessive depth | Existing `InvalidArguments` | `existing_syntax_and_depth_refusals_keep_their_category` |
| Every refused shape through both Fixture and Protected dispatch | Typed refusal, no CDP commands, no allocator advance, unchanged references and publication revisions | `client_observation_composition_dispatch_tests.rs` |
| Unexpected unsupported observation error inside hidden-frame geometry proof | Safe backend failure | `hidden_proof_cleanup_keeps_original_failure` |

## Adapter matrix

The E2E test `packages/web/tests/unit/native-display-value-composition.test.ts` uses the real `NativeClient` framed parser and `EngineChannel`, with an in-memory protocol peer. It records each request before returning a native error. The adapter only snapshots a bounded diagnostic fact before the await. It neither refuses queries nor executes them.

| Native response and original request | Expected result |
| --- | --- |
| Either query command, bounded direct or wrapped scope/has shape, unsupported-capability, not-dispatched, usable | Original fixed public diagnostic |
| Same AST, native success | Success is decoded normally |
| Plain display value or any allowed refinement, native unsupported-capability | Generic native capability error |
| Unknown outcome, including owner retirement while awaiting | `ACTION_MAY_HAVE_COMMITTED`; native transport is quarantined |
| Quarantined or closed scope with not-dispatched refusal | Generic error; no new request on that client |
| Completed refusal | Generic error |
| Cancelled, deadline, browser failure, unsupported command | Existing error category and wording |
| Invalid native error code | Protocol failure, not a composition diagnostic |
| Unrelated engine command carrying an extra unsupported-looking expression | Generic error |
| Caller replaces the expression after native dispatch | Classification follows the original request in both directions |
| Excessive depth, traversal budget, cycles, unknown AST kind | No diagnostic evidence |

The fixed diagnostic remains: `displayValue queries cannot scope child queries or serve as a has-filter in this engine`.

## Evidence status

- Rust source is UNCOMPILED and its tests are UNRUN in this lane. `rustfmt --check` and `git diff --check` pass. Central compilation and test execution are required before acceptance.
- Six focused TypeScript suites pass, 149 tests total: display-value composition, native action errors, engine channel, protocol, client, and channel retirement. Web package typecheck and changed-file lint pass using already-vetted local dependencies and a local copy of core dist whose 568 file SHA-256 hashes matched the source copy.
- The initial pnpm prerequisite check failed before tests began. It is not a test failure or test execution. The later focused run used the existing Vitest entry point directly without installing dependencies.
- Original public `packages/web/tests/integration/lifecycle.test.ts:482-495` and `packages/web/tests/unit/locators.test.ts:216-246` are unchanged. The original lifecycle assertion still requires hosted native/Chromium evidence. Synthetic transport tests do not replace it.
