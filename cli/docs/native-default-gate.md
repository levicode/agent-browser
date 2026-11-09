# Native default-configuration gate

The native default gate is the whole Rust suite built with the default features in the `ci` profile:

```bash
cd cli
CARGO_PROFILE_CI_LTO=false cargo test --profile ci
```

`CARGO_PROFILE_CI_LTO=false` only removes thin-LTO compile time. It does not change the feature set, the test selection, or any assertion.

## Reporting the gate

Always state the revision and all three counts together: passed, failed and ignored. The crate has no fixed denominator. At `57c45914` the test binary lists 3,770 test functions: 3,516 non-ignored and 254 `#[ignore]`d.

The lifecycle group named by the original acceptance audit is `native::client_browser::state_lifecycle_tests`. At `57c45914` it contains 114 tests.

## The "43/110" notation

levicode/e2e#14 and its follow-ups quote a "native 43/110 default gate". That pair cannot be produced from the repository today:

- there is no test selection with 110 entries. The lifecycle module has 114 tests at `57c45914` (109 at the e2e inventory pin `d6d7d5d9`); further tests landed after the audit snapshot;
- `original-core-consumers` is a 125-test Vitest selection in levicode/e2e's `current-ordinary-consumers` workflow. It exercises the public packages against a native runtime. It is not a native Rust selection and cannot stand in for the 110;
- the only stored required native list is `scripts/ci/native-targeted-plan.json` in levicode/e2e: 284 exact names pinned to native `88c700be`. 19 of the 114 lifecycle tests are in that list.

The current equivalent, and the form future reports should use, is:

| Selection | How to run | Count at `57c45914` |
| --- | --- | --- |
| default gate | `CARGO_PROFILE_CI_LTO=false cargo test --profile ci` | 3,516 non-ignored |
| lifecycle group | `cargo test --profile ci --bin agent-browser native::client_browser::state_lifecycle_tests` | 114 |
| required subset | intersection with the e2e native-targeted plan | 19 |

Report the explicit selection and counts (for example "default gate: X passed / Y failed / Z ignored; lifecycle 114/114; required 19/19") instead of the "43/110" shorthand.

## Load sensitivity and the checkout path

- A test that passes idle but fails under load is a test-budget problem, not a product defect, and must not be made green by widening a timeout. Report it as its own class.
- `native::stream::http::tests` binds an AF_UNIX socket under `<crate>/target/t`. A checkout whose absolute path is too long fails both tests with `path must be shorter than SUN_LEN`. That is a limit of the checkout path, not a test failure; run the gate from a short path (or CI) before attributing those two tests.

## Test peers must model every production CDP command

Most native tests drive the real dispatcher through a hand-written WebSocket peer that answers CDP frames and often asserts the exact command sequence. A new production command on a capture path must be modeled by every peer that reaches it. An unmodeled command usually panics the peer task, and the operation then fails with an unrelated-looking timeout, stale-reference or browser-failure. When a capture-path command is added, grep the native test peers for the method name and for the operation script they assert, not only the module the change targets.
