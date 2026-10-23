# Session Management

Multiple isolated browser sessions with state persistence and concurrent browsing.

**Related**: [authentication.md](authentication.md) for login patterns, [SKILL.md](../SKILL.md) for quick start.

## Contents

- [Named Sessions](#named-sessions)
- [Session Isolation Properties](#session-isolation-properties)
- [Tab Pinning in a Shared Browser](#tab-pinning-in-a-shared-browser)
- [Session State Persistence](#session-state-persistence)
- [Common Patterns](#common-patterns)
- [Default Session](#default-session)
- [Session Cleanup](#session-cleanup)
- [Best Practices](#best-practices)

## Named Sessions

Use `--session` to isolate browser contexts. Agent skills should derive one stable id and reuse it on every command:

```bash
SESSION="$(agent-browser session id --scope worktree --prefix my-skill)"
agent-browser --session "$SESSION" --restore open https://app.example.com/login
```

`--scope worktree` uses the Git worktree root when available, then the Git root, then the canonical current directory. This is the recommended default for agents because worktrees are commonly used for parallel agent runs.

```bash
# Session 1: Authentication flow
agent-browser --session auth open https://app.example.com/login

# Session 2: Public browsing (separate cookies, storage)
agent-browser --session public open https://example.com

# Commands are isolated by session
agent-browser --session auth fill @e1 "user@example.com"
agent-browser --session public get text body
```

## Session Isolation Properties

Each session has independent:
- Cookies
- LocalStorage / SessionStorage
- IndexedDB
- Cache
- Browsing history
- Open tabs

## Tab Pinning in a Shared Browser

Full isolation applies when each session launches its own browser. When sessions instead share one Chrome over `--cdp <port>`, cookies and storage are shared, and only the tab selection separates the sessions. Add `--pin-tab` so each session sticks to its own tab:

```bash
agent-browser --session agent1 --cdp 9222 --pin-tab open https://site-a.com
agent-browser --session agent2 --cdp 9222 --pin-tab open https://site-b.com
```

Every session remembers which tab it is bound to (by CDP target id, persisted in the session's state directory), so a restarted daemon reattaches to the session's own tab instead of adopting the most recently active one. `--pin-tab` (env `AGENT_BROWSER_PIN_TAB=1`) additionally makes the binding strict:

- Attaching with no binding opens a fresh tab instead of adopting an existing one
- If the bound tab is closed, commands fail with a `tab_gone` error instead of silently acting on another tab. JSON output includes `"code": "tab_gone"`, `data.targetId`, and optional `data.lastUrl`
- Recovery commands still work in that state: run `tab new <url>` to bind a fresh tab, or `tab list` and switch to an existing one
- Tabs opened by other sessions or the user never steal the pinned session's active tab

The flag is sticky per session: pass it once at session creation and later commands and daemon restarts keep the strict semantics. Pass `--no-pin-tab` to explicitly turn the pin off again. Use each tab's `targetId` from `tab list --json` when one session needs to reference another session's tab; target ids stay stable across daemon restarts.

The structured `lastUrl` is limited to sanitized HTTP(S) URLs and `about:blank`. Credentials, query strings, and fragments are removed from HTTP(S) URLs. Opaque URLs such as `data:` are omitted. In batch JSON, the recovery object appears under `result` instead of `data`.

When re-running a shared-tab script such as the repro from #1530, add `--pin-tab` to the first command for every session. Without it, `open` intentionally preserves the legacy behavior and navigates the shared active tab, so the original script still collides. The same rule applies when sessions attach with `--auto-connect` instead of `--cdp`.

## Session State Persistence

### Automatic Restore

```bash
# Bare --restore uses the current --session as the persistence key
SESSION="$(agent-browser session id --scope worktree --prefix next-dev-loop)"
agent-browser --session "$SESSION" --restore open https://app.example.com/dashboard
```

When `--restore` or another restore key is configured, state is loaded before navigation and saved on close, daemon shutdown, idle timeout, and compatible relaunch. It is also saved periodically while the browser is open (after commands settle, at most once per `AGENT_BROWSER_AUTOSAVE_INTERVAL_MS`, default 30000; set to `0` to save only on close), so a browser window the user closes by hand still leaves a recent save behind. A session ID by itself only isolates the daemon and does not enable persistence; without a restore key, shutdown discards transient browser state and open tabs. Idle sessions with configured persistence keep saving on the same interval, capturing changes the page makes on its own such as token refreshes. The daemon exits after one hour without commands or dashboard input by default; `--idle-timeout <time>` or `AGENT_BROWSER_IDLE_TIMEOUT_MS` tunes this, and `0` disables it. Headed, Safari/iOS WebDriver, and user-attached browsers are exempt from the default timeout; provider-owned cloud browsers are not. The default save policy is `--restore-save auto`, which skips auto-save if restore failed or validation failed; `never` disables periodic autosave too.

```bash
agent-browser --session "$SESSION" --restore --restore-check-url "**/dashboard" open https://app.example.com/dashboard
agent-browser --session "$SESSION" --restore --restore-check-text Dashboard open https://app.example.com/dashboard
agent-browser --session "$SESSION" --restore --restore-check-fn "!!localStorage.getItem('session')" open https://app.example.com/dashboard
```

Use `agent-browser session info --json` for diagnostics:

```bash
agent-browser --session "$SESSION" session info --json
```

### Manual State Files

Use `state save`, `state load`, and `--state <path>` when you need an explicit portable JSON file. Do not make agents construct paths under `~/.agent-browser/sessions/`; prefer `--restore` for reusable agent sessions.

## Common Patterns

### Authenticated Session Reuse

```bash
#!/bin/bash
SESSION="$(agent-browser session id --scope worktree --prefix app)"
agent-browser --session "$SESSION" --restore open https://app.example.com/dashboard
```

### Concurrent Scraping

```bash
#!/bin/bash
# Scrape multiple sites concurrently

# Start all sessions
agent-browser --session site1 open https://site1.com &
agent-browser --session site2 open https://site2.com &
agent-browser --session site3 open https://site3.com &
wait

# Extract from each
agent-browser --session site1 get text body > site1.txt
agent-browser --session site2 get text body > site2.txt
agent-browser --session site3 get text body > site3.txt

# Cleanup
agent-browser --session site1 close
agent-browser --session site2 close
agent-browser --session site3 close
```

### A/B Testing Sessions

```bash
# Test different user experiences
agent-browser --session variant-a open "https://app.com?variant=a"
agent-browser --session variant-b open "https://app.com?variant=b"

# Compare
agent-browser --session variant-a screenshot /tmp/variant-a.png
agent-browser --session variant-b screenshot /tmp/variant-b.png
```

## Default Session

When `--session` is omitted, commands use the default session:

```bash
# These use the same default session
agent-browser open https://example.com
agent-browser snapshot -i
agent-browser close  # Closes default session
```

## Session Cleanup

```bash
# Close specific session
agent-browser --session auth close

# List active sessions
agent-browser session list
```

## Best Practices

### 1. Name Sessions Semantically

```bash
# GOOD: Clear purpose
agent-browser --session github-auth open https://github.com
agent-browser --session docs-scrape open https://docs.example.com

# AVOID: Generic names
agent-browser --session s1 open https://github.com
```

### 2. Always Clean Up

```bash
# Close sessions when done
agent-browser --session auth close
agent-browser --session scrape close
```

### 3. Handle State Files Securely

```bash
# Don't commit state files (contain auth tokens!)
echo "*.auth-state.json" >> .gitignore

# Delete after use
rm /tmp/auth-state.json
```

### 4. Timeout Long Sessions

```bash
# Set timeout for automated scripts
timeout 60 agent-browser --session long-task get text body
```

## Persistent client protocol

`agent-browser --session <dedicated-name> session connect --json` opens a negotiated JSON-line connection over stdin/stdout. Use a dedicated `--session` name. Send an `agent-browser-session/1` hello with `requiredCapabilities`; inspect `ready.capabilities` before sending operations. This additive protocol currently exposes only `browser.scope/1` and `browser.evaluate/1` for owned scope lifecycle and page evaluation. Other commands are rejected without dispatch. This is not a claim of full browser feature parity; protected capture, state transfer, routing and structured observation are not advertised yet. An existing launched browser or another client owner is refused rather than silently adopted.

For integrations with negotiated protected capture, `capture.screenshot` accepts an optional closed `purpose`: `pixelsOnly` (the default) or `trace`. Trace output adds the native Page `viewportRef`, exact captured `viewport`, and `location` to the protected image descriptor. It does not publish a semantic root, advance semantic revisions, or replace node membership. Trace capture cannot supersede an explicit observation; a newly admitted observation rejects an older trace. The normal CLI and MCP screenshot remain pixels-only; no new CLI flag or MCP tool is introduced.


Each UTF-8 JSON frame is limited to 1 MiB. Required capability failures, unknown fields, stale generations and replayed operation sequences fail explicitly. Cancellation acknowledgment does not prove browser effects stopped; only a terminal result with native scope health may authorize reuse. Never automatically replay an operation after transport loss. Large screenshots and response bodies will require bounded artifact handles, not oversized frames.

Clients requiring `terminal.close/1` retain cleanup-only control after a quarantined result. Native shutdown starts immediately; within a fixed ten-second control window, the client may send one same-generation `close` and receive its correlated `closed` only after proven teardown and the original operation results. No request, callback or reconnect authority is restored, and the original unknown-effects result is unchanged. Cleanup failure remains an error; EOF is never a cleanup receipt. This transport capability has no one-shot MCP equivalent.


The CLI inserts a fixed socket preface; clients on stdin/stdout only exchange JSON. Socket preface/hello negotiation has a five-second timeout. Legacy JSON commands retain their framing and payload-size behavior; an idle connection must begin sending within five seconds. Legacy browser mutation is refused while the daemon is exclusively owned by a negotiated client. The persistent connection intentionally has no one-shot MCP tool equivalent; existing MCP tools remain unchanged.

The negotiated entrypoint requires an explicit dedicated session name and accepts only `--session`, `--namespace`, and `--json`. It bypasses project/user configuration, plugin loading and inherited browser-launch environment settings. Only transport socket-directory and namespace settings are retained. An already-running named daemon is never adopted or restarted. The dedicated daemon exits after proven scope teardown. Dedicated names are one-use: choose a fresh unique name for every connection, including after a failed startup or a clean close. A small admission marker remains to reject reuse and prevent crash-time ownership races. Ordinary CLI commands retain their existing configuration behavior.

Request decisions use exactly one body source: `bodyBase64` or a sealed, scope-bound `bodyHandle`. Fulfillment requires one; continue/fallback overrides may omit both to preserve the current body. A handle is transferred only when its decision is accepted. Rejected decisions leave the upload releasable. Large-body storage is a separately negotiated extension; the narrow scope/evaluation executor does not advertise it and refuses handles without consuming the decision token.

The native callback bridge is an internal implementation pending capability admission and browser acceptance. It does not change the narrow advertised session capabilities. Callback requests retain their original route registry and scope identity; JavaScript performs its own pattern matching and fallback selection. Large request bodies use read-only `postDataHandle` aliases, read in bounded chunks with `network.body.read`; these aliases cannot be submitted as upload handles or released by the client. Response events expose headers immediately, while body reads wait independently for completion. Download metadata distinguishes native-owned local files from provider-owned resources; provider metadata exposes only a validated basename under the configured provider directory, never an arbitrary remote file path. Application HTTP credentials are never sent to proxy challenges. Callback admission shares the native protected-read gate, while decision and cancellation control remain independent.
