#!/usr/bin/env bash
set -euo pipefail
# Local, explicit upgrade preparation only. Never pushes, publishes or moves main.
[[ $# == 2 && "$1" =~ ^[0-9a-f]{40}$ ]] || { echo 'Usage: prepare-upstream-sync.sh <exact-upstream-sha> <new-candidate-branch>' >&2; exit 2; }
ROOT="$(git rev-parse --show-toplevel)"
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || { echo 'Commit or stash local changes first' >&2; exit 1; }
git check-ref-format --branch "$2" >/dev/null
[[ "$2" != main && "$2" != upstream/main ]] || { echo 'Use a new upgrade candidate branch, not a stable branch' >&2; exit 1; }
git -C "$ROOT" fetch https://github.com/vercel-labs/agent-browser.git "$1"
[[ "$(git -C "$ROOT" rev-parse FETCH_HEAD)" == "$1" ]] || exit 1
git -C "$ROOT" switch -c "$2"
git -C "$ROOT" merge --no-commit --no-ff "$1"
printf '%s\n' 'Candidate prepared locally. Review all conflicts/diffs and update maintainer/upstream.json only after checking the contract.' 'Run native CI and e2e cross-repository acceptance before committing/promoting. No push or release was performed.'
