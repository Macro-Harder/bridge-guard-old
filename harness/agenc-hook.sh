#!/bin/sh
# agenc-hook.sh — example AgenC hook for bridge-guard (harness variant).
#
# How it fits: the bridge poll drops an incoming guard file-request
# envelope's JSON into $GUARD_INBOX_DIR (one file per request). This
# hook validates it with guard.py and writes the verdict next to it:
#   <id>.verdict.json — {"verdict": "pending"|"approved"|"rejected",
#                        "reason": "..."}
# The harness (or the guardian agent) then approves pending requests
# with `guard.py approve`, stages with `guard.py stage`, and the main
# agent sends the staged copy. Receipts come back the same way and
# are fed to `guard.py receipt`.
#
# This is an example, not a daemon: adapt the inbox path and the
# approval step (manual guardian vs --auto policy mode) to your setup.
# Headless `agenc -p` cannot run shell commands — run this from a
# durable `agenc run` or from the bridge hook, not from a one-shot.
set -u
GUARD_HOME="${BRIDGE_GUARD_HOME:-$HOME/.bridge-guard}"
GUARD_INBOX_DIR="${GUARD_INBOX_DIR:-$HOME/.bridge-guard/inbox}"
GUARD_PY="$(dirname "$0")/../guard.py"

mkdir -p "$GUARD_INBOX_DIR"
for req in "$GUARD_INBOX_DIR"/*.json; do
  [ -e "$req" ] || continue
  case "$req" in *.verdict.json) continue ;; esac
  id="$(basename "$req" .json)"
  verdict="$GUARD_INBOX_DIR/$id.verdict.json"
  [ -e "$verdict" ] && continue
  if python3 "$GUARD_PY" --home "$GUARD_HOME" intake --file "$req" \
      > "$verdict.out" 2>&1; then
    verdict_text="pending"
  else
    verdict_text="rejected"
  fi
  reason="$(tail -n 1 "$verdict.out")"
  rm -f "$verdict.out"
  printf '{"verdict": "%s", "reason": "%s"}\n' \
    "$verdict_text" "$(printf '%s' "$reason" | sed 's/"/\\"/g')" \
    > "$verdict"
done
