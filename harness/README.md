# Harness variant — AgenC and other CLI agents

The guardian as a command-line tool the harness calls. No MCP, no
conversational agent in the loop for every request — the harness
drives `guard.py` directly, and the guardian decision is either the
policy (auto mode) or a guardian agent's explicit approve/reject.

## The flow (AgenC, concretely)

Side A owns the file; side B wants it. Both sides run a guardian
(`guard.py --home <dir> init` once per side).

```
B's harness                    A's guardian                    A's harness
    |                                |                               |
    | -- request JSON --------------> |                               |
    |   (bridge message envelope,    |                               |
    |    or a file dropped in the    |                               |
    |    inbox dir)                  |                               |
    |                                | guard.py intake               |
    |                                |  -> auto-reject if not a pure |
    |                                |     file request (logged)     |
    |                                | guard.py approve --id <id>    |
    |                                |  (guardian agent, or --auto   |
    |                                |   policy approval)            |
    |                                | guard.py stage --id <id>      |
    |                                |  -> shared/<send_id>_file,    |
    |                                |     sha256 recorded           |
    |                                |                               | main agent sends
    |                                |                               | the staged copy
    |                                |                               | guard.py sent
    |                                |                               |   --send-id <id>
    | <--- receipt JSON -------------|                               |
    |      (sha256 of what arrived)  |                               |
    |                                | guard.py receipt --file ...   |
    |                                |  -> hash matches: copy DELETED|
    |                                |     hash differs: alert, kept |
```

`harness/agenc-hook.sh` is an example hook: it watches an inbox
directory for incoming request JSON, runs `guard.py intake` on each,
and writes a `<id>.verdict.json` (`pending` / `rejected` + reason)
next to it. Adapt the inbox path and the approval step to your
setup.

## Notes for AgenC specifically

- Headless `agenc -p` cannot run shell commands. Run the guardian
  steps from a durable `agenc run start --permission-mode
  bypassPermissions` (project must be a git repo with a commit), or
  from the bridge hook / a cron, not from a one-shot.
- The bridge poll path (`bridge.py poll`) cannot execute shell
  tasks either — the guardian CLI is for the operator's side, or
  for a durable run, not for a polled task.
- Auto mode (`guard.py init --auto`) approves on policy alone.
  Use it only where the allowlist is tight: the guardian agent's
  judgment is the point of the manual mode.
- The guard never touches bridge keys or envelopes. It validates
  request/receipt JSON and local files; the bridge (or any other
  channel) moves the bytes. See `../INTEGRATION.md` for the
  envelope mapping.
