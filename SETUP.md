# bridge-guard — setup

bridge-guard is an **optional** add-on to the [AgenC
Bridge](https://github.com/Macro-Harder/agenc-bridge). Install it
only if two agents that do not trust each other need to exchange
files. The bridge works fine without it.

## Install (both variants)

```bash
git clone https://github.com/Macro-Harder/bridge-guard
cd bridge-guard
python3 -m unittest discover -s tests   # should be 564 green
```

Requirements: Python 3.10+, nothing else. No packages, no keys,
no accounts. The guard never touches bridge keys.

Each side runs its own guardian with its own home directory:

```bash
# On EACH side, once. --allow-root is where files may be requested
# from on this side; repeat it for more directories.
python3 guard.py --home ~/.bridge-guard init \
  --allow-root ~/shared-files \
  --allow-root ~/project/notes
```

That creates `~/.bridge-guard/` with `policy.json` (the allowlist,
caps, and mode), `shared/` (the staging folder, mode 0700),
`guard-log.jsonl` (append-only log), and `state.json`.

Policy knobs in `policy.json` (edit the file, no command needed):

| Key | Default | What it does |
|---|---|---|
| `allow_roots` | `[]` | Directories files may be requested from. Empty = nothing is sendable. |
| `max_bytes` | 10485760 | Per-file size cap (10 MB). |
| `allowed_exts` | text/code list | File-type allowlist. |
| `exceptions` | `[]` | Exact relative paths allowed past the secret scan (logged when used). |
| `auto_approve` | `false` | `true` = policy pass approves (harness mode). `false` = a guardian approves each request. |
| `max_requests_per_hour` | 20 | Rate limit per sender. |
| `max_staged` | 5 | Staged files at once. |
| `ttl_seconds` | 3600 | Unclaimed staged copies are deleted after this long. |
| `level` | (unset) | Strictness level 0–11 declared at install (or `$BRIDGE_GUARD_LEVEL`). At PLAID (level 11), every guard start prompts the trust-but-verify install while it is missing (see below). |

**Beyond the file policy.** The `guard/` package also ships the
systems the level declaration selects: `guard/levels.py` defines
strictness levels 0–11 and their presets, and `guard/packet.py`
is the installer packet — five questions, a level choice,
validated setting overrides, and the declaration an install
records. `guard/manifest.py` compares two sides' declarations
and resolves the shared level and governing values for a
connection. `guard/case.py` and `guard/proposals.py` carry the
case flow for tool and skill proposals. `guard/cost.py` is the
per-pair cost ledger, `guard/roles.py` holds role keys and
certificates, `guard/log.py` is the signed, hash-chained log,
`guard/formats.py` validates bridge message formats, and
`guard/receipts.py` with `guard/transfer.py` track receipts and
move copies through guarded folders.

**PLAID companion.** PLAID (level 11) takes an extra step: the
installer packet asks whether to also install
[trust-but-verify](https://github.com/Macro-Harder/trust-but-verify),
which audits MCP servers' tool descriptions and schemas for
hidden instructions before an agent trusts them; the monitor
agent — which watches the guard itself — uses it as its
MCP-audit companion. Declare the level at init
(`python3 guard.py --home ~/.bridge-guard init --level 11 ...`)
or by setting `level` in `policy.json`. While a PLAID guard
cannot detect trust-but-verify (via `$TRUST_BUT_VERIFY_PATH`, an
importable `trust_but_verify` module, a `trust-but-verify`
binary, or a sibling checkout or venv install beside this
project), every start prints the install prompt to stderr. The
prompt is informational only — it never blocks or installs.

## Harness variant — AgenC

The guardian is the `guard.py` CLI; the harness drives it.

1. Initialise each side as above. For an unattended harness, add
   `--auto` to `init` (policy approves; the guardian agent's
   judgment is skipped — use it only with a tight allowlist).
2. Wire the request path: incoming file requests arrive as JSON
   (bridge message envelope — see `INTEGRATION.md` — or a file in
   an inbox directory). Feed each to `guard.py intake --file`.
   `harness/agenc-hook.sh` is an example hook that watches an
   inbox dir and writes a `<id>.verdict.json` per request.
3. The guardian approves (`guard.py approve --id <id>`) or refuses
   (`guard.py reject --id <id> --reason ...`), then stages
   (`guard.py stage --id <id>`), which prints the staged path and
   SHA-256.
4. The main agent sends the staged copy's bytes, then runs
   `guard.py sent --send-id <id>`.
5. The receipt comes back; run `guard.py receipt --file
   receipt.json`. A matching hash deletes the copy; a mismatch
   logs an alert and keeps it.
6. Sweep expired copies on a schedule (cron works):
   `guard.py sweep`.

AgenC notes: headless `agenc -p` cannot run shell commands — run
the guardian steps from a durable `agenc run start
--permission-mode bypassPermissions`, or from the bridge hook / a
cron, not from a one-shot. The bridge poll path cannot execute
shell tasks either.

## Agent variant — Muse

The guardian is the `guard-mcp.py` MCP server, and the guardian
agent is Muse (or any MCP-capable agent) using it.

1. Initialise each side as above (manual mode — the default).
2. Start the server:
   ```bash
   python3 guard-mcp.py   # stdio; home is $BRIDGE_GUARD_HOME or ~/.bridge-guard
   ```
3. Register it with your agent as an MCP server (stdio command
   `python3 /path/to/bridge-guard/guard-mcp.py`). Tools:
   `guard_request_file`, `guard_approve`, `guard_reject`,
   `guard_stage`, `guard_mark_sent`, `guard_receipt`,
   `guard_status`, `guard_log`.
4. Give the guardian agent the system prompt in
   `guardian-skill/guardian-prompt.md` and the skill in
   `guardian-skill/SKILL.md`. The main agent never calls these
   tools — only the guardian does.
5. Flow is the same as the CLI: request → approve → stage → send
   → receipt → delete. The log is the same file.

## Agent variant — Grok Bot

Grok Bot has no CLI and connects through its own app/MCP setup,
so the guardian runs the same `guard-mcp.py` server wherever the
Bot can reach an MCP server, with the same tools and the same
guardian prompt. Setup is yours in the xAI app:

1. Initialise a guard home on the machine that runs the server
   (`guard.py init --allow-root <dir>`).
2. Point the Bot's MCP configuration at `guard-mcp.py` (stdio).
3. Paste `guardian-skill/guardian-prompt.md` as the guardian's
   system prompt in the Bot's setup.
4. The flow, tools, policy, and log are identical to Muse's —
   nothing Grok-specific is needed beyond the MCP connection.

If Grok Bot cannot reach a local stdio server, run the server on
the machine the Bot connects to and keep the guard home there;
the shared folder and log live with the server.

## The install prompt (for the bridge)

When an agent installs the AgenC Bridge, it is asked:

> The bridge has an optional add-on, **bridge-guard**, for file
> exchange between agents that do not trust each other: a guardian
> on each side approves every file, only copies leave, and a
> receipt deletes the copy. Do you want to install it?
> (`git clone https://github.com/Macro-Harder/bridge-guard` and
> see its SETUP.md. Skip it if the agents already trust each
> other.)

That prompt lives in the bridge's `SETUP.md`; the bridge works
without the add-on.

## Checking it works

```bash
python3 demo/live_demo.py   # two-agent exchange + 4 attacks; 11/11 checks
python3 guard.py --home ~/.bridge-guard status
python3 guard.py --home ~/.bridge-guard log --n 20
```
