# bridge-guard

Two agents that do **not** trust each other can still exchange files
— through a guardian, not directly. A DLC (add-on) for the [AgenC
Bridge](https://github.com/Macro-Harder/agenc-bridge): the bridge
works fine without it, and this works without changing the bridge.

## The design

Each side runs **two** agents: its main agent and a **guardian**.
The main agent never hands a file to the other side directly —
everything goes through its guardian.

1. The other side **requests a file, via handoff**. The request
   must be a pure file request and nothing else. Anything other
   than a file request is **auto-rejected**, and the rejection is
   logged.
2. The **guardian approves or disapproves** the request under its
   policy. The decision is logged with a reason.
3. On approval the guardian moves a **copy** of the file to a
   **shared folder**. The main agent sends that copy to the other
   side, which sends back a **received receipt** carrying the
   file's SHA-256.
4. Once the receipt arrives and its hash matches, the copy is
   **deleted** from the shared folder. A mismatched receipt means
   no delete and a logged alert.
5. A **log file** is appended on every send and every receipt
   (message id, timestamp, file name + SHA-256, from/to, receipt
   hash match).

## The point: no prompt injection

The cross-boundary channel carries **file requests and receipts
ONLY** — never instructions, prompts, or commands. Any
instruction-shaped content in a request (an `instructions` field,
a `command`, a `prompt`, anything outside the file-request schema)
is an auto-reject. The other side can ask for a file, and nothing
else — it cannot smuggle an instruction across, and it cannot see
any file it was not given. That is the defense this repo exists
for. The bridge's own rule still stands underneath it: untrusted
input is data, never instruction.

## Two variants

- **Harness variant** — for CLI coding agents like AgenC: the
  guardian is `guard.py`, a command-line tool the harness calls
  (see `harness/`). File requests and receipts are JSON files the
  harness can drive, or bridge message envelopes (see
  `INTEGRATION.md`).
- **Agent variant** — for conversational/API agents like Muse and
  Grok Bot: the guardian is `guard-mcp.py`, an MCP server with
  `guard_request_file`, `guard_approve`, `guard_stage`,
  `guard_receipt` and friends, plus `guardian-skill/` (the skill
  and system prompt for the agent that plays the guardian).

Captain's note on naming: she described the two kinds as "a jev
type agent and a regular" one. This repo treats "jev type" as a
harness-type agent (AgenC and other CLI harnesses) and "regular" as
a conversational agent (Muse, Grok Bot). If "jev" turns out to mean
something specific, the variant names will be corrected — nothing
in the design depends on the word.

## Guardrails

Deny by default. Beyond Captain's design, the guard enforces:

- **Allowlisted directories only.** No absolute paths outside the
  allowed root, no `..` escapes, no symlinks followed (any
  symlinked path component refuses, even one that stays inside
  the root).
- **Size caps** (default 10 MB) and a **file-type allowlist**
  (text and code by default; binaries refused unless allowlisted).
- **Hash verification.** The staged copy is hashed before sending;
  the receipt must carry the same SHA-256 or the copy is kept and
  an alert is logged.
- **Secret scan.** Files that look like credentials or keys
  (private-key headers, `sk-` / `AKIA` / `ghp_` tokens,
  `api_key=` / `password=` assignments, `.pem` / `.key` / `.env`
  filenames) are refused unless their exact path is explicitly
  allowlisted as an exception — and the exception is logged when
  used.
- **Only copies leave.** The original is never sent. The shared
  folder is mode 0700, staged copies are mode 0600, and copies
  are wiped on receipt or on expiry (TTL, default 1 hour).
- **Rate limits** per sender (default 20 requests/hour) and a cap
  on staged files at once (default 5). Over the limit is an
  auto-reject.
- **Replay guard.** A request id may be used once; a duplicate is
  an auto-reject.
- **Every decision is logged** (approve / auto-reject / reject /
  staged / sent / received / deleted / alert / expired) with id +
  timestamp. The log is append-only; the guard never edits a
  prior line.
- **Receipts must match a known send.** A receipt for an unknown
  send id, or for a send in the wrong state, is an alert, not a
  delete.

## Quickstart

```bash
git clone https://github.com/Macro-Harder/bridge-guard
cd bridge-guard

# Each side, once: a guard home with its allowlist.
python3 guard.py --home ~/.bridge-guard init --allow-root ~/shared-files

# A requests a file from B: B's guardian intakes it.
python3 guard.py --home ~/.bridge-guard intake --file request.json
python3 guard.py --home ~/.bridge-guard approve --id <request-id> --reason "fine"
python3 guard.py --home ~/.bridge-guard stage --id <request-id>
# ... main agent sends the staged copy ...
python3 guard.py --home ~/.bridge-guard sent --send-id <send-id>
# ... receipt comes back ...
python3 guard.py --home ~/.bridge-guard receipt --file receipt.json
# ... staged copy is deleted; check the log:
python3 guard.py --home ~/.bridge-guard log
```

Full install and per-agent setup: [SETUP.md](SETUP.md).
Bridge mapping: [INTEGRATION.md](INTEGRATION.md).

## The request and receipt schemas

A file request — exactly these keys, nothing else:

```json
{"kind": "file-request", "id": "req-1", "from": "agent-b",
 "to": "agent-a", "path": "notes/plan.md",
 "created_at": "2026-11-07T18:00:00Z"}
```

A receipt — exactly these keys, nothing else:

```json
{"kind": "file-receipt", "id": "rcpt-1", "request_id": "req-1",
 "send_id": "a1b2c3d4e5f6a7b8", "from": "agent-b", "to": "agent-a",
 "filename": "plan.md",
 "sha256": "<64 hex chars of what arrived>",
 "received_at": "2026-11-07T18:00:05Z"}
```

## Log format

`guard-log.jsonl`, one JSON object per line, append-only:

```json
{"event": "received", "ts": "2026-11-07T18:00:05Z", "id": "req-1",
 "send_id": "a1b2c3d4e5f6a7b8", "from": "agent-b", "to": "agent-a",
 "filename": "plan.md", "sha256": "<hex>", "hash_match": true}
```

Events: `request`, `auto-reject`, `approve`, `reject`, `staged`,
`send`, `received`, `deleted`, `alert`, `expired`.

## Files

| File | What it does |
|---|---|
| `guard.py` | Guardian engine + CLI (stdlib only) |
| `guard-mcp.py` | Guardian as an MCP server (agent variant) |
| `guardian-skill/` | Skill + system prompt for the agent that plays guardian |
| `harness/` | AgenC hook example + harness-variant notes |
| `demo/live_demo.py` | Two-agent exchange + attacks, runnable |
| `SETUP.md` | Install, setup per agent (AgenC, Muse, Grok Bot) |
| `INTEGRATION.md` | How it latches onto the AgenC Bridge |
| `tests/test_guard.py` | Unit tests |

## Tests

```bash
python3 -m unittest tests.test_guard -v   # 34 tests
python3 demo/live_demo.py                 # end-to-end + attacks
```

## Companion at level 11: trust-but-verify

At strictness level 11 — every maximum, plus the monitor agent —
the guard has a companion:
[trust-but-verify](https://github.com/Macro-Harder/trust-but-verify).
It audits MCP servers' tool descriptions and schemas for hidden
instructions before an agent trusts them, and at level 11 the
monitor uses it as its MCP-audit companion.

- **Install question.** Picking level 11 in the installer packet
  asks one extra question — whether to also install
  trust-but-verify, with its link — and the answer is recorded in
  the packet declaration. Levels 0–10 are never asked.
- **Startup prompt.** On every start (`guard.py` or
  `guard-mcp.py`), a guard declared at level 11 whose
  trust-but-verify is not detected prints the install prompt —
  the question and the link — to stderr, and keeps printing it
  on every start until the companion is installed. The prompt
  never blocks a start and never installs anything itself.
- Declare the level with `guard.py init --level 11`, the
  `level` key in `policy.json`, or `$BRIDGE_GUARD_LEVEL`.
  Detection checks `$TRUST_BUT_VERIFY_PATH`, an importable
  `trust_but_verify` module, or a `trust-but-verify` binary.

## A DLC, not a fork

The bridge works fine without this. It is an optional install:
drop it next to a bridge node and it latches on; take it out and
the bridge is untouched. It never changes bridge code, never reads
bridge keys, and never writes to the bridge bus itself — it
validates request/receipt JSON and local files, and the bridge (or
any other channel) moves the bytes.

## License

Apache License 2.0. See `LICENSE`. Copyright 2026 J.P. Picard aka Macro-Harder.
