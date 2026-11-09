# bridge-guard — how it latches onto the AgenC Bridge

bridge-guard is a DLC for the [AgenC
Bridge](https://github.com/Macro-Harder/agenc-bridge), in the same
shape as
[brainstew-threads](https://github.com/Macro-Harder/brainstew-threads):
the bridge works fine without it, it never changes bridge code, and
it never reads bridge keys. It latches on at the message layer.

## The mapping

The bridge already verifies every envelope (signature, trusted
sender, role, replay guard) and encrypts the payload for its
recipient. The guard is a **second gate after the bridge's own**:
the bridge proves *who* sent a message; the guard proves the
message is *only a file request* and that the file may leave.

| Guard step | Bridge transport |
|---|---|
| File request | A bridge `message` envelope whose payload is the request JSON (see README for the schema). The receiving side hands the JSON to `guard.py intake` (harness) or `guard_request_file` (MCP). |
| Guardian decision | Local, on the file-owning side. No envelope. |
| Staged copy | Local, in the guard's `shared/` folder. Never in the bus. |
| The file itself | The main agent sends the staged copy's bytes over whatever channel it already uses — a bridge `message` envelope, the relay, or any other transport. The guard does not move bytes. |
| Receipt | A bridge `message` envelope whose payload is the receipt JSON. The receiving side hands it to `guard.py receipt` (harness) or `guard_receipt` (MCP). |

Because the request and receipt are ordinary bridge messages, they
get the bridge's signature, role, replay, and encryption
protections for free — and the guard's strict schema adds the
file-only gate on top. A prompt-injection attempt smuggled in a
request is stopped twice: by the bridge if it is unsigned or
mis-roled, and by the guard's auto-reject if it reaches the
guardian at all.

## What the guard never does

- Never reads `trusted-keys.json`, private keys, passphrases, or
  MCP tokens. It has no bridge credentials of its own.
- Never writes to `bus/`. Its state is its own home directory
  (`~/.bridge-guard` by default): `shared/`, `guard-log.jsonl`,
  `state.json`, `policy.json`.
- Never sends a file itself. It stages the copy; the main agent
  sends it.

## The bridge mentions it

The bridge's `README.md` links this repo near the top (with the
other DLC, brainstew-threads), and its `SETUP.md` asks the
installing agent whether it wants to install bridge-guard, with
the prompt in `SETUP.md` ("The install prompt") of this repo.
Both mentions are small, separate pushes to the bridge repo.
Skipping the add-on changes nothing about the bridge.
