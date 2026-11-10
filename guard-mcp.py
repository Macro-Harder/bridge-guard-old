#!/usr/bin/env python3
"""guard-mcp.py — the bridge-guard guardian as an MCP server.

For agents like Muse and Grok Bot: run this server and the agent
acts as the guardian through its tools. The main agent never touches
a file directly — it asks the guardian (this server) to validate the
request, approve it, stage the copy, and process the receipt.

Stdio JSON-RPC, same shape as bridge-mcp.py: one JSON object per
line on stdin, one per line on stdout. No SDK, stdlib only.

Tools:
  guard_request_file {request}  — intake + policy gate (auto-rejects
                                  anything but a pure file request)
  guard_approve {request_id, approver, reason}
  guard_reject  {request_id, approver, reason}
  guard_stage   {request_id}    — copy to shared, returns path + sha256
  guard_mark_sent {send_id}     — log that the copy was transmitted
  guard_receipt {receipt}       — verify hash, delete the staged copy
  guard_status  {}              — pending requests, staged files
  guard_log     {n}             — recent log entries

Home dir: $BRIDGE_GUARD_HOME, else ~/.bridge-guard.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from guard import Guard, GuardError, VERSION

TOOLS = [
    {"name": "guard_request_file",
     "description": "Validate a file request from an untrusted agent. "
                    "Accepts ONLY a pure file request (kind, id, from, "
                    "to, path, created_at). Anything else — extra "
                    "fields, instructions, commands — is auto-rejected "
                    "and logged. Returns the verdict and, in auto mode, "
                    "the approval.",
     "inputSchema": {"type": "object",
                     "properties": {"request": {"type": "object"}},
                     "required": ["request"]}},
    {"name": "guard_approve",
     "description": "Guardian approves a pending file request.",
     "inputSchema": {"type": "object",
                     "properties": {"request_id": {"type": "string"},
                                    "approver": {"type": "string"},
                                    "reason": {"type": "string"}},
                     "required": ["request_id"]}},
    {"name": "guard_reject",
     "description": "Guardian refuses a pending file request.",
     "inputSchema": {"type": "object",
                     "properties": {"request_id": {"type": "string"},
                                    "approver": {"type": "string"},
                                    "reason": {"type": "string"}},
                     "required": ["request_id"]}},
    {"name": "guard_stage",
     "description": "Copy an approved file into the shared folder. "
                    "Returns the staged path and its SHA-256. Only a "
                    "copy is ever sent; the original is never handed out.",
     "inputSchema": {"type": "object",
                     "properties": {"request_id": {"type": "string"}},
                     "required": ["request_id"]}},
    {"name": "guard_mark_sent",
     "description": "Log that a staged copy's bytes were transmitted.",
     "inputSchema": {"type": "object",
                     "properties": {"send_id": {"type": "string"}},
                     "required": ["send_id"]}},
    {"name": "guard_receipt",
     "description": "Process a received receipt. The receipt's SHA-256 "
                    "must match the staged copy; on a match the copy is "
                    "deleted. A mismatched receipt deletes nothing and "
                    "logs an alert.",
     "inputSchema": {"type": "object",
                     "properties": {"receipt": {"type": "object"}},
                     "required": ["receipt"]}},
    {"name": "guard_status",
     "description": "Guardian status: pending requests, staged files.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "guard_log",
     "description": "Recent guard log entries.",
     "inputSchema": {"type": "object",
                     "properties": {"n": {"type": "integer"}}}},
]


def home():
    return os.environ.get("BRIDGE_GUARD_HOME") or "~/.bridge-guard"


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def call_tool(guard, name, args):
    if name == "guard_request_file":
        req = guard.intake(args.get("request"))
        out = {"request_id": req["id"], "status": "pending",
               "path": req["path"]}
        if guard.policy["auto_approve"]:
            guard.auto_decide(req["id"])
            out["status"] = "approved"
            out["note"] = "auto-approved by policy (auto mode)"
        else:
            out["note"] = "pending guardian approval"
        return out
    if name == "guard_approve":
        req = guard.decide(args["request_id"],
                           args.get("approver") or "guardian",
                           True, reason=args.get("reason") or "")
        return {"request_id": req["id"], "status": req["status"]}
    if name == "guard_reject":
        req = guard.decide(args["request_id"],
                           args.get("approver") or "guardian",
                           False, reason=args.get("reason") or "")
        return {"request_id": req["id"], "status": req["status"]}
    if name == "guard_stage":
        send_id, path, digest = guard.stage(args["request_id"])
        return {"send_id": send_id, "staged_path": path,
                "sha256": digest}
    if name == "guard_mark_sent":
        send = guard.mark_sent(args["send_id"])
        return {"send_id": send["send_id"], "status": send["status"]}
    if name == "guard_receipt":
        send = guard.receipt(args.get("receipt"))
        return {"send_id": send["send_id"], "status": send["status"],
                "deleted": True}
    if name == "guard_status":
        return guard.status()
    if name == "guard_log":
        n = args.get("n") or 20
        if not guard.log_path.exists():
            return {"entries": []}
        lines = guard.log_path.read_text().splitlines()
        return {"entries": [json.loads(l) for l in lines[-n:]]}
    raise GuardError("unknown tool: %s" % name)


def _companion_startup_check():
    try:
        from guard import companion
        companion.check_startup(companion.declared_level(home()))
    except Exception:
        pass


def main():
    _companion_startup_check()
    guard = Guard(home())
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except Exception as e:
            sys.stderr.write(
                "guard-mcp: ignoring malformed JSON line (%s)\n" % e)
            sys.stderr.flush()
            continue
        if not isinstance(msg, dict):
            continue
        rid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "bridge-guard",
                               "version": VERSION}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": rid,
                  "result": {"tools": TOOLS}})
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                out = call_tool(guard, params.get("name"),
                                params.get("arguments") or {})
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": json.dumps(out, indent=2)}]}})
            except GuardError as e:
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text", "text": str(e)}],
                    "isError": True}})
            except Exception as e:
                send({"jsonrpc": "2.0", "id": rid, "result": {
                    "content": [{"type": "text",
                                 "text": "guard error: %s" % e}],
                    "isError": True}})
        elif method == "ping":
            if rid is not None:
                send({"jsonrpc": "2.0", "id": rid, "result": {}})
        elif method == "notifications/initialized":
            continue
        else:
            send({"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32601, "message": "method not found: %s"
                                           % method}})


if __name__ == "__main__":
    main()
