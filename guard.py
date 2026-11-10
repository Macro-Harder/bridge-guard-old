#!/usr/bin/env python3
"""bridge-guard — a guardian for file exchange between agents that do
not trust each other.

Two agents (A and B) that do not trust each other can still exchange
files through this guard. Each side runs TWO agents: its main agent and
a guardian. The main agent never hands a file to the other side
directly — everything goes through its guardian:

  1. The other side requests a file, via handoff. The request must be
     a pure file request and nothing else. Anything other than a file
     request is AUTO-REJECTED, and the rejection is logged.
  2. The guardian on the file-owning side approves or disapproves the
     request under its policy. The decision is logged with a reason.
  3. On approval the guardian moves a COPY of the file to a shared
     folder. The main agent sends that copy to the other side, which
     sends back a received receipt carrying the file's SHA-256.
  4. Once the receipt arrives and its hash matches, the copy is
     DELETED from the shared folder. A mismatched receipt means no
     delete and a logged alert.

The cross-boundary channel carries file requests and receipts ONLY —
never instructions, prompts, or commands. Any instruction-shaped
content in a request is an auto-reject. That is the prompt-injection
defense: the other side can ask for a file, and nothing else.

Stdlib-only Python. No bridge import — the guard latches onto any
transport (the AgenC bridge, a relay, a shared folder) because it
works on request/receipt JSON and local files, never on bridge keys.
See INTEGRATION.md for the bridge mapping and README.md for the
guardrails.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

VERSION = "0.1.0"

DEFAULT_MAX_BYTES = 10 * 1024 * 1024          # 10 MB per file
DEFAULT_ALLOWED_EXTS = {
    ".md", ".txt", ".py", ".json", ".yaml", ".yml", ".csv",
    ".ts", ".js", ".html", ".css", ".toml", ".ini", ".cfg",
    ".log", ".xml", ".sh",
}
DEFAULT_TTL_SECONDS = 3600                     # unclaimed copy lifetime
DEFAULT_MAX_REQUESTS_PER_HOUR = 20
DEFAULT_MAX_STAGED = 5

# The request schema, exactly. No other keys are allowed.
REQUEST_KEYS = {"kind", "id", "from", "to", "path", "created_at"}
RECEIPT_KEYS = {"kind", "id", "request_id", "send_id", "from", "to",
                "filename", "sha256", "received_at"}

# A field with one of these names is instruction-shaped content, not
# a file request. Its presence is an auto-reject.
INSTRUCTION_KEYS = {
    "prompt", "instructions", "instruction", "command", "run",
    "execute", "system", "message", "text", "content", "note",
    "notes", "task", "action", "code", "script", "shell",
    "directive", "order", "goal",
}

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Obvious secret patterns. A file whose content matches one is
# refused unless its exact path is in the policy's `exceptions`.
SECRET_PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"sk-[A-Za-z0-9]{20,}"),
    re.compile(rb"sk-ant-[A-Za-z0-9-]{10,}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"gho_[A-Za-z0-9]{20,}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(rb"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S{8,}"),
    re.compile(rb"(?i)password\s*[:=]\s*\S{4,}"),
    re.compile(rb"(?i)passwd\s*[:=]\s*\S{4,}"),
    re.compile(rb"(?i)\bsecret\s*[:=]\s*\S{4,}"),
    re.compile(rb"(?i)\btoken\s*[:=]\s*\S{8,}"),
    re.compile(rb"(?i)OPENROUTER_API_KEY\s*[:=]"),
    re.compile(rb"(?i)aws_secret_access_key\s*[:=]"),
]

# Filenames that are refused outright (unless in `exceptions`).
SECRET_FILENAMES = [
    re.compile(r"(?i)(^|/)\.env(\.|$)"),
    re.compile(r"(?i)\.pem$"),
    re.compile(r"(?i)\.key$"),
    re.compile(r"(?i)\.enc$"),
    re.compile(r"(?i)(^|/)credentials"),
    re.compile(r"(?i)secret"),
    re.compile(r"(?i)(^|/)id_rsa"),
    re.compile(r"(?i)(^|/)\.ssh(/|$)"),
]


def utcnow():
    return datetime.now(timezone.utc)


def iso_now():
    return utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text):
    """An ISO-8601 timestamp back to a datetime, or None."""
    if not isinstance(text, str):
        return None
    try:
        return datetime.strptime(
            text.replace("Z", "+00:00"), "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_safe_name(value):
    return isinstance(value, str) and bool(_SAFE_NAME.match(value))


class GuardError(Exception):
    """A refusal with a reason safe to show and log."""


def validate_request(obj):
    """Strict-schema check on a file request.

    Returns the request as a clean dict. Raises GuardError on
    anything that is not exactly a pure file request — wrong kind,
    extra keys, instruction-shaped keys, bad names, bad path shape,
    unparseable timestamp. This is the prompt-injection gate: the
    request may name a file and nothing else.
    """
    if not isinstance(obj, dict):
        raise GuardError("request is not a JSON object")
    keys = set(obj)
    extra = keys - REQUEST_KEYS
    if extra:
        instruction = sorted(extra & INSTRUCTION_KEYS)
        if instruction:
            raise GuardError(
                "auto-reject: instruction-shaped field(s) in request: "
                + ", ".join(instruction))
        raise GuardError(
            "auto-reject: unexpected field(s) in request: "
            + ", ".join(sorted(extra)))
    missing = REQUEST_KEYS - keys
    if missing:
        raise GuardError(
            "auto-reject: missing field(s): " + ", ".join(sorted(missing)))
    if obj["kind"] != "file-request":
        raise GuardError(
            "auto-reject: kind is not file-request: %r" % obj["kind"])
    for field in ("id", "from", "to"):
        if not _is_safe_name(obj[field]):
            raise GuardError("auto-reject: bad %s: %r" % (field, obj[field]))
    if parse_iso(obj["created_at"]) is None:
        raise GuardError("auto-reject: bad created_at: %r"
                         % obj["created_at"])
    age = (utcnow() - parse_iso(obj["created_at"])).total_seconds()
    if age > 24 * 3600:
        raise GuardError("auto-reject: request is older than 24h")
    if age < -300:
        raise GuardError("auto-reject: created_at is in the future")
    validate_path_shape(obj["path"])
    return dict(obj)


def validate_receipt(obj):
    """Strict-schema check on a file receipt. Same gate as requests:
    only the receipt fields, nothing else."""
    if not isinstance(obj, dict):
        raise GuardError("receipt is not a JSON object")
    keys = set(obj)
    extra = keys - RECEIPT_KEYS
    if extra:
        raise GuardError(
            "auto-reject: unexpected field(s) in receipt: "
            + ", ".join(sorted(extra)))
    missing = RECEIPT_KEYS - keys
    if missing:
        raise GuardError(
            "auto-reject: missing field(s): " + ", ".join(sorted(missing)))
    if obj["kind"] != "file-receipt":
        raise GuardError(
            "auto-reject: kind is not file-receipt: %r" % obj["kind"])
    for field in ("id", "request_id", "send_id", "from", "to"):
        if not _is_safe_name(obj[field]):
            raise GuardError("auto-reject: bad %s: %r" % (field, obj[field]))
    if not isinstance(obj["filename"], str) or not obj["filename"] \
            or "/" in obj["filename"] or "\\" in obj["filename"]:
        raise GuardError("auto-reject: bad filename: %r"
                         % obj["filename"])
    if not re.fullmatch(r"[0-9a-f]{64}", obj["sha256"] or ""):
        raise GuardError("auto-reject: bad sha256 in receipt")
    if parse_iso(obj["received_at"]) is None:
        raise GuardError("auto-reject: bad received_at: %r"
                         % obj["received_at"])
    return dict(obj)


def validate_path_shape(path):
    """The path must be a plain relative path: no absolute path, no
    `..`, no backslash, no NUL, no empty components."""
    if not isinstance(path, str) or not path:
        raise GuardError("auto-reject: path is not a non-empty string")
    if "\x00" in path or "\\" in path:
        raise GuardError("auto-reject: bad characters in path: %r" % path)
    p = PurePosixPath(path)
    if p.is_absolute():
        raise GuardError("auto-reject: absolute path: %r" % path)
    if ".." in p.parts:
        raise GuardError("auto-reject: path escapes its root: %r" % path)
    if any(part in ("", ".") for part in p.parts):
        raise GuardError("auto-reject: bad path component in: %r" % path)
    return path


def scan_secrets(data, filename):
    """Return the reason a file is refused as secret-looking, or None.
    Checks the filename first, then the content."""
    for pat in SECRET_FILENAMES:
        if pat.search(filename):
            return "secret-looking filename: %s" % filename
    for pat in SECRET_PATTERNS:
        if pat.search(data):
            return "secret pattern matched in file content"
    return None

DEFAULT_POLICY = {
    "allow_roots": [],
    "max_bytes": DEFAULT_MAX_BYTES,
    "allowed_exts": sorted(DEFAULT_ALLOWED_EXTS),
    "exceptions": [],
    "auto_approve": False,
    "max_requests_per_hour": DEFAULT_MAX_REQUESTS_PER_HOUR,
    "max_staged": DEFAULT_MAX_STAGED,
    "ttl_seconds": DEFAULT_TTL_SECONDS,
}


class Guard:
    """One side's guardian. Holds its policy, its shared (staging)
    folder, its append-only log, and its state file.

    The guardian never reads a file into an agent's context and
    never sends an original — only a staged copy, only after
    approval, only to a request that passed the strict schema.
    """

    def __init__(self, home, policy=None):
        self.home = Path(home).expanduser()
        self.shared = self.home / "shared"
        self.log_path = self.home / "guard-log.jsonl"
        self.state_path = self.home / "state.json"
        self.policy_path = self.home / "policy.json"
        self.policy = dict(DEFAULT_POLICY)
        if policy:
            self.policy.update(policy)
        if self.policy_path.exists():
            try:
                saved = json.loads(self.policy_path.read_text())
                if isinstance(saved, dict):
                    self.policy.update(saved)
            except Exception:
                pass
        self.home.mkdir(parents=True, exist_ok=True)
        self.shared.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.shared, 0o700)
        except OSError:
            pass

    # -- persistence ------------------------------------------------

    def _load_state(self):
        if not self.state_path.exists():
            return {"requests": {}, "sends": {}, "seen_ids": [],
                    "rate": {}}
        try:
            state = json.loads(self.state_path.read_text())
            if isinstance(state, dict):
                state.setdefault("requests", {})
                state.setdefault("sends", {})
                state.setdefault("seen_ids", [])
                state.setdefault("rate", {})
                return state
        except Exception:
            pass
        return {"requests": {}, "sends": {}, "seen_ids": [],
                "rate": {}}

    def _save_state(self, state):
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        os.replace(tmp, self.state_path)

    def log(self, event, **fields):
        """Append one JSONL line. The log is append-only; the guard
        never edits a prior line."""
        entry = {"event": event, "ts": iso_now()}
        # `from` is a Python keyword, so callers pass from_=...;
        # the log itself carries the plain field name.
        if "from_" in fields:
            fields["from"] = fields.pop("from_")
        entry.update(fields)
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def save_policy(self):
        self.policy_path.write_text(json.dumps(self.policy, indent=2))

    # -- intake: the prompt-injection gate --------------------------

    def intake(self, obj, sender=None):
        """Validate a file request and record it as pending policy.

        Returns the stored request. Raises GuardError (and logs an
        auto-reject) for anything that is not exactly a pure file
        request. The sender is taken from the request's `from`
        field unless given explicitly, and must match.
        """
        try:
            req = validate_request(obj)
        except GuardError as e:
            rid = obj.get("id") if isinstance(obj, dict) else None
            self.log("auto-reject", id=rid,
                     from_=sender or (obj.get("from")
                                     if isinstance(obj, dict) else None),
                     reason=str(e))
            raise
        if sender is not None and sender != req["from"]:
            self.log("auto-reject", id=req["id"], from_=sender,
                     reason="auto-reject: sender does not match from field")
            raise GuardError(
                "auto-reject: sender does not match from field")
        state = self._load_state()
        if req["id"] in state["seen_ids"]:
            self.log("auto-reject", id=req["id"], from_=req["from"],
                     reason="auto-reject: duplicate request id (replay)")
            raise GuardError("auto-reject: duplicate request id (replay)")
        # Rate limit, per sender per hour.
        now = utcnow()
        window = now - timedelta(hours=1)
        stamps = [parse_iso(t) for t in
                  state["rate"].get(req["from"], [])]
        stamps = [t for t in stamps if t and t > window]
        if len(stamps) >= self.policy["max_requests_per_hour"]:
            self.log("auto-reject", id=req["id"], from_=req["from"],
                     reason="auto-reject: rate limit for sender")
            raise GuardError("auto-reject: rate limit for sender")
        stamps.append(now)
        state["rate"][req["from"]] = [t.strftime("%Y-%m-%dT%H:%M:%SZ")
                                      for t in stamps]
        state["seen_ids"].append(req["id"])
        state["seen_ids"] = state["seen_ids"][-1000:]
        state["requests"][req["id"]] = dict(req, status="pending",
                                            decided_by=None,
                                            decision_reason=None)
        self._save_state(state)
        self.log("request", id=req["id"], from_=req["from"],
                 to=req["to"], path=req["path"])
        return dict(req)

    # -- policy: what may leave this side ---------------------------

    def _resolve(self, rel_path):
        """Resolve a request path against the allow roots.

        Returns the real file path, or raises GuardError. No
        symlinks are followed: any symlinked component refuses.
        The resolved path must stay inside its allow root.
        """
        for root in self.policy["allow_roots"]:
            root_path = Path(root).expanduser()
            try:
                root_real = root_path.resolve()
            except OSError:
                continue
            candidate = root_real.joinpath(*PurePosixPath(rel_path).parts)
            # Refuse symlinks anywhere on the path.
            cur = root_real
            for part in PurePosixPath(rel_path).parts:
                cur = cur / part
                try:
                    if cur.is_symlink():
                        raise GuardError(
                            "policy-refuse: symlinked path component: %s"
                            % part)
                except OSError:
                    pass
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved == root_real or root_real not in resolved.parents:
                continue
            return resolved
        raise GuardError(
            "policy-refuse: path is not under an allowed root: %r"
            % rel_path)

    def policy_check(self, rel_path):
        """The allow/deny decision for a path. Returns (ok, reason).
        Deny by default: allowlisted roots only, size cap, file-type
        allowlist, secret scan (unless explicitly excepted)."""
        try:
            resolved = self._resolve(rel_path)
        except GuardError as e:
            return False, str(e)
        if not resolved.is_file():
            return False, "policy-refuse: not a regular file: %r" % rel_path
        try:
            size = resolved.stat().st_size
        except OSError as e:
            return False, "policy-refuse: cannot stat file: %s" % e
        if size > self.policy["max_bytes"]:
            return False, ("policy-refuse: file is %d bytes, over the "
                           "%d byte cap" % (size, self.policy["max_bytes"]))
        if resolved.suffix.lower() not in \
                {e.lower() for e in self.policy["allowed_exts"]}:
            return False, ("policy-refuse: extension %r is not in the "
                           "allowlist" % resolved.suffix)
        try:
            data = resolved.read_bytes()
        except OSError as e:
            return False, "policy-refuse: cannot read file: %s" % e
        if rel_path not in self.policy["exceptions"]:
            reason = scan_secrets(data, resolved.name)
            if reason:
                return False, "policy-refuse: " + reason
        return True, "ok"

    # -- guardian decision ------------------------------------------

    def decide(self, request_id, approver, approve, reason=""):
        """The guardian's decision. Returns the stored request.

        A policy failure refuses regardless of the decision — the
        guardian may not approve what policy forbids. In auto mode
        a policy pass approves without a guardian call; in manual
        mode (the default) the guardian approves each request.
        """
        state = self._load_state()
        req = state["requests"].get(request_id)
        if req is None:
            raise GuardError("unknown request id: %r" % request_id)
        if req["status"] != "pending":
            raise GuardError("request %s is already %s"
                             % (request_id, req["status"]))
        ok, policy_reason = self.policy_check(req["path"])
        if not ok:
            req["status"] = "rejected"
            req["decided_by"] = approver
            req["decision_reason"] = policy_reason
            self._save_state(state)
            self.log("reject", id=request_id, from_=req["from"],
                     to=req["to"], path=req["path"],
                     decided_by=approver, reason=policy_reason)
            raise GuardError(policy_reason)
        if not approve:
            req["status"] = "rejected"
            req["decided_by"] = approver
            req["decision_reason"] = reason or "guardian refused"
            self._save_state(state)
            self.log("reject", id=request_id, from_=req["from"],
                     to=req["to"], path=req["path"],
                     decided_by=approver,
                     reason=req["decision_reason"])
            return dict(req)
        req["status"] = "approved"
        req["decided_by"] = approver
        req["decision_reason"] = reason or "guardian approved"
        self._save_state(state)
        self.log("approve", id=request_id, from_=req["from"],
                 to=req["to"], path=req["path"],
                 decided_by=approver, reason=req["decision_reason"])
        return dict(req)

    def auto_decide(self, request_id, approver="policy"):
        """Auto mode: approve iff policy passes, else refuse. Used
        by the harness variant where no guardian agent is in the
        loop for every request."""
        state = self._load_state()
        req = state["requests"].get(request_id)
        if req is None:
            raise GuardError("unknown request id: %r" % request_id)
        return self.decide(request_id, approver, True,
                           reason="auto-approved by policy")

    # -- staging, sending, receipts ---------------------------------

    def stage(self, request_id):
        """Copy the approved file into the shared folder. Returns
        (send_id, staged_path, sha256). Only a copy is ever sent —
        the original is never handed out."""
        state = self._load_state()
        req = state["requests"].get(request_id)
        if req is None:
            raise GuardError("unknown request id: %r" % request_id)
        if req["status"] != "approved":
            raise GuardError("request %s is %s, not approved"
                             % (request_id, req["status"]))
        ok, policy_reason = self.policy_check(req["path"])
        if not ok:
            raise GuardError(policy_reason)
        resolved = self._resolve(req["path"])
        staged_sends = [s for s in state["sends"].values()
                        if s["status"] in ("staged", "sent")]
        if len(staged_sends) >= self.policy["max_staged"]:
            raise GuardError("refuse: too many files staged at once "
                             "(max %d)" % self.policy["max_staged"])
        send_id = uuid.uuid4().hex[:16]
        staged_name = "%s_%s" % (send_id, resolved.name)
        staged_path = self.shared / staged_name
        shutil.copyfile(resolved, staged_path)
        try:
            os.chmod(staged_path, 0o600)
        except OSError:
            pass
        digest = sha256_file(staged_path)
        # The copy is verified by hash before it may be sent: hash
        # the staged copy itself, not the original.
        if digest != sha256_file(resolved):
            staged_path.unlink(missing_ok=True)
            raise GuardError("refuse: staged copy hash does not match "
                             "the original")
        state["sends"][send_id] = {
            "send_id": send_id, "request_id": request_id,
            "from": req["from"], "to": req["to"],
            "path": req["path"], "filename": resolved.name,
            "sha256": digest, "staged_name": staged_name,
            "staged_at": iso_now(), "status": "staged",
        }
        self._save_state(state)
        self.log("staged", id=request_id, send_id=send_id,
                 from_=req["from"], to=req["to"], path=req["path"],
                 filename=resolved.name, sha256=digest)
        return send_id, str(staged_path), digest

    def mark_sent(self, send_id):
        """The main agent calls this once the staged copy's bytes
        have been transmitted. Appends the send log entry."""
        state = self._load_state()
        send = state["sends"].get(send_id)
        if send is None:
            raise GuardError("unknown send id: %r" % send_id)
        if send["status"] != "staged":
            raise GuardError("send %s is %s, not staged"
                             % (send_id, send["status"]))
        send["status"] = "sent"
        send["sent_at"] = iso_now()
        self._save_state(state)
        self.log("send", id=send["request_id"], send_id=send_id,
                 from_=send["from"], to=send["to"],
                 filename=send["filename"], sha256=send["sha256"])
        return dict(send)

    def receipt(self, obj):
        """Process a received receipt. The receipt must carry the
        same SHA-256 as the staged copy; on a match the copy is
        DELETED from the shared folder. A mismatched or unknown
        receipt deletes nothing and logs an alert."""
        try:
            rec = validate_receipt(obj)
        except GuardError as e:
            self.log("alert", reason=str(e))
            raise
        state = self._load_state()
        send = state["sends"].get(rec["send_id"])
        if send is None:
            self.log("alert", id=rec["request_id"],
                     send_id=rec["send_id"], from_=rec["from"],
                     reason="alert: receipt for unknown send id")
            raise GuardError("alert: receipt for unknown send id")
        if send["status"] != "sent":
            self.log("alert", id=rec["request_id"],
                     send_id=rec["send_id"], from_=rec["from"],
                     reason="alert: receipt for send in state %s"
                            % send["status"])
            raise GuardError("alert: receipt for send in state %s"
                             % send["status"])
        if rec["sha256"] != send["sha256"] \
                or rec["filename"] != send["filename"]:
            self.log("alert", id=rec["request_id"],
                     send_id=rec["send_id"], from_=rec["from"],
                     filename=rec["filename"], sha256=rec["sha256"],
                     reason="alert: receipt hash/filename does not match "
                            "the staged copy — copy NOT deleted")
            raise GuardError("alert: receipt hash does not match — "
                             "copy kept, investigate")
        staged_path = self.shared / send["staged_name"]
        staged_path.unlink(missing_ok=True)
        send["status"] = "received"
        send["received_at"] = iso_now()
        self._save_state(state)
        self.log("received", id=rec["request_id"],
                 send_id=rec["send_id"], from_=rec["from"],
                 to=rec["to"], filename=send["filename"],
                 sha256=send["sha256"], hash_match=True)
        self.log("deleted", id=rec["request_id"],
                 send_id=rec["send_id"], filename=send["filename"],
                 reason="staged copy deleted after matching receipt")
        return dict(send)

    def sweep(self):
        """Delete staged copies older than the TTL. Returns the
        list of expired send ids."""
        state = self._load_state()
        now = utcnow()
        expired = []
        for send_id, send in list(state["sends"].items()):
            if send["status"] not in ("staged", "sent"):
                continue
            staged_at = parse_iso(send.get("staged_at") or "")
            if staged_at is None:
                continue
            if (now - staged_at).total_seconds() > \
                    self.policy["ttl_seconds"]:
                (self.shared / send["staged_name"]).unlink(
                    missing_ok=True)
                send["status"] = "expired"
                expired.append(send_id)
                self.log("expired", id=send["request_id"],
                         send_id=send_id, filename=send["filename"],
                         reason="staged copy expired (TTL %ds) and was "
                                "deleted" % self.policy["ttl_seconds"])
        if expired:
            self._save_state(state)
        return expired

    def status(self):
        state = self._load_state()
        pending = [r for r in state["requests"].values()
                   if r["status"] == "pending"]
        staged = [s for s in state["sends"].values()
                  if s["status"] in ("staged", "sent")]
        return {
            "home": str(self.home),
            "allow_roots": list(self.policy["allow_roots"]),
            "auto_approve": bool(self.policy["auto_approve"]),
            "pending_requests": len(pending),
            "staged_files": len(staged),
            "shared_dir": str(self.shared),
            "log": str(self.log_path),
        }


# -- CLI --------------------------------------------------------------

def _home(args):
    return args.home or os.environ.get("BRIDGE_GUARD_HOME") or \
        "~/.bridge-guard"


def _load_json_file(path):
    with open(path) as f:
        return json.load(f)


def _fail(message):
    print("guard: %s" % message, file=sys.stderr)
    return 1


def cmd_init(args):
    policy = {}
    if args.allow_root:
        policy["allow_roots"] = args.allow_root
    if args.auto:
        policy["auto_approve"] = True
    if args.max_bytes:
        policy["max_bytes"] = args.max_bytes
    if args.level is not None:
        if not 0 <= args.level <= 11:
            return _fail("level %d outside 0..11" % args.level)
        policy["level"] = args.level
    g = Guard(_home(args), policy)
    g.save_policy()
    print("guard home: %s" % g.home)
    print("shared folder: %s" % g.shared)
    print("allow roots: %s"
          % (", ".join(g.policy["allow_roots"]) or "(none — add some)"))
    print("mode: %s" % ("auto-approve by policy"
                        if g.policy["auto_approve"]
                        else "manual guardian approval"))
    return 0


def cmd_intake(args):
    g = Guard(_home(args))
    try:
        req = _load_json_file(args.file)
    except Exception as e:
        return _fail("cannot read request file: %s" % e)
    try:
        req = g.intake(req, sender=args.sender)
    except GuardError as e:
        return _fail(str(e))
    print("request %s accepted for policy: %s"
          % (req["id"], req["path"]))
    if g.policy["auto_approve"]:
        try:
            g.auto_decide(req["id"])
            print("auto-approved by policy (auto mode)")
        except GuardError as e:
            return _fail(str(e))
    else:
        print("pending guardian approval "
              "(guard.py approve --id %s)" % req["id"])
    return 0


def cmd_decide(args, approve):
    g = Guard(_home(args))
    try:
        req = g.decide(args.id, args.approver or "guardian", approve,
                       reason=args.reason or "")
    except GuardError as e:
        return _fail(str(e))
    print("request %s %s" % (args.id, req["status"]))
    return 0


def cmd_stage(args):
    g = Guard(_home(args))
    try:
        send_id, path, digest = g.stage(args.id)
    except GuardError as e:
        return _fail(str(e))
    print("staged: %s" % path)
    print("send_id: %s" % send_id)
    print("sha256: %s" % digest)
    return 0


def cmd_sent(args):
    g = Guard(_home(args))
    try:
        g.mark_sent(args.send_id)
    except GuardError as e:
        return _fail(str(e))
    print("send %s logged" % args.send_id)
    return 0


def cmd_receipt(args):
    g = Guard(_home(args))
    try:
        rec = _load_json_file(args.file)
    except Exception as e:
        return _fail("cannot read receipt file: %s" % e)
    try:
        g.receipt(rec)
    except GuardError as e:
        return _fail(str(e))
    print("receipt accepted — staged copy deleted")
    return 0


def cmd_sweep(args):
    g = Guard(_home(args))
    expired = g.sweep()
    print("expired %d staged copies" % len(expired))
    return 0


def cmd_status(args):
    g = Guard(_home(args))
    print(json.dumps(g.status(), indent=2))
    return 0


def cmd_log(args):
    g = Guard(_home(args))
    if not g.log_path.exists():
        print("(no log entries yet)")
        return 0
    lines = g.log_path.read_text().splitlines()
    for line in lines[-args.n:]:
        print(line)
    return 0


def _companion_startup_check(home):
    try:
        from guard import companion
        companion.check_startup(companion.declared_level(home))
    except Exception:
        pass


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="guard.py",
        description="bridge-guard: a guardian for file exchange "
                    "between agents that do not trust each other.")
    p.add_argument("--home", default=None,
                   help="guard home dir (default $BRIDGE_GUARD_HOME or "
                        "~/.bridge-guard)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="create a guard home + policy")
    pi.add_argument("--allow-root", action="append", default=[],
                    help="directory files may be requested from "
                         "(repeatable)")
    pi.add_argument("--auto", action="store_true",
                    help="auto-approve when policy passes (harness mode)")
    pi.add_argument("--max-bytes", type=int, default=None)
    pi.add_argument("--level", type=int, default=None,
                    help="strictness level 0..11, recorded in the "
                         "policy (level 11 prompts the "
                         "trust-but-verify companion install on "
                         "every start while it is missing)")

    pin = sub.add_parser("intake", help="validate a file request")
    pin.add_argument("--file", required=True,
                     help="JSON file holding the request")
    pin.add_argument("--sender", default=None)

    pa = sub.add_parser("approve", help="guardian approves a request")
    pa.add_argument("--id", required=True)
    pa.add_argument("--approver", default=None)
    pa.add_argument("--reason", default="")
    pr = sub.add_parser("reject", help="guardian refuses a request")
    pr.add_argument("--id", required=True)
    pr.add_argument("--approver", default=None)
    pr.add_argument("--reason", default="")

    ps = sub.add_parser("stage", help="copy an approved file to shared")
    ps.add_argument("--id", required=True)
    pm = sub.add_parser("sent", help="log that a staged copy was sent")
    pm.add_argument("--send-id", required=True)
    pc = sub.add_parser("receipt", help="process a received receipt")
    pc.add_argument("--file", required=True,
                    help="JSON file holding the receipt")
    sub.add_parser("sweep", help="delete expired staged copies")
    sub.add_parser("status", help="show guard status")
    pl = sub.add_parser("log", help="show recent log entries")
    pl.add_argument("--n", type=int, default=20)

    args = p.parse_args(argv)
    _companion_startup_check(_home(args))
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "intake":
        return cmd_intake(args)
    if args.cmd == "approve":
        return cmd_decide(args, True)
    if args.cmd == "reject":
        return cmd_decide(args, False)
    if args.cmd == "stage":
        return cmd_stage(args)
    if args.cmd == "sent":
        return cmd_sent(args)
    if args.cmd == "receipt":
        return cmd_receipt(args)
    if args.cmd == "sweep":
        return cmd_sweep(args)
    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "log":
        return cmd_log(args)
    p.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
