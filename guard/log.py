import copy
import dataclasses
import datetime
import hashlib
import hmac
import json
import os
import secrets

GENESIS_PREV_HASH = "0" * 64


class LogError(Exception):
    pass


class SchemaError(LogError):
    pass


class SignerError(LogError):
    pass


class SignatureError(LogError):
    pass


class ChainError(LogError):
    pass


class WriterError(LogError):
    pass


@dataclasses.dataclass(frozen=True)
class Key:
    material: bytes

    @property
    def public_key(self):
        return self.material


def generate_key():
    return Key(secrets.token_bytes(32))


def _canonical(event):
    return json.dumps(event, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _material(key):
    if isinstance(key, Key):
        return key.material
    return key


def sign_event(key, event):
    return hmac.new(_material(key), _canonical(event),
                    hashlib.sha256).digest()


def _verify_signature(public_key, event, signature):
    if not isinstance(signature, (bytes, bytearray)):
        return False
    expected = hmac.new(public_key, _canonical(event),
                        hashlib.sha256).digest()
    return hmac.compare_digest(expected, bytes(signature))


@dataclasses.dataclass
class LogEvent:
    id: str
    ts: str
    type: str
    signer: str
    fields: dict
    prev_hash: str
    hash: str
    position: int
    signature: bytes
    second_signature: object = None


@dataclasses.dataclass(frozen=True)
class Receipt:
    event_id: str
    chain_position: int
    chain_head: str
    signature: bytes


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(
        ch in "0123456789abcdefABCDEF" for ch in value)


def _is_id(value):
    return isinstance(value, str) and len(value) > 0


def _check_kind(kind, value):
    if kind == "any":
        return True
    if kind == "str":
        return isinstance(value, str)
    if kind == "int":
        return _is_int(value)
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "hash":
        return _is_hash(value)
    if kind == "id":
        return _is_id(value)
    if kind == "id?":
        return value is None or _is_id(value)
    if kind == "record":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if isinstance(kind, tuple) and kind[0] == "enum":
        if isinstance(kind[1][0], int):
            return _is_int(value) and value in kind[1]
        return value in kind[1]
    if isinstance(kind, tuple) and kind[0] == "array":
        return isinstance(value, list) and all(
            _check_kind(kind[1], item) for item in value)
    raise AssertionError("unknown field kind: %r" % (kind,))


_CLEAN_FINDINGS = ("clean", "findings", "uninspectable")
_INSPECTABILITY = ("inspectable", "uninspectable")


def _check_request(fields):
    if fields["format"] == 1 and "sha256" not in fields:
        raise SchemaError("request: sha256 is required for format 1")


def _check_approve(fields):
    if fields["basis"] == "case":
        if "case_ref" not in fields:
            raise SchemaError(
                "approve: case_ref is required when basis is case")
    elif fields["basis"] in ("list", "token", "precedent", "agreement"):
        if "case_ref" in fields:
            raise SchemaError(
                "approve: case_ref is absent when basis is %s"
                % (fields["basis"],))


def _check_scan(fields):
    if fields.get("pattern_result") == "findings" \
            or fields.get("agent_verdict") == "findings":
        if "finding_class" not in fields:
            raise SchemaError(
                "scan: finding_class is required when a verdict "
                "is findings")


def _check_deleted(fields):
    refs = [name for name in ("receipt_ref", "disposition_ref")
            if name in fields]
    if len(refs) != 1:
        raise SchemaError(
            "deleted: exactly one of receipt_ref and disposition_ref "
            "is required")


def _check_kill_switch(fields):
    if "signal_refs" in fields and len(fields["signal_refs"]) != 2:
        raise SchemaError(
            "kill-switch: signal_refs must hold exactly 2 ids")
    if fields["trip_kind"] == "agent-raised" \
            and "signal_refs" not in fields:
        raise SchemaError(
            "kill-switch: signal_refs is required when trip_kind "
            "is agent-raised")


def _check_escrow(fields):
    if fields["transition"] == "burned" and "junk_class" not in fields:
        raise SchemaError(
            "escrow: junk_class is required when transition is burned")


def _check_clock(fields):
    if fields["verdict"] == "human-cleared" \
            and "disposition_ref" not in fields:
        raise SchemaError(
            "clock: disposition_ref is required when verdict "
            "is human-cleared")


def _check_challenge(fields):
    if fields["challenge_type"] == "canary":
        if "transfer_id" not in fields:
            raise SchemaError(
                "challenge: transfer_id is required when "
                "challenge_type is canary")
    elif "transfer_id" in fields:
        raise SchemaError(
            "challenge: transfer_id is forbidden unless "
            "challenge_type is canary")
    if fields["outcome"] == "answered" and "ref" not in fields:
        raise SchemaError(
            "challenge: ref is required when outcome is answered")
    if fields["challenge_type"] == "checkpoint-proof":
        if "position" not in fields:
            raise SchemaError(
                "challenge: position is required when challenge_type "
                "is checkpoint-proof")
    elif "position" in fields:
        raise SchemaError(
            "challenge: position is forbidden unless challenge_type "
            "is checkpoint-proof")


def _check_close_out(fields):
    if "sever_ref" in fields:
        for name in ("trip_ref", "dispositions"):
            if name in fields:
                raise SchemaError(
                    "close-out: %s is forbidden when sever_ref "
                    "is present" % (name,))
    else:
        for name in ("trip_ref", "dispositions"):
            if name not in fields:
                raise SchemaError(
                    "close-out: %s is required when sever_ref "
                    "is absent" % (name,))


def _check_volume(fields):
    totals = fields["totals"]
    names = ("requests", "bytes", "distinct_paths", "refusals",
             "burns", "late_receipts")
    if set(totals) != set(names) or not all(
            _is_int(totals[name]) for name in names):
        raise SchemaError(
            "volume: totals must be a record of the six named "
            "int fields")


_SCHEMAS = {
    "request": {
        "signers": ("communicator",),
        "required": {"request_id": "id", "counterpart": "str",
                     "format": ("enum", (1, 2)), "path": "str",
                     "size": "int"},
        "optional": {"sha256": "hash", "reason": "str"},
        "check": _check_request,
    },
    "auto-reject": {
        "signers": ("gate",),
        "required": {"request_ref": "id?",
                     "reason": ("enum", ("shape", "kind-mismatch"))},
        "optional": {},
    },
    "format-reject": {
        "signers": ("gate",),
        "required": {"request_ref": "id", "expected": "array"},
        "optional": {},
    },
    "case": {
        "signers": ("investigator",),
        "required": {"case_id": "id", "request_ref": "id",
                     "file_hash": "hash", "size": "int",
                     "case_hash": "hash"},
        "optional": {"signals": ("array", "str")},
    },
    "approve": {
        "signers": ("manager",),
        "required": {"basis": ("enum", ("case", "list", "token",
                                        "precedent", "agreement",
                                        "override")),
                     "artifact_hash": "hash", "size": "int"},
        "optional": {"case_ref": "id",
                     "decided_by": ("enum", ("policy", "manager"))},
        "check": _check_approve,
    },
    "reject": {
        "signers": ("manager",),
        "required": {"case_ref": "id", "artifact_hash": "hash"},
        "optional": {"junk_class": "str"},
    },
    "policy-refusal": {
        "signers": ("gate",),
        "required": {"counterpart": "str", "path": "str",
                     "refusal_class": ("enum", ("fast-path", "dedup",
                                                "breaker"))},
        "optional": {"request_ref": "id"},
    },
    "staged": {
        "signers": ("manager",),
        "required": {"transfer_id": "id", "file_hash": "hash",
                     "size": "int", "staged_name": "str"},
        "optional": {},
    },
    "transfer-ready": {
        "signers": ("manager",),
        "required": {"transfer_id": "id", "artifact_hash": "hash"},
        "optional": {},
    },
    "gate-pass": {
        "signers": ("verifier",),
        "required": {"pass_id": "id", "transfer_id": "id",
                     "staged_hash": "hash", "expires": "int",
                     "state": ("enum", ("issued", "spent", "voided"))},
        "optional": {},
    },
    "moved": {
        "signers": ("transfer-agent",),
        "required": {"transfer_id": "id", "pass_hash": "hash",
                     "folder2_hash": "hash"},
        "optional": {},
    },
    "sent": {
        "signers": ("sender",),
        "required": {"transfer_id": "id", "nonce": "str",
                     "envelope_hash": "hash", "size": "int"},
        "optional": {},
    },
    "received": {
        "signers": ("verifier",),
        "required": {"transfer_id": "id", "message_id": "id",
                     "nonce": "str", "sha256": "hash",
                     "attestation_ref": "id", "size": "int"},
        "optional": {},
    },
    "scan": {
        "signers": ("scanner-runner",),
        "required": {"file_hash": "hash",
                     "pattern_result": ("enum", _CLEAN_FINDINGS),
                     "pattern_result_hash": "hash",
                     "agent_verdict": ("enum", _CLEAN_FINDINGS),
                     "inspectability": ("enum", _INSPECTABILITY)},
        "optional": {"finding_class": "str"},
        "check": _check_scan,
    },
    "received-scan": {
        "signers": ("scanner-runner",),
        "required": {"file_hash": "hash",
                     "pattern_result": ("enum", _CLEAN_FINDINGS),
                     "pattern_result_hash": "hash",
                     "inspectability": ("enum", _INSPECTABILITY),
                     "transfer_id": "id"},
        "optional": {"agent_verdict": ("enum", _CLEAN_FINDINGS),
                     "finding_class": "str"},
        "check": _check_scan,
    },
    "scan-record": {
        "signers": ("scanner-runner",),
        "required": {"transfer_id": "id",
                     "path": ("enum", ("fast", "local", "agreement",
                                       "precedent")),
                     "pattern_result": ("enum", _CLEAN_FINDINGS),
                     "inspectability": ("enum", _INSPECTABILITY)},
        "optional": {"finding_class": "str"},
    },
    "deleted": {
        "signers": ("transfer-agent", "manager"),
        "required": {"transfer_id": "id", "size": "int"},
        "optional": {"receipt_ref": "id", "disposition_ref": "id",
                     "instruction_ref": "id"},
        "check": _check_deleted,
    },
    "alert": {
        "signers": ("gate", "manager", "investigator", "boss",
                    "ledger-function", "verifier"),
        "required": {"class": ("enum", ("instant", "digest")),
                     "subject_refs": ("array", "id"),
                     "evidence_hash": "hash"},
        "optional": {"counterpart": "str", "decision_requested": "str",
                     "deadline": "int", "size": "int"},
    },
    "alert-ack": {
        "signers": ("signing-tool",),
        "required": {"alert_ref": "id"},
        "optional": {},
    },
    "quarantine": {
        "signers": ("transfer-agent", "manager"),
        "required": {"file_hash": "hash", "from_state": "str",
                     "reason": "str"},
        "optional": {"transfer_id": "id"},
    },
    "kill-switch": {
        "signers": ("verifier", "transfer-agent", "spoiler-checker",
                    "signing-tool", "boss"),
        "required": {"reason": "str",
                     "evidence_refs": ("array", "id"),
                     "trip_kind": ("enum", ("code-verified",
                                             "agent-raised"))},
        "optional": {"signal_refs": ("array", "id"),
                     "staged_hash": "hash", "checker_version": "str"},
        "check": _check_kill_switch,
    },
    "enrollment": {
        "signers": ("signing-tool",),
        "required": {"counterpart": "str", "pinning_hash": "hash",
                     "terms_hash": "hash"},
        "optional": {},
    },
    "rotation": {
        "signers": ("communicator",),
        "required": {"counterpart": "str", "epoch": "int",
                     "new_key_hash": "hash", "pair_hash": "hash"},
        "optional": {},
    },
    "revocation": {
        "signers": ("signing-tool", "communicator"),
        "required": {"subject": "str", "reason": "str"},
        "optional": {"epoch": "int"},
    },
    "trust-on": {
        "signers": ("signing-tool",),
        "required": {"counterpart": "str", "agreement_id": "id",
                     "expires": "int"},
        "optional": {},
    },
    "trust-off": {
        "signers": ("signing-tool", "manager"),
        "required": {"counterpart": "str", "agreement_id": "id",
                     "reason": "str"},
        "optional": {},
    },
    "toggle": {
        "signers": ("signing-tool",),
        "required": {"counterpart": "str", "scope": "str",
                     "field": "str", "old": "any", "new": "any"},
        "optional": {},
    },
    "terms-amendment": {
        "signers": ("signing-tool",),
        "required": {"counterpart": "str", "terms_version": "int",
                     "allocation_version": "int",
                     "terms_hash": "hash", "allocation_hash": "hash"},
        "optional": {},
    },
    "suspension": {
        "signers": ("manager", "boss", "ledger-function", "gate"),
        "required": {"counterpart": "str",
                     "action": ("enum", ("apply", "lift")),
                     "reason": "str", "actor": "str"},
        "optional": {},
    },
    "hold": {
        "signers": ("verifier",),
        "required": {"counterpart": "str",
                     "state": ("enum", ("applied", "lifted")),
                     "cause": ("enum", ("missed-checkpoint",
                                        "non-extending-head"))},
        "optional": {},
    },
    "component-halt": {
        "signers": ("verifier", "log-service", "boss"),
        "required": {"component": "str",
                     "action": ("enum", ("apply", "lift")),
                     "cause": "str"},
        "optional": {},
    },
    "charge": {
        "signers": ("ledger-function",),
        "required": {"counterpart": "str", "amount": "int",
                     "class": "str", "ref": "id"},
        "optional": {"credit_flag": "bool"},
    },
    "escrow": {
        "signers": ("ledger-function",),
        "required": {"request_id": "id",
                     "transition": ("enum", ("escrowed", "refunded",
                                             "burned", "contested")),
                     "amount": "int"},
        "optional": {"junk_class": "str"},
        "check": _check_escrow,
    },
    "incident": {
        "signers": ("gate", "log-service", "verifier", "scanner-runner",
                    "ledger-function", "boss", "signing-tool"),
        "required": {"incident_id": "id",
                     "action": ("enum", ("open", "close")),
                     "counterpart": "str"},
        "optional": {"failure_signature": "str"},
    },
    "clock": {
        "signers": ("verifier",),
        "required": {"skew_ms": "int",
                     "verdict": ("enum", ("within", "beyond",
                                          "corroborated",
                                          "human-cleared"))},
        "optional": {"counterpart": "str", "disposition_ref": "id"},
        "check": _check_clock,
    },
    "tombstone": {
        "signers": ("log-service",),
        "required": {"entry_ref": "id", "reason": "str"},
        "optional": {},
    },
    "holdback": {
        "signers": ("verifier",),
        "required": {"scan_ref": "id", "team_ref": "str"},
        "optional": {},
    },
    "repair": {
        "signers": ("log-service",),
        "required": {"checkpoint_ref": "hash",
                     "cause": ("enum", ("tear", "divergence", "restore",
                                        "lost-count"))},
        "optional": {"counterpart": "str"},
    },
    "close-out": {
        "signers": ("signing-tool",),
        "required": {},
        "optional": {"trip_ref": "id",
                     "dispositions": ("array", "str"),
                     "sever_ref": "id"},
        "check": _check_close_out,
    },
    "spoiler-advancement": {
        "signers": ("spoiler-checker",),
        "required": {"presented_version": "int", "list_hash": "hash",
                     "version_record_ref": "id",
                     "escrow_act_ref": "id"},
        "optional": {},
    },
    "severance-interim": {
        "signers": ("verifier",),
        "required": {"counterpart": "str", "pendency_ref": "id",
                     "duty_ref": "id"},
        "optional": {},
    },
    "retired": {
        "signers": ("signing-tool",),
        "required": {"counterpart": "str", "reason": "str"},
        "optional": {},
    },
    "checkpoint": {
        "signers": ("log-service",),
        "required": {"checkpoint_hash": "hash", "set_root": "hash",
                     "entry_count": "int"},
        "optional": {"counterpart": "str", "hold_state": "record"},
    },
    "duty": {
        "signers": ("duty-queue", "verifier"),
        "required": {"duty_id": "id", "duty_type": "str",
                     "deadline": "int", "default": "str"},
        "optional": {"counterpart": "str",
                     "outcome": ("enum", ("done", "defaulted",
                                          "expired"))},
    },
    "challenge": {
        "signers": ("communicator",),
        "required": {"counterpart": "str",
                     "challenge_type": ("enum", ("checkpoint-proof",
                                                 "manifest-reattestation",
                                                 "canary")),
                     "outcome": ("enum", ("issued", "answered",
                                          "unanswered", "failed")),
                     "challenge_ref": "id"},
        "optional": {"transfer_id": "id", "ref": "id",
                     "position": "int"},
        "check": _check_challenge,
    },
    "canary": {
        "signers": ("communicator",),
        "required": {"counterpart": "str",
                     "outcome": ("enum", ("completed", "failed")),
                     "ref": "id"},
        "optional": {},
    },
    "resync": {
        "signers": ("verifier",),
        "required": {"common_checkpoint": "hash",
                     "outcome": ("enum", ("clean", "diverged",
                                          "floor"))},
        "optional": {"counterpart": "str"},
    },
    "away-notice-received": {
        "signers": ("log-service",),
        "required": {"notice_ref": "id", "arrival_position": "int"},
        "optional": {},
    },
    "manifest-received": {
        "signers": ("gate",),
        "required": {"counterpart": "str", "manifest_version": "int",
                     "manifest_hash": "hash",
                     "governing_value_outcome": "record",
                     "outcome": ("enum", ("accepted", "stale-version",
                                          "fork"))},
        "optional": {},
    },
    "adjudicate": {
        "signers": ("signing-tool",),
        "required": {"divergence_ref": "id", "decision": "str"},
        "optional": {},
    },
    "restore": {
        "signers": ("log-service",),
        "required": {"backup_ref": "str",
                     "gate_result": ("enum", ("accepted", "refused")),
                     "verified_to": "hash"},
        "optional": {},
    },
    "volume": {
        "signers": ("scanner-runner",),
        "required": {"counterpart": "str", "window": "str",
                     "totals": "record"},
        "optional": {"crossed_quantity": ("enum", ("requests", "bytes",
                                                   "distinct_paths",
                                                   "refusals",
                                                   "burns")),
                     "spool_gap": "record"},
        "check": _check_volume,
    },
}


def _authorized_signers(event):
    spec = _SCHEMAS[event["type"]]
    if event["type"] == "kill-switch":
        trip_kind = event.get("trip_kind")
        if trip_kind == "agent-raised":
            return ("boss",)
        if trip_kind == "code-verified":
            return ("verifier", "transfer-agent", "spoiler-checker",
                    "signing-tool")
    return spec["signers"]


def _second_signer(event):
    event_type = event["type"]
    if event_type == "scan":
        return "scanner", True
    if event_type == "received-scan":
        return "scanner", "agent_verdict" in event
    if event_type in ("checkpoint", "repair", "restore", "tombstone"):
        return "verifier", True
    if event_type in ("toggle", "terms-amendment"):
        return "signing-tool", False
    if event_type == "close-out":
        return "signing-tool", "sever_ref" in event
    return None, False


def _validate_schema(event):
    spec = _SCHEMAS[event["type"]]
    if not _is_id(event.get("id")):
        raise SchemaError("%s: id must be a non-empty string"
                          % (event["type"],))
    fields = {name: value for name, value in event.items()
              if name not in ("id", "type")}
    allowed = dict(spec["required"])
    allowed.update(spec["optional"])
    for name in fields:
        if name not in allowed:
            raise SchemaError("%s: field %r is not in the schema"
                              % (event["type"], name))
    for name in spec["required"]:
        if name not in fields:
            raise SchemaError("%s: required field %r is missing"
                              % (event["type"], name))
    for name, value in fields.items():
        if not _check_kind(allowed[name], value):
            raise SchemaError("%s: field %r has the wrong type"
                              % (event["type"], name))
    check = spec.get("check")
    if check is not None:
        check(fields)
    return fields


def _check_signatures(event, signer, signature, second_signature,
                      public_keys):
    if not _verify_signature(public_keys[signer], event, signature):
        raise SignatureError("%s: signature does not verify for %s"
                             % (event["type"], signer))
    second_role, second_required = _second_signer(event)
    if second_role is None:
        if second_signature is not None:
            raise SignatureError(
                "%s: this event type carries no second signature"
                % (event["type"],))
        return
    if second_signature is None:
        if second_required:
            raise SignatureError(
                "%s: a second signature from %s is required"
                % (event["type"], second_role))
        return
    if event["type"] == "received-scan" \
            and "agent_verdict" not in event:
        raise SchemaError(
            "received-scan: agent_verdict is required when a "
            "second signature is carried")
    if second_role not in public_keys or not _verify_signature(
            public_keys[second_role], event, second_signature):
        raise SignatureError(
            "%s: second signature does not verify for %s"
            % (event["type"], second_role))


def _record_hash(record):
    body = {name: value for name, value in record.items()
            if name != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


_OPEN_LOGS = set()


class LogService:
    def __init__(self, path, public_keys):
        self._path = os.fspath(path)
        self._key = os.path.abspath(self._path)
        if self._key in _OPEN_LOGS:
            raise WriterError("log is already open for writing: %s"
                              % (self._path,))
        self._public_keys = dict(public_keys)
        self._closed = False
        self._head = GENESIS_PREV_HASH
        self._count = 0
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        raise ChainError(
                            "existing log %s has an unreadable entry"
                            % (self._path,)) from None
                    self._head = record["hash"]
                    self._count += 1
        _OPEN_LOGS.add(self._key)

    def submit(self, event, signer, signature, second_signature=None):
        if self._closed:
            raise WriterError("log service is closed")
        if not isinstance(event, dict) \
                or event.get("type") not in _SCHEMAS:
            raise SchemaError("unknown event type: %r"
                              % (event.get("type")
                                 if isinstance(event, dict) else event,))
        if signer not in self._public_keys \
                or signer not in _authorized_signers(event):
            raise SignerError("%s may not sign %s"
                              % (signer, event["type"]))
        fields = _validate_schema(event)
        _check_signatures(event, signer, signature, second_signature,
                          self._public_keys)
        record = {
            "id": event["id"],
            "ts": _now(),
            "type": event["type"],
            "signer": signer,
            "fields": copy.deepcopy(fields),
            "prev_hash": self._head,
            "position": self._count,
            "signature": bytes(signature).hex(),
            "second_signature": bytes(second_signature).hex()
            if second_signature is not None else None,
        }
        record["hash"] = _record_hash(record)
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
        self._head = record["hash"]
        self._count += 1
        return Receipt(event_id=record["id"],
                       chain_position=record["position"],
                       chain_head=record["hash"],
                       signature=bytes(signature))

    def close(self):
        if not self._closed:
            self._closed = True
            _OPEN_LOGS.discard(self._key)


def verify_log(path, public_keys):
    path = os.fspath(path)
    if not os.path.exists(path):
        return []
    events = []
    prev_hash = GENESIS_PREV_HASH
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    for position, line in enumerate(lines):
        if not line.strip():
            raise ChainError("entry %d is blank" % (position,))
        try:
            record = json.loads(line)
        except ValueError:
            raise ChainError("entry %d is not readable"
                             % (position,)) from None
        if record.get("position") != position:
            raise ChainError("entry %d is out of order" % (position,))
        if record.get("prev_hash") != prev_hash:
            raise ChainError("entry %d does not chain to the "
                             "previous hash" % (position,))
        if record.get("hash") != _record_hash(record):
            raise ChainError("entry %d has a broken hash"
                             % (position,))
        signer = record.get("signer")
        event = {"id": record.get("id"), "type": record.get("type")}
        event.update(record.get("fields") or {})
        if signer not in public_keys \
                or event["type"] not in _SCHEMAS \
                or signer not in _authorized_signers(event):
            raise SignerError("entry %d: %s may not sign %s"
                              % (position, signer, event["type"]))
        signature = bytes.fromhex(record["signature"])
        second = bytes.fromhex(record["second_signature"]) \
            if record.get("second_signature") else None
        _check_signatures(event, signer, signature, second, public_keys)
        events.append(LogEvent(
            id=record["id"], ts=record["ts"], type=record["type"],
            signer=signer, fields=record["fields"],
            prev_hash=record["prev_hash"], hash=record["hash"],
            position=record["position"], signature=signature,
            second_signature=second))
        prev_hash = record["hash"]
    return events
