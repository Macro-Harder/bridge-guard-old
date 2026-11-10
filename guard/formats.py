import copy
import dataclasses
import hashlib
import hmac
import json
import re

from guard import roles

SUPPORTED_VERSION = 1

_FORMAT1_KIND = "pre-approved-transfer"
_FORMAT2_KIND = "approval-request"

_FORMAT1_KEYS = frozenset({
    "kind", "v", "id", "from", "to", "path", "sha256", "created_at",
})
_FORMAT2_KEYS = frozenset({
    "kind", "v", "id", "from", "to", "path", "reason", "created_at",
})

_FORMAT1_TEMPLATE = {
    "kind": "pre-approved-transfer",
    "v": 1,
    "id": "req-3f9a1c7e5b2d8046a1c3e5f7092b4d68",
    "from": "agent-b",
    "to": "agent-a",
    "path": "notes/plan.md",
    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c"
              "15b0f00a08",
    "created_at": "2026-11-07T18:00:00Z",
}
_FORMAT2_TEMPLATE = {
    "kind": "approval-request",
    "v": 1,
    "id": "req-8b2e04d6f1a947c3b5e60718293a4c5d",
    "from": "agent-b",
    "to": "agent-a",
    "path": "reports/draft.md",
    "reason": "needed for the weekly summary",
    "created_at": "2026-11-07T18:00:00Z",
}

_REQUEST_ID = re.compile(r"req-[0-9a-f]{32,}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_BASE_KEYS = frozenset({"kind", "v", "id", "from", "to"})

_PROTOCOL_KEYS = {
    "receipt": _BASE_KEYS | {"transfer_id", "sha256", "nonce"},
    "receipt-request": _BASE_KEYS | {"transfer_id"},
    "working-on-it": _BASE_KEYS | {"transfer_id"},
    "question": _BASE_KEYS | {"request_id", "text"},
    "answer": _BASE_KEYS | {"request_id", "question_id", "text"},
    "decision": _BASE_KEYS | {"request_id", "decision", "created_at",
                              "reason", "junk_class", "stake"},
    "balance-request": _BASE_KEYS,
    "volume-counts": _BASE_KEYS | {"window", "totals"},
    "receive-refused": _BASE_KEYS | {"transfer_id", "sha256", "nonce",
                                     "scan_result_hash",
                                     "inspectability"},
    "appeal": _BASE_KEYS | {"request_id", "cited_fact",
                            "evidence_hash"},
    "appeal-decision": _BASE_KEYS | {"appeal_id", "outcome"},
    "challenge-response": _BASE_KEYS | {"challenge_id", "nonce",
                                        "proof"},
    "transfer-status-query": _BASE_KEYS | {"transfer_id", "nonce"},
    "succession-confirmation": _BASE_KEYS | {"introduction_id",
                                             "duty_ref",
                                             "decision_event",
                                             "ceremony_ref"},
    "succession-withdrawal": _BASE_KEYS | {"introduction_id"},
    "rotation-introduction": _BASE_KEYS | {"new_key", "extends_epoch",
                                           "current_key_hash"},
    "emergency-introduction": _BASE_KEYS | {"key_type", "new_key",
                                            "extends_epoch",
                                            "current_key_hash",
                                            "countersig"},
    "revocation": _BASE_KEYS | {"pair_id", "revoked_key",
                                "revoked_epoch", "effective_position"},
    "away-notice": _BASE_KEYS | {"window_start", "return_date",
                                 "issued_at", "human_sig"},
    "adjudication-outcome": _BASE_KEYS | {"adjudication_ref", "outcome"},
    "close-out": _BASE_KEYS | {"sever_ref", "record_hash"},
    "trust-proposal": _BASE_KEYS | {"agreement"},
    "trust-acceptance": _BASE_KEYS | {"proposal_id", "agreement_id",
                                      "agreement_hash", "countersig"},
    "format-rejection": frozenset({"kind", "v", "from", "to", "id",
                                   "request_id", "reason", "expected"}),
}

_PROTOCOL_OPTIONAL = {
    "balance": frozenset({"charges"}),
    "succession-introduction": frozenset({"human_cert_ref"}),
}

_PROTOCOL_REQUIRED = {
    "balance": _BASE_KEYS | {"as_of_checkpoint", "balance",
                             "charges_root", "charges_from",
                             "charges_to", "charges_count"},
    "succession-introduction": _BASE_KEYS | {"key_type", "new_key",
                                             "extends_epoch",
                                             "current_key_hash"},
}


@dataclasses.dataclass(frozen=True)
class Verdict:
    outcome: str
    message: object = None
    rejection: object = None


def _drop():
    return Verdict("drop")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_request_id(value):
    return isinstance(value, str) \
        and _REQUEST_ID.fullmatch(value) is not None


def _is_sha256(value):
    return isinstance(value, str) \
        and _SHA256.fullmatch(value) is not None


def sha256_matches(claimed, reference):
    if not isinstance(claimed, str) or not isinstance(reference, str):
        return False
    return hmac.compare_digest(claimed.encode("utf-8"),
                               reference.encode("utf-8"))


def _origin_problem(origin, sender, msg=None, origin_keys=None):
    if not isinstance(origin, dict):
        return "origin must be an object"
    keys = set(origin)
    if not {"id", "epoch"} <= keys:
        return "origin must carry id and epoch"
    if not keys <= {"id", "epoch", "sig"}:
        return "origin carries a key outside id, epoch, sig"
    if not isinstance(origin["id"], str):
        return "origin id must be a string"
    if not _is_int(origin["epoch"]):
        return "origin epoch must be an integer"
    if "sig" in origin and not isinstance(origin["sig"], str):
        return "origin sig must be a string"
    if origin["id"] == sender:
        return None
    if "sig" not in origin:
        return "a relayed origin must carry its own signature"
    # A relayed origin is a claim about a third party, and a claim
    # is only as good as its signature: the origin signs the message
    # with its own origin entry reduced to {id, epoch}, and the gate
    # verifies that signature against the origin's key on record.
    # With no key on record the claim cannot be verified, and an
    # unverifiable origin is rejected, never taken on faith.
    public = (origin_keys or {}).get(origin["id"])
    if public is None:
        return "a relayed origin cannot be verified: no key on " \
               "record for %r" % (origin["id"],)
    body = dict(msg)
    body["origin"] = {"id": origin["id"], "epoch": origin["epoch"]}
    if not roles.verify(public, body, origin["sig"]):
        return "a relayed origin signature does not verify"
    return None


def _format_problem(msg, kind, sender, origin_keys=None):
    if kind == _FORMAT1_KIND:
        required = _FORMAT1_KEYS
        allowed = _FORMAT1_KEYS | {"origin"}
    else:
        required = _FORMAT2_KEYS
        allowed = _FORMAT2_KEYS | {"origin", "supersedes"}
    keys = set(msg)
    extra = keys - allowed
    if extra:
        return "unexpected keys: %s" % (", ".join(sorted(extra)),)
    missing = required - keys
    if missing:
        return "missing keys: %s" % (", ".join(sorted(missing)),)
    if not _is_int(msg["v"]) or msg["v"] != SUPPORTED_VERSION:
        return "unsupported version %r: this side supports version %d" \
            % (msg["v"], SUPPORTED_VERSION)
    if not _is_request_id(msg["id"]):
        return "id must be a req- id carrying at least 128 bits"
    if not isinstance(msg["path"], str):
        return "path must be a string"
    if not isinstance(msg["created_at"], str):
        return "created_at must be a string"
    if kind == _FORMAT1_KIND:
        if not _is_sha256(msg["sha256"]):
            return "sha256 must be a 64-character lowercase hex digest"
    else:
        if not isinstance(msg["reason"], str):
            return "reason must be a string"
        if "supersedes" in msg \
                and not _is_request_id(msg["supersedes"]):
            return "supersedes must name a request id"
    if "origin" in msg:
        return _origin_problem(msg["origin"], sender, msg,
                               origin_keys)
    return None


def _templates(kind):
    if kind == _FORMAT1_KIND:
        return [copy.deepcopy(_FORMAT1_TEMPLATE)]
    if kind == _FORMAT2_KIND:
        return [copy.deepcopy(_FORMAT2_TEMPLATE)]
    return [copy.deepcopy(_FORMAT1_TEMPLATE),
            copy.deepcopy(_FORMAT2_TEMPLATE)]


def _rejection(msg, sender, own_side, kind, reason):
    request_id = msg.get("id")
    if not isinstance(request_id, str):
        request_id = None
    canonical = json.dumps(msg, sort_keys=True, default=repr)
    rejection_id = "rej-" + hashlib.sha256(
        canonical.encode("utf-8")).hexdigest()[:32]
    return Verdict("format-rejection", rejection={
        "kind": "format-rejection",
        "v": SUPPORTED_VERSION,
        "from": own_side,
        "to": sender,
        "id": rejection_id,
        "request_id": request_id,
        "reason": reason,
        "expected": _templates(kind),
    })


def _protocol_ok(msg):
    kind = msg["kind"]
    keys = set(msg)
    if kind == "challenge":
        required = _BASE_KEYS | {"nonce", "challenge_type"}
        if msg.get("challenge_type") == "checkpoint-proof":
            required = required | {"position"}
            forbidden = {"transfer_id"}
        elif msg.get("challenge_type") == "canary":
            required = required | {"transfer_id"}
            forbidden = {"position"}
        else:
            required = required | {"position", "transfer_id"}
            forbidden = set()
        return keys == required and not keys & forbidden
    if kind == "transfer-status":
        required = _BASE_KEYS | {"transfer_id", "nonce", "state"}
        if msg.get("state") == "unknown":
            return keys == required
        return keys == required | {"sha256"}
    if kind in _PROTOCOL_REQUIRED:
        required = _PROTOCOL_REQUIRED[kind]
        optional = _PROTOCOL_OPTIONAL.get(kind, frozenset())
        return required <= keys <= required | optional
    allowed = _PROTOCOL_KEYS.get(kind)
    if allowed is None:
        return False
    return keys == allowed


def validate(envelope, *, verified_from, own_side, origin_keys=None):
    if not isinstance(envelope, dict):
        return _drop()
    if set(envelope) != {"msg", "sig"}:
        return _drop()
    if not isinstance(envelope["sig"], str):
        return _drop()
    if verified_from is None:
        return _drop()
    msg = envelope["msg"]
    if not isinstance(msg, dict):
        return _drop()
    if "from" in msg and msg["from"] != verified_from:
        return _drop()
    if "to" in msg and msg["to"] != own_side:
        return _drop()
    kind = msg.get("kind")
    if kind in _PROTOCOL_KEYS or kind in _PROTOCOL_REQUIRED \
            or kind in ("challenge", "transfer-status"):
        if _is_int(msg.get("v")) and msg["v"] == SUPPORTED_VERSION \
                and _protocol_ok(msg):
            return Verdict("protocol", message=msg)
    if kind in (_FORMAT1_KIND, _FORMAT2_KIND) or "path" in msg:
        declared = kind if kind in (_FORMAT1_KIND, _FORMAT2_KIND) \
            else None
        if declared is not None:
            problem = _format_problem(msg, declared, verified_from,
                                      origin_keys)
            if problem is None:
                return Verdict(declared, message=msg)
            return _rejection(msg, verified_from, own_side, declared,
                              problem)
        return _rejection(msg, verified_from, own_side, None,
                          "request did not match a known format")
    return _drop()
