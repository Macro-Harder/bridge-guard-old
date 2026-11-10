import copy
import secrets


class ProposalError(Exception):
    pass


SUPPORTED_VERSION = 1

_TOOL_KEYS = ("kind", "v", "id", "from", "to", "name", "arguments",
              "reason", "created_at")
_SKILL_KEYS = ("kind", "v", "id", "from", "to", "name", "sha256",
               "reason", "created_at")
_KEY_SETS = {"tool-proposal": _TOOL_KEYS, "skill-proposal": _SKILL_KEYS}
_HEX_DIGITS = frozenset("0123456789abcdef")


def _is_sha256(value):
    return isinstance(value, str) and len(value) == 64 \
        and all(char in _HEX_DIGITS for char in value)


def validate_proposal(message):
    if not isinstance(message, dict):
        raise ProposalError(
            "a proposal is a form: a mapping of named fields, "
            "never free text")
    kind = message.get("kind")
    if not isinstance(kind, str) or kind not in _KEY_SETS:
        raise ProposalError("unknown proposal kind %r" % (kind,))
    keys = _KEY_SETS[kind]
    if set(message) != set(keys):
        missing = [key for key in keys if key not in message]
        extra = [key for key in message if key not in keys]
        raise ProposalError(
            "a %s carries exactly the fields on its form "
            "(missing: %s; extra: %s)" % (kind, missing, extra))
    if isinstance(message["v"], bool) \
            or not isinstance(message["v"], int) \
            or message["v"] != SUPPORTED_VERSION:
        raise ProposalError(
            "unsupported proposal version %r; this desk reads "
            "version %d" % (message["v"], SUPPORTED_VERSION))
    if kind == "tool-proposal":
        if not isinstance(message["arguments"], dict):
            raise ProposalError(
                "a tool proposal's arguments are an object of "
                "named values; the reason is a fact, never an "
                "instruction")
    elif not _is_sha256(message["sha256"]):
        raise ProposalError(
            "a skill proposal binds itself to the exact file "
            "that crossed by its SHA-256 hash")
    return {key: copy.deepcopy(message[key]) for key in keys}


class ProposalDesk:
    def __init__(self, forms_on_file=()):
        self._forms = set(forms_on_file)
        self._records = {}
        self._proposals = {}

    def receive(self, message, sender=None):
        proposal = validate_proposal(message)
        proposal_id = proposal["id"]
        if proposal_id in self._records:
            raise ProposalError(
                "duplicate proposal id %r" % (proposal_id,))
        if sender is not None and sender != proposal["from"]:
            raise ProposalError(
                "the envelope's verified sender is not the "
                "proposal's author")
        if proposal["name"] not in self._forms:
            raise ProposalError(
                "no form on file for %r; without a form the "
                "proposal cannot proceed" % (proposal["name"],))
        record = {
            "id": proposal_id,
            "case_id": "case-" + secrets.token_hex(16),
            "kind": proposal["kind"],
            "name": proposal["name"],
            "from": proposal["from"],
            "to": proposal["to"],
            "status": "case-open",
            "reason": "",
            "executed": False,
        }
        self._records[proposal_id] = record
        self._proposals[proposal_id] = proposal
        return dict(record)

    def open_cases(self):
        return [record["case_id"]
                for record in self._records.values()
                if record["status"] == "case-open"]

    def _require_record(self, proposal_id):
        record = self._records.get(proposal_id)
        if record is None:
            raise ProposalError(
                "no proposal %r on this desk" % (proposal_id,))
        return record

    def decide(self, proposal_id, outcome, reason=""):
        record = self._require_record(proposal_id)
        if record["status"] != "case-open":
            raise ProposalError(
                "proposal %s is already decided" % (proposal_id,))
        if outcome not in ("accepted", "refused"):
            raise ProposalError(
                "unknown proposal outcome %r" % (outcome,))
        if outcome == "refused" and not reason:
            raise ProposalError(
                "a refusal is a first-class outcome and is "
                "recorded with its reason")
        record["status"] = outcome
        record["reason"] = reason
        return dict(record)

    def outcome(self, proposal_id):
        return dict(self._require_record(proposal_id))
