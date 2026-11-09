import copy
import dataclasses
import secrets
from datetime import datetime, timedelta, timezone


class CaseError(Exception):
    pass


def _parse_time(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclasses.dataclass
class Question:
    id: str
    request_id: str
    text: str
    answer: object = None
    answered_by: object = None


@dataclasses.dataclass
class Case:
    request_id: str
    sender: str
    path: str
    reason: str
    created_at: object = None
    outcome: object = None
    decision_reason: str = ""
    refused_by_default: bool = False
    transfer_id: object = None
    case_for: object = None
    case_against: object = None
    evidence: object = None
    questions: list = dataclasses.field(default_factory=list)
    deadline: object = dataclasses.field(default=None, repr=False)


@dataclasses.dataclass
class LocalSend:
    id: str
    path: str
    sha256: str
    case_id: object = None
    steps: list = dataclasses.field(default_factory=list)
    token_id: object = None


class CaseFlow:
    def __init__(self, question_round_cap=3, case_deadline_s=259200):
        self.question_round_cap = question_round_cap
        self.case_deadline_s = case_deadline_s
        self._cases = {}
        self._questions = {}
        self._spent_token_ids = set()

    def receive(self, message):
        if not isinstance(message, dict):
            return None
        if message.get("kind") != "approval-request":
            return None
        request_id = message.get("id")
        if request_id in self._cases:
            return self._cases[request_id]
        created_at = message.get("created_at")
        deadline = None
        opened = _parse_time(created_at)
        if opened is not None and self.case_deadline_s is not None:
            deadline = opened + timedelta(seconds=self.case_deadline_s)
        case = Case(
            request_id=request_id,
            sender=message.get("from"),
            path=message.get("path"),
            reason=message.get("reason"),
            created_at=created_at,
            deadline=deadline,
        )
        self._cases[request_id] = case
        return case

    def case_for(self, request_id):
        return self._cases.get(request_id)

    def _require_case(self, request_id):
        case = self._cases.get(request_id)
        if case is None:
            raise CaseError("no case for request %r" % (request_id,))
        return case

    def investigate(self, request_id, evidence):
        case = self._require_case(request_id)
        if not isinstance(evidence, dict) \
                or "case_for" not in evidence \
                or "case_against" not in evidence:
            raise CaseError(
                "a case needs both a case for and a case against")
        case.evidence = copy.deepcopy(evidence)
        case.case_for = evidence["case_for"]
        case.case_against = evidence["case_against"]
        return case

    def ask(self, request_id, text):
        case = self._require_case(request_id)
        if case.outcome is not None:
            raise CaseError(
                "case %s is already closed" % (request_id,))
        if len(case.questions) >= self.question_round_cap:
            case.outcome = "refused"
            case.refused_by_default = True
            raise CaseError(
                "case %s is out of question rounds; refused by "
                "default" % (request_id,))
        question = Question(
            id="q-" + secrets.token_hex(16),
            request_id=request_id,
            text=text,
        )
        case.questions.append(question)
        self._questions[question.id] = question
        return question

    def answer(self, question_id, text, sender=None):
        question = self._questions.get(question_id)
        if question is None:
            raise CaseError("no outstanding question %r"
                            % (question_id,))
        case = self._require_case(question.request_id)
        if question.answer is not None:
            raise CaseError(
                "question %s is already answered" % (question_id,))
        if case.outcome is not None:
            raise CaseError(
                "case %s is already closed" % (case.request_id,))
        if sender != case.sender:
            raise CaseError(
                "answers are accepted only from the request's "
                "sender")
        question.answer = text
        question.answered_by = sender
        return question

    def decide(self, request_id, outcome, reason=""):
        case = self._require_case(request_id)
        if outcome not in ("approved", "refused"):
            raise CaseError("unknown decision outcome %r"
                            % (outcome,))
        if case.outcome is not None:
            raise CaseError(
                "case %s is already decided" % (request_id,))
        case.outcome = outcome
        case.decision_reason = reason
        case.refused_by_default = False
        if outcome == "approved":
            case.transfer_id = "transfer-" + secrets.token_hex(16)
        return case

    def expire_cases(self, now):
        moment = _parse_time(now)
        if moment is None:
            raise CaseError("cannot parse the expiry time")
        closed = []
        for case in self._cases.values():
            if case.outcome is not None:
                continue
            if case.deadline is not None and moment > case.deadline:
                case.outcome = "unjudged"
                case.decision_reason = ""
                closed.append(case)
        return closed

    def initiate_local_send(self, path=None, sha256=None, token=None):
        if token is None:
            raise CaseError(
                "a locally initiated send needs its human-signed "
                "initiation token")
        if not isinstance(token, dict) \
                or token.get("path") != path \
                or token.get("sha256") != sha256:
            raise CaseError(
                "the initiation token is bound to another path or "
                "hash")
        token_id = token.get("nonce")
        if token_id is not None:
            if token_id in self._spent_token_ids:
                raise CaseError(
                    "the initiation token has already been spent")
            self._spent_token_ids.add(token_id)
        return LocalSend(
            id="local-" + secrets.token_hex(16),
            path=path,
            sha256=sha256,
            case_id=None,
            steps=["folder-1", "transfer-agent", "log"],
            token_id=token_id,
        )
