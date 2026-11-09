import dataclasses

from guard.companion import COMPANION_NAME, companion_offer_for_level
from guard.manifest import DESIGN_REVISION

FORMAT_VERSION = 1
DEFAULT_LEVEL = 5
LEVEL_MIN = 0
LEVEL_MAX = 11


class PacketError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class Question:
    id: str
    prompt: str
    options: tuple
    default: str


@dataclasses.dataclass(frozen=True)
class LevelEntry:
    level: int
    human_text: str
    agent_text: str


_QUESTIONS = (
    Question(
        "role_staffing",
        "Who plays manager and investigator on this side: a dedicated "
        "agent instance per role, or one agent switching hats? (The "
        "roles stay separate even if one agent fills both.)",
        ("dedicated-per-role", "one-agent-switching"),
        "dedicated-per-role",
    ),
    Question(
        "boss_form",
        "Is the boss the main agent (the communicator) in its emergency "
        "role, or a separate agent?",
        ("main-agent", "separate-agent"),
        "main-agent",
    ),
    Question(
        "scanner_provider",
        "The scanner is a dedicated agent of its own. Who provides it: "
        "the one bundled with the guard, or one the operator provides?",
        ("bundled", "operator-provided"),
        "bundled",
    ),
    Question(
        "kill_switch_channel",
        "Which physical channel carries the kill-switch alert to the "
        "human?",
        ("os-notification", "email", "sms"),
        "os-notification",
    ),
    Question(
        "transfer_ready_authorship",
        "Who may write \"transfer ready\": the manager only, or may the "
        "boss also send one in an emergency? (A move still needs the "
        "verifier's gate-pass either way.)",
        ("manager-only", "manager-or-boss-emergency"),
        "manager-only",
    ),
)

def _spectrum_agent_text(level):
    return (
        "Level %d: strictness position %d of 11 on the spectrum. The "
        "connection and the transfer run at one shared level, the "
        "stricter of the two sides' picks, agreed in the section 8.1 "
        "handshake; preset values resolve through "
        "guard.levels.preset_for(%d). absolute_trust_enabled is never "
        "a preset default at any level (section 10), and logging is on "
        "at every level: only an advanced-settings override turns it "
        "off." % (level, level, level))


_LEVEL_PICKER = (
    LevelEntry(
        0,
        "Level 0: no security at all. Every check is off and only the "
        "log keeps running. For your own internal system only, where "
        "both sides are already yours.",
        "Level 0: install-time exception, set locally only and never "
        "by remote request. The preset resolves every toggle off "
        "except logging_enabled, which stays on, and leaves the "
        "numeric variables unset; at this level the section 8.4 "
        "transfer-agent check and the section 15 spoiler check are "
        "off as well.",
    ),
    LevelEntry(
        1,
        "Level 1: the lightest real guard. The log, the two folders, "
        "and the basic transfer checks are on, at their standard "
        "settings.",
        "Level 1: lowest non-zero strictness. Preset: logging, "
        "manager review, scanner, fast path and precedent path on; "
        "cost ledger and absolute trust off; size and rate variables "
        "at shipped defaults; no added components.",
    ),
    LevelEntry(
        2,
        "Level 2: a light guard, for a counterpart you already know "
        "well. The full flow runs, with the standard defaults.",
        _spectrum_agent_text(2),
    ),
    LevelEntry(
        3,
        "Level 3: the standard guard. Cases, scans, receipts, and the "
        "missing-receipt ladder all run the way the design describes.",
        _spectrum_agent_text(3),
    ),
    LevelEntry(
        4,
        "Level 4: the standard guard, tightened a step, for a "
        "counterpart you know less well.",
        _spectrum_agent_text(4),
    ),
    LevelEntry(
        5,
        "Level 5: the middle of the spectrum, and the shipped "
        "default. The full guard, with nothing skipped, for an "
        "ordinary working pair.",
        _spectrum_agent_text(5),
    ),
    LevelEntry(
        6,
        "Level 6: stricter than standard, for a counterpart whose "
        "traffic you want watched closely.",
        _spectrum_agent_text(6),
    ),
    LevelEntry(
        7,
        "Level 7: strict. Little is taken on trust; the guard checks "
        "hard before anything moves.",
        _spectrum_agent_text(7),
    ),
    LevelEntry(
        8,
        "Level 8: very strict, for valuable files or a counterpart "
        "with a mixed history.",
        _spectrum_agent_text(8),
    ),
    LevelEntry(
        9,
        "Level 9: near maximum. One step below the strictest the "
        "guard can run on its own.",
        _spectrum_agent_text(9),
    ),
    LevelEntry(
        10,
        "Level 10: every maximum. The strictest settings the guard "
        "has, all of them on.",
        "Level 10: maximum strictness preset: every toggle at its "
        "strictest shipped setting and every variable at its shipped "
        "default. absolute_trust_enabled still stays off, because it "
        "is never a preset default (section 10). Components: none.",
    ),
    LevelEntry(
        11,
        "Level 11: every maximum, plus a monitor agent that watches "
        "the guard itself.",
        "Level 11: the level 10 preset plus the monitor-agent "
        "component (preset_for(11).components == {'monitor-agent'}). "
        "The monitor is the only component any level adds.",
    ),
)


def questions():
    return _QUESTIONS


def level_picker():
    return _LEVEL_PICKER


def _find_question(question_id):
    for q in _QUESTIONS:
        if q.id == question_id:
            return q
    return None


class InstallerPacket:
    def __init__(self):
        self._level = DEFAULT_LEVEL
        self._answers = {q.id: q.default for q in _QUESTIONS}
        self._overrides = {}
        self._companion_install = False

    def answer(self, question_id, option_id):
        q = _find_question(question_id)
        if q is None:
            raise PacketError("unknown question: %r" % (question_id,))
        if option_id not in q.options:
            raise PacketError(
                "%r is not an option for %s (options: %s)"
                % (option_id, q.id, ", ".join(q.options)))
        self._answers[q.id] = option_id

    def pick_level(self, level):
        if isinstance(level, bool) or not isinstance(level, int):
            raise PacketError("level must be an integer, got %r"
                              % (level,))
        if not LEVEL_MIN <= level <= LEVEL_MAX:
            raise PacketError("level %d outside %d..%d"
                              % (level, LEVEL_MIN, LEVEL_MAX))
        self._level = level

    def set_override(self, name, value):
        self._overrides[name] = value

    def companion_offer(self):
        return companion_offer_for_level(self._level)

    def answer_companion(self, install):
        offer = self.companion_offer()
        if offer is None:
            raise PacketError(
                "the %s install question is only presented at "
                "level 11, not at level %d"
                % (COMPANION_NAME, self._level))
        if not isinstance(install, bool):
            raise PacketError(
                "the %s answer is a yes/no choice, got %r"
                % (offer.name, install))
        self._companion_install = install

    def declaration(self):
        decl = {
            "format_version": FORMAT_VERSION,
            "design_revision": DESIGN_REVISION,
            "level": self._level,
            "answers": dict(self._answers),
            "overrides": dict(self._overrides),
        }
        offer = self.companion_offer()
        if offer is not None:
            decl["companion"] = {
                "name": offer.name,
                "url": offer.url,
                "install": self._companion_install,
            }
        return decl


def default_packet():
    return InstallerPacket()
