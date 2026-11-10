"""The trust-but-verify companion: offer, declaration, startup prompt.

trust-but-verify is a standalone MCP Server Auditor
(https://github.com/Macro-Harder/trust-but-verify): it audits an MCP
server's tool descriptions and schemas for hidden instructions
before an agent trusts them. It is not part of this guard and the
guard works without it.

Two PLAID surfaces live here, and nowhere else:

- The installer offer. At PLAID -- strictness level 11 (the level
  10 maximums plus the monitor-agent component) the installer
  packet presents one additional question -- whether to also
  install trust-but-verify, carrying its link -- because at PLAID
  the monitor uses it as its MCP-audit companion. guard.packet
  asks this module for the offer; the pinned five packet
  questions and the level presets do not change.
- The startup prompt. On every guard start, if the guard's
  declared level is PLAID (11) and trust-but-verify is not
  detected
  installed, the start prints the install prompt (the question and
  the link) to stderr. The check never blocks a start, never
  installs anything, and is silent at every other level and
  whenever the companion is detected.
"""
import dataclasses
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

from guard.levels import LEVEL_PLAID

COMPANION_NAME = "trust-but-verify"
COMPANION_URL = "https://github.com/Macro-Harder/trust-but-verify"
COMPANION_DESCRIPTION = (
    "trust-but-verify audits MCP servers' tool descriptions and "
    "schemas for hidden instructions before an agent trusts them.")
COMPANION_LEVEL = LEVEL_PLAID

LEVEL_ENV = "BRIDGE_GUARD_LEVEL"
PATH_ENV = "TRUST_BUT_VERIFY_PATH"
MODULE_NAME = "trust_but_verify"
BINARY_NAME = "trust-but-verify"

_QUESTION = (
    "Also install trust-but-verify, the guard's MCP-audit "
    "companion at PLAID (level 11)? It audits MCP servers' tool "
    "descriptions and schemas for hidden instructions before an "
    "agent trusts them: " + COMPANION_URL)


@dataclasses.dataclass(frozen=True)
class CompanionOffer:
    name: str
    url: str
    description: str
    question: str
    options: tuple
    default: str


@dataclasses.dataclass(frozen=True)
class StartupPrompt:
    level: int
    name: str
    url: str
    message: str


_OFFER = CompanionOffer(
    name=COMPANION_NAME,
    url=COMPANION_URL,
    description=COMPANION_DESCRIPTION,
    question=_QUESTION,
    options=("install", "skip"),
    default="skip",
)


def companion_offer_for_level(level):
    if isinstance(level, bool) or not isinstance(level, int):
        return None
    if level != COMPANION_LEVEL:
        return None
    return _OFFER


def default_detector(environ=None):
    env = os.environ if environ is None else environ
    override = env.get(PATH_ENV)
    if override:
        return Path(override).expanduser().exists()
    try:
        if importlib.util.find_spec(MODULE_NAME) is not None:
            return True
    except Exception:
        pass
    return shutil.which(BINARY_NAME) is not None


def install_prompt(level, detector=None):
    if companion_offer_for_level(level) is None:
        return None
    detect = default_detector if detector is None else detector
    try:
        installed = bool(detect())
    except Exception:
        installed = False
    if installed:
        return None
    message = (
        "bridge-guard: this guard is set to PLAID (level 11), "
        "and its MCP-audit companion is not installed.\n"
        + _QUESTION + "\n"
        "The guard runs without it; the prompt returns on every "
        "start until it is installed.")
    return StartupPrompt(level=level, name=COMPANION_NAME,
                         url=COMPANION_URL, message=message)


def check_startup(level, detector=None, stream=None):
    prompt = install_prompt(level, detector=detector)
    if prompt is None:
        return None
    out = sys.stderr if stream is None else stream
    try:
        out.write(prompt.message + "\n")
        out.flush()
    except Exception:
        pass
    return prompt


def _coerce_level(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def declared_level(home, environ=None):
    env = os.environ if environ is None else environ
    if home is not None:
        try:
            saved = json.loads(
                (Path(home).expanduser() / "policy.json")
                .read_text())
            if isinstance(saved, dict) and "level" in saved:
                level = _coerce_level(saved["level"])
                if level is not None:
                    return level
        except Exception:
            pass
    return _coerce_level(env.get(LEVEL_ENV))
