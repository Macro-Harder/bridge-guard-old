"""Tests for guard.companion: the trust-but-verify companion offer.

At strictness level 11 (level 10 maximums plus the monitor-agent
component), the installer packet presents one additional question:
whether to also install trust-but-verify, the MCP Server Auditor,
with its link. The answer rides in the packet declaration at level
11 only. On every guard start at level 11, if trust-but-verify is
not detected installed, the start prompts its install (question +
link); below 11, or when it is installed, the start is silent.

The pinned packet surface does not move: questions() still returns
the five section 13 questions, and preset_for(11).components is
still exactly {'monitor-agent'}.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard import companion
from guard.levels import preset_for
from guard.packet import PacketError, default_packet, questions

URL = "https://github.com/Macro-Harder/trust-but-verify"
ROOT = Path(__file__).resolve().parent.parent


def packet_at(level):
    packet = default_packet()
    packet.pick_level(level)
    return packet


class CompanionOfferTest(unittest.TestCase):
    def test_no_offer_below_level_11(self):
        for level in range(0, 11):
            self.assertIsNone(packet_at(level).companion_offer(), level)
            self.assertIsNone(companion.companion_offer_for_level(level),
                              level)

    def test_offer_at_level_11_carries_the_link(self):
        offer = packet_at(11).companion_offer()
        self.assertIsNotNone(offer)
        self.assertEqual(offer.name, "trust-but-verify")
        self.assertEqual(offer.url, URL)
        self.assertIn(URL, offer.question)

    def test_offer_says_what_it_is_in_one_line(self):
        offer = companion.companion_offer_for_level(11)
        text = (offer.description + " " + offer.question).lower()
        self.assertIn("mcp", text)
        self.assertIn("hidden instructions", text)

    def test_offer_names_the_plaid_level(self):
        offer = companion.companion_offer_for_level(11)
        self.assertIn("PLAID", offer.question)

    def test_offer_options_and_default(self):
        offer = companion.companion_offer_for_level(11)
        self.assertEqual(set(offer.options), {"install", "skip"})
        self.assertEqual(offer.default, "skip")

    def test_pinned_packet_surface_is_unchanged(self):
        self.assertEqual(len(questions()), 5)
        self.assertEqual(preset_for(11).components,
                         frozenset({"monitor-agent"}))
        self.assertEqual(preset_for(10).components, frozenset())


class CompanionDeclarationTest(unittest.TestCase):
    def test_declaration_below_11_has_no_companion_record(self):
        for level in (0, 5, 10):
            decl = packet_at(level).declaration()
            self.assertNotIn("companion", decl, level)
            self.assertEqual(
                set(decl),
                {"format_version", "design_revision", "level",
                 "answers", "overrides"}, level)

    def test_declaration_at_11_records_the_companion(self):
        decl = packet_at(11).declaration()
        self.assertIn("companion", decl)
        self.assertEqual(decl["companion"]["name"], "trust-but-verify")
        self.assertEqual(decl["companion"]["url"], URL)

    def test_unanswered_offer_defaults_to_not_installing(self):
        decl = packet_at(11).declaration()
        self.assertIs(decl["companion"]["install"], False)

    def test_answer_install_is_recorded(self):
        packet = packet_at(11)
        packet.answer_companion(True)
        self.assertIs(packet.declaration()["companion"]["install"],
                      True)

    def test_answer_skip_is_recorded(self):
        packet = packet_at(11)
        packet.answer_companion(True)
        packet.answer_companion(False)
        self.assertIs(packet.declaration()["companion"]["install"],
                      False)

    def test_answering_below_11_is_rejected(self):
        for level in (0, 5, 10):
            with self.assertRaises(PacketError):
                packet_at(level).answer_companion(True)

    def test_non_bool_answer_is_rejected(self):
        packet = packet_at(11)
        for bad in ("install", 1, None):
            with self.assertRaises(PacketError):
                packet.answer_companion(bad)

    def test_dropping_below_11_hides_the_record_not_the_answer(self):
        packet = packet_at(11)
        packet.answer_companion(True)
        packet.pick_level(10)
        self.assertNotIn("companion", packet.declaration())
        packet.pick_level(11)
        self.assertIs(packet.declaration()["companion"]["install"],
                      True)


class StartupPromptTest(unittest.TestCase):
    def test_prompt_fires_at_11_when_not_installed(self):
        prompt = companion.install_prompt(11, detector=lambda: False)
        self.assertIsNotNone(prompt)
        self.assertIn(URL, prompt.message)
        self.assertIn("trust-but-verify", prompt.message)

    def test_prompt_is_silent_at_11_when_installed(self):
        self.assertIsNone(companion.install_prompt(
            11, detector=lambda: True))

    def test_prompt_is_silent_below_11(self):
        for level in (0, 5, 10):
            self.assertIsNone(companion.install_prompt(
                level, detector=lambda: False), level)

    def test_check_startup_writes_the_prompt_to_the_stream(self):
        stream = io.StringIO()
        prompt = companion.check_startup(
            11, detector=lambda: False, stream=stream)
        self.assertIsNotNone(prompt)
        self.assertIn(URL, stream.getvalue())

    def test_check_startup_writes_nothing_when_silent(self):
        for level, installed in ((11, True), (10, False)):
            stream = io.StringIO()
            self.assertIsNone(companion.check_startup(
                level, detector=lambda: installed, stream=stream))
            self.assertEqual(stream.getvalue(), "")

    def test_a_broken_detector_never_blocks_the_start(self):
        def boom():
            raise RuntimeError("detector exploded")
        prompt = companion.check_startup(
            11, detector=boom, stream=io.StringIO())
        self.assertIsNotNone(prompt)

    def test_default_detector_honours_the_path_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"TRUST_BUT_VERIFY_PATH": tmp}
            self.assertTrue(companion.default_detector(environ=env))
            env = {"TRUST_BUT_VERIFY_PATH": str(Path(tmp) / "nope")}
            self.assertFalse(companion.default_detector(environ=env))


class DeclaredLevelTest(unittest.TestCase):
    def test_level_from_the_guard_policy_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "policy.json").write_text(
                json.dumps({"level": 11}))
            self.assertEqual(companion.declared_level(home, environ={}),
                             11)

    def test_level_from_the_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(
                companion.declared_level(
                    tmp, environ={"BRIDGE_GUARD_LEVEL": "10"}), 10)

    def test_policy_beats_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "policy.json").write_text(json.dumps({"level": 11}))
            self.assertEqual(
                companion.declared_level(
                    home, environ={"BRIDGE_GUARD_LEVEL": "3"}), 11)

    def test_no_level_declared_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(companion.declared_level(tmp, environ={}))

    def test_garbage_level_is_no_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / "policy.json").write_text(
                json.dumps({"level": "eleven"}))
            self.assertIsNone(companion.declared_level(home, environ={}))
            self.assertIsNone(companion.declared_level(
                home, environ={"BRIDGE_GUARD_LEVEL": "soon"}))


def run_cli(home, *args, env_extra=None):
    env = dict(os.environ)
    env.pop("BRIDGE_GUARD_LEVEL", None)
    env.pop("TRUST_BUT_VERIFY_PATH", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(ROOT / "guard.py"), "--home", str(home),
         *args],
        capture_output=True, text=True, env=env, timeout=60)


class GuardCliStartupTest(unittest.TestCase):
    def test_start_at_11_without_the_tool_prompts_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            init = run_cli(home, "init", "--level", "11")
            self.assertEqual(init.returncode, 0, init.stderr)
            policy = json.loads((home / "policy.json").read_text())
            self.assertEqual(policy["level"], 11)
            status = run_cli(home, "status")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn(URL, status.stderr)
            again = run_cli(home, "status")
            self.assertIn(URL, again.stderr)

    def test_start_at_11_with_the_tool_detected_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            run_cli(home, "init", "--level", "11")
            status = run_cli(
                home, "status",
                env_extra={"TRUST_BUT_VERIFY_PATH": tmp})
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertNotIn(URL, status.stderr)

    def test_start_at_10_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            run_cli(home, "init", "--level", "10")
            status = run_cli(home, "status")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertNotIn(URL, status.stderr)

    def test_start_with_no_level_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            run_cli(home, "init")
            status = run_cli(home, "status")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertNotIn(URL, status.stderr)


class GuardMcpStartupTest(unittest.TestCase):
    def run_mcp(self, home, env_extra=None):
        env = dict(os.environ)
        env.pop("BRIDGE_GUARD_LEVEL", None)
        env.pop("TRUST_BUT_VERIFY_PATH", None)
        env["BRIDGE_GUARD_HOME"] = str(home)
        if env_extra:
            env.update(env_extra)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "guard-mcp.py")],
            input='{"jsonrpc": "2.0", "id": 1, "method": '
                  '"initialize", "params": {}}\n',
            capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        reply = json.loads(proc.stdout.strip().splitlines()[0])
        self.assertEqual(reply["result"]["serverInfo"]["name"],
                         "bridge-guard")
        return proc

    def test_mcp_start_at_11_prompts_on_stderr_not_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            (home / "policy.json").write_text(json.dumps({"level": 11}))
            proc = self.run_mcp(home)
            self.assertIn(URL, proc.stderr)
            self.assertNotIn(URL, proc.stdout)

    def test_mcp_start_at_10_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            (home / "policy.json").write_text(json.dumps({"level": 10}))
            proc = self.run_mcp(home)
            self.assertNotIn(URL, proc.stderr)


if __name__ == "__main__":
    unittest.main()
