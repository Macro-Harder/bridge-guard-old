"""Tests for guard-mcp.py's stdio JSON-RPC input handling."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_mcp(home, lines):
    env = dict(os.environ)
    env.pop("BRIDGE_GUARD_LEVEL", None)
    env.pop("TRUST_BUT_VERIFY_PATH", None)
    env["BRIDGE_GUARD_HOME"] = str(home)
    return subprocess.run(
        [sys.executable, str(ROOT / "guard-mcp.py")],
        input="\n".join(lines) + "\n",
        capture_output=True, text=True, env=env, timeout=60)


class NonObjectInputTest(unittest.TestCase):
    """Regression for audit H4 / break-it A9: one valid-JSON but
    non-object line used to raise AttributeError outside the
    loop's error handling and kill the MCP server."""

    def test_non_object_lines_do_not_kill_the_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_mcp(Path(tmp) / "home", [
                "[]",
                '"a string"',
                "42",
                "null",
                "true",
                '{"jsonrpc": "2.0", "id": 99, "method": '
                '"initialize", "params": {}}',
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            replies = [json.loads(line)
                       for line in proc.stdout.splitlines()]
            self.assertEqual(len(replies), 1)
            self.assertEqual(replies[0]["id"], 99)
            self.assertEqual(
                replies[0]["result"]["serverInfo"]["name"],
                "bridge-guard")


class PingAndMalformedInputTest(unittest.TestCase):
    """Regression for audit L5 / break-it A10: ping requests were
    swallowed with notifications and never answered, and malformed
    JSON lines vanished without a trace."""

    def test_ping_is_answered_and_malformed_json_is_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_mcp(Path(tmp) / "home", [
                '{"jsonrpc": "2.0", "id": 7, "method": "ping"}',
                '{"jsonrpc": "2.0", "method": ',
                '{"jsonrpc": "2.0", "id": 8, "method": '
                '"initialize", "params": {}}',
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            replies = [json.loads(line)
                       for line in proc.stdout.splitlines()]
            self.assertEqual([reply["id"] for reply in replies],
                             [7, 8])
            self.assertEqual(replies[0]["result"], {})
            self.assertIn("malformed JSON", proc.stderr)

    def test_notifications_still_get_no_reply(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_mcp(Path(tmp) / "home", [
                '{"jsonrpc": "2.0", "method": '
                '"notifications/initialized"}',
                '{"jsonrpc": "2.0", "id": 9, "method": '
                '"initialize", "params": {}}',
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            replies = [json.loads(line)
                       for line in proc.stdout.splitlines()]
            self.assertEqual([reply["id"] for reply in replies], [9])


class GuardLogToolTest(unittest.TestCase):
    """Regression for audit L6: guard_log parsed the requested
    tail with one list comprehension, so a single corrupt line
    failed the whole tool, and a non-integer n crashed or sliced
    the log in surprising ways."""

    def call_log(self, home, arguments):
        request = {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                   "params": {"name": "guard_log",
                              "arguments": arguments}}
        proc = run_mcp(home, [json.dumps(request)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        reply = json.loads(proc.stdout.strip().splitlines()[0])
        result = reply["result"]
        self.assertNotIn("isError", result)
        return json.loads(result["content"][0]["text"])

    def test_corrupt_lines_are_skipped_and_n_is_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            entries = [{"event": "e%d" % i} for i in range(5)]
            lines = [json.dumps(entry) for entry in entries]
            lines.insert(4, '{"event": "torn"')
            (home / "guard-log.jsonl").write_text(
                "\n".join(lines) + "\n")
            self.assertEqual(
                self.call_log(home, {"n": 3})["entries"],
                entries[2:])
            self.assertEqual(
                self.call_log(home, {"n": "3"})["entries"], entries)
            self.assertEqual(
                self.call_log(home, {"n": -1})["entries"], entries)
            self.assertEqual(
                self.call_log(home, {})["entries"], entries)


if __name__ == "__main__":
    unittest.main()
