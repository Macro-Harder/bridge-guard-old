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


if __name__ == "__main__":
    unittest.main()
