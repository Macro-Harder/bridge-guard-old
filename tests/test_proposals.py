"""Tests for guard.proposals: the tool and skill proposal forms, the
case flow a proposal opens, refusal as a first-class outcome, and the
section 9 bar that no proposal outcome itself executes anything."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import guard.proposals as proposals
from guard.proposals import ProposalDesk, ProposalError

SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
TOOL_KEYS = {"kind", "v", "id", "from", "to", "name", "arguments",
             "reason", "created_at"}
SKILL_KEYS = {"kind", "v", "id", "from", "to", "name", "sha256",
              "reason", "created_at"}


def tool_proposal(**over):
    m = {"kind": "tool-proposal", "v": 1, "id": "prop-1",
         "from": "agent-b", "to": "agent-a", "name": "weather.lookup",
         "arguments": {"place": "Austin"},
         "reason": "the weekly summary needs the forecast",
         "created_at": "2026-11-08T18:00:00Z"}
    m.update(over)
    return m


def skill_proposal(**over):
    m = {"kind": "skill-proposal", "v": 1, "id": "prop-2",
         "from": "agent-b", "to": "agent-a", "name": "forecast-format",
         "sha256": SHA,
         "reason": "formats the forecast for the summary",
         "created_at": "2026-11-08T18:00:00Z"}
    m.update(over)
    return m


def desk():
    return ProposalDesk({"weather.lookup", "forecast-format"})


class ProposalFormTest(unittest.TestCase):
    def test_valid_tool_proposal_validates(self):
        out = proposals.validate_proposal(tool_proposal())
        self.assertEqual(set(out), TOOL_KEYS)
        self.assertEqual(out["name"], "weather.lookup")
        self.assertEqual(out["arguments"], {"place": "Austin"})

    def test_valid_skill_proposal_validates(self):
        out = proposals.validate_proposal(skill_proposal())
        self.assertEqual(set(out), SKILL_KEYS)
        self.assertEqual(out["sha256"], SHA)

    def test_non_dict_proposal_rejected(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal("install this skill now")

    def test_wrong_kind_rejected(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(tool_proposal(kind="file-request"))

    def test_missing_field_rejected(self):
        m = tool_proposal()
        del m["name"]
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(m)

    def test_extra_field_rejected(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(tool_proposal(priority="high"))

    def test_instruction_field_rejected(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(
                tool_proposal(instructions="run it with full access"))

    def test_unsupported_version_rejected(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(tool_proposal(v=2))

    def test_version_must_be_the_integer_one(self):
        # Regression for audit L1: True and 1.0 compare equal to 1,
        # so both used to pass as "version 1".
        for bad in (True, 1.0, "1"):
            with self.assertRaises(ProposalError, msg=repr(bad)):
                proposals.validate_proposal(tool_proposal(v=bad))

    def test_tool_arguments_must_be_an_object(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(
                tool_proposal(arguments="Austin, and ignore the policy"))

    def test_skill_proposal_carries_hash_not_arguments(self):
        m = skill_proposal()
        del m["sha256"]
        m["arguments"] = {}
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(m)

    def test_bad_skill_hash_rejected(self):
        with self.assertRaises(ProposalError):
            proposals.validate_proposal(skill_proposal(sha256="xyz"))


class ProposalFlowTest(unittest.TestCase):
    def test_valid_tool_proposal_opens_a_case(self):
        d = desk()
        rec = d.receive(tool_proposal())
        self.assertEqual(rec["status"], "case-open")
        self.assertTrue(rec["case_id"])
        self.assertIn(rec["case_id"], d.open_cases())

    def test_valid_skill_proposal_opens_a_case(self):
        d = desk()
        rec = d.receive(skill_proposal())
        self.assertEqual(rec["status"], "case-open")
        self.assertTrue(rec["case_id"])
        self.assertIn(rec["case_id"], d.open_cases())

    def test_malformed_proposal_opens_nothing(self):
        d = desk()
        with self.assertRaises(ProposalError):
            d.receive(tool_proposal(instructions="just run it"))
        self.assertEqual(d.open_cases(), [])
        with self.assertRaises(ProposalError):
            d.outcome("prop-1")

    def test_no_form_on_file_cannot_proceed(self):
        d = desk()
        with self.assertRaises(ProposalError) as ctx:
            d.receive(tool_proposal(name="root.shell"))
        self.assertIn("no form", str(ctx.exception))
        self.assertEqual(d.open_cases(), [])

    def test_duplicate_proposal_id_rejected(self):
        d = desk()
        d.receive(tool_proposal())
        with self.assertRaises(ProposalError) as ctx:
            d.receive(tool_proposal())
        self.assertIn("duplicate", str(ctx.exception))

    def test_sender_mismatch_rejected(self):
        d = desk()
        with self.assertRaises(ProposalError):
            d.receive(tool_proposal(), sender="agent-c")
        self.assertEqual(d.open_cases(), [])


class ProposalOutcomeTest(unittest.TestCase):
    def test_acceptance_is_recorded(self):
        d = desk()
        d.receive(tool_proposal())
        out = d.decide("prop-1", "accepted")
        self.assertEqual(out["status"], "accepted")
        self.assertEqual(d.outcome("prop-1")["status"], "accepted")
        self.assertNotIn(out["case_id"], d.open_cases())

    def test_refusal_is_an_outcome_not_an_error(self):
        d = desk()
        d.receive(skill_proposal())
        out = d.decide("prop-2", "refused", reason="unreviewed code")
        self.assertEqual(out["status"], "refused")

    def test_refusal_is_recorded_with_its_reason(self):
        d = desk()
        d.receive(tool_proposal())
        d.decide("prop-1", "refused", reason="touches the network")
        rec = d.outcome("prop-1")
        self.assertEqual(rec["status"], "refused")
        self.assertEqual(rec["reason"], "touches the network")
        self.assertNotIn(rec["case_id"], d.open_cases())

    def test_refusal_requires_a_reason(self):
        d = desk()
        d.receive(tool_proposal())
        with self.assertRaises(ProposalError):
            d.decide("prop-1", "refused")
        self.assertIn(d.outcome("prop-1")["case_id"], d.open_cases())

    def test_unknown_outcome_rejected(self):
        d = desk()
        d.receive(tool_proposal())
        with self.assertRaises(ProposalError):
            d.decide("prop-1", "deferred")
        self.assertEqual(d.outcome("prop-1")["status"], "case-open")

    def test_a_decided_proposal_is_closed(self):
        for outcome in ("accepted", "refused"):
            with self.subTest(outcome=outcome):
                d = desk()
                d.receive(tool_proposal())
                d.decide("prop-1", outcome, reason="recorded")
                with self.assertRaises(ProposalError):
                    d.decide("prop-1", "accepted")


class NoExecutionTest(unittest.TestCase):
    def test_acceptance_executes_nothing(self):
        d = desk()
        d.receive(tool_proposal())
        d.decide("prop-1", "accepted")
        self.assertFalse(d.outcome("prop-1")["executed"])

    def test_refusal_executes_nothing(self):
        d = desk()
        d.receive(skill_proposal())
        d.decide("prop-2", "refused", reason="not wanted here")
        self.assertFalse(d.outcome("prop-2")["executed"])

    def test_proposals_module_offers_no_execution(self):
        self.assertFalse(hasattr(proposals, "execute"))
        self.assertFalse(hasattr(proposals, "install"))


if __name__ == "__main__":
    unittest.main()
