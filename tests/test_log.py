"""Tests for guard.log: the single-writer, role-signed, hash-chained
log core (DESIGN section 7, Appendix B.1 schemas, Appendix B.3
submission interface)."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.log import (
    ChainError,
    LogError,
    LogEvent,
    LogService,
    SchemaError,
    SignatureError,
    SignerError,
    WriterError,
    generate_key,
    sign_event,
    verify_log,
)

ROLES = [
    "communicator",
    "investigator",
    "manager",
    "verifier",
    "gate",
    "log-service",
    "scanner-runner",
    "scanner",
    "transfer-agent",
    "sender",
    "ledger-function",
    "signing-tool",
    "boss",
    "spoiler-checker",
]

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def request_event(**over):
    event = {
        "type": "request",
        "request_id": "req-1",
        "counterpart": "agent-b",
        "format": 2,
        "path": "notes/plan.md",
        "size": 128,
        "reason": "quarterly numbers",
    }
    event.update(over)
    return event


def case_event(**over):
    event = {
        "type": "case",
        "case_id": "case-1",
        "request_ref": "evt-req",
        "file_hash": HASH_A,
        "size": 128,
        "case_hash": HASH_B,
    }
    event.update(over)
    return event


def approve_event(**over):
    event = {
        "type": "approve",
        "basis": "case",
        "artifact_hash": HASH_B,
        "size": 128,
        "case_ref": "evt-case",
    }
    event.update(over)
    return event


class LogTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmp.name) / "guard.log.jsonl"
        self.keys = {role: generate_key() for role in ROLES}
        self.public = {role: key.public_key for role, key in self.keys.items()}
        self.counter = 0
        self.service = LogService(self.log_path, self.public)

    def tearDown(self):
        self.service.close()
        self.tmp.cleanup()

    def fresh_id(self):
        self.counter += 1
        return "evt-%d" % self.counter

    def submit(self, event, signer, key=None, second_key=None):
        event = dict(event)
        event.setdefault("id", self.fresh_id())
        signing_key = key if key is not None else self.keys[signer]
        signature = sign_event(signing_key, event)
        second = sign_event(second_key, event) if second_key else None
        return self.service.submit(event, signer, signature, second)

    def stored(self):
        return verify_log(self.log_path, self.public)


class SingleWriterTest(LogTestBase):
    def test_second_writer_refused(self):
        with self.assertRaises(WriterError):
            LogService(self.log_path, self.public)

    def test_writer_reopens_after_close(self):
        self.submit(request_event(), "communicator")
        self.service.close()
        self.service = LogService(self.log_path, self.public)
        events = self.stored()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].type, "request")

    def test_submit_after_close_refused(self):
        self.service.close()
        event = request_event(id="evt-closed")
        signature = sign_event(self.keys["communicator"], event)
        with self.assertRaises(LogError):
            self.service.submit(event, "communicator", signature)


class ChainTest(LogTestBase):
    def test_events_chain_to_previous_hash(self):
        self.submit(request_event(), "communicator")
        self.submit(case_event(), "investigator")
        self.submit(approve_event(), "manager")
        events = self.stored()
        self.assertEqual([e.position for e in events], [0, 1, 2])
        self.assertEqual(events[1].prev_hash, events[0].hash)
        self.assertEqual(events[2].prev_hash, events[1].hash)
        for event in events:
            self.assertIsInstance(event, LogEvent)
            self.assertTrue(event.hash)

    def test_genesis_prev_hash_is_a_fixed_sentinel(self):
        self.submit(request_event(), "communicator")
        other_path = Path(self.tmp.name) / "other.jsonl"
        other = LogService(other_path, self.public)
        try:
            event = request_event(id="evt-other")
            signature = sign_event(self.keys["communicator"], event)
            other.submit(event, "communicator", signature)
        finally:
            other.close()
        mine = self.stored()[0]
        theirs = verify_log(other_path, self.public)[0]
        self.assertEqual(mine.prev_hash, theirs.prev_hash)

    def test_receipt_reports_position_and_head(self):
        self.submit(request_event(), "communicator")
        receipt = self.submit(case_event(), "investigator")
        events = self.stored()
        self.assertEqual(receipt.event_id, events[1].id)
        self.assertEqual(receipt.chain_position, events[1].position)
        self.assertEqual(receipt.chain_head, events[1].hash)
        self.assertTrue(receipt.signature)

    def test_stored_events_carry_id_and_timestamp(self):
        self.submit(request_event(), "communicator")
        event = self.stored()[0]
        self.assertTrue(event.id)
        self.assertTrue(event.ts)
        self.assertEqual(event.signer, "communicator")

    def test_verify_rejects_edited_entry(self):
        self.submit(request_event(), "communicator")
        self.submit(case_event(), "investigator")
        text = self.log_path.read_text()
        self.assertIn("notes/plan.md", text)
        self.log_path.write_text(text.replace("notes/plan.md", "notes/other.md"))
        with self.assertRaises(ChainError):
            verify_log(self.log_path, self.public)

    def test_verify_rejects_deleted_entry(self):
        self.submit(request_event(), "communicator")
        self.submit(case_event(), "investigator")
        self.submit(approve_event(), "manager")
        lines = self.log_path.read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.log_path.write_text("\n".join([lines[0], lines[2]]) + "\n")
        with self.assertRaises(ChainError):
            verify_log(self.log_path, self.public)

    def test_verify_rejects_out_of_order_entries(self):
        self.submit(request_event(), "communicator")
        self.submit(case_event(), "investigator")
        self.submit(approve_event(), "manager")
        lines = self.log_path.read_text().splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        self.log_path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(ChainError):
            verify_log(self.log_path, self.public)


class SignatureTest(LogTestBase):
    def test_wrong_signer_for_event_kind_rejected(self):
        with self.assertRaises(SignerError):
            self.submit(case_event(), "manager")

    def test_signature_from_wrong_key_rejected(self):
        with self.assertRaises(SignatureError):
            self.submit(approve_event(), "manager",
                        key=self.keys["investigator"])

    def test_signature_over_other_event_rejected(self):
        event = approve_event(id="evt-target")
        other = approve_event(id="evt-other", size=999)
        signature = sign_event(self.keys["manager"], other)
        with self.assertRaises(SignatureError):
            self.service.submit(event, "manager", signature)

    def test_scan_dual_signed_accepted(self):
        event = {
            "type": "scan",
            "file_hash": HASH_A,
            "pattern_result": "clean",
            "pattern_result_hash": HASH_B,
            "agent_verdict": "clean",
            "inspectability": "inspectable",
        }
        self.submit(event, "scanner-runner", second_key=self.keys["scanner"])
        events = self.stored()
        self.assertEqual(events[0].type, "scan")
        self.assertEqual(events[0].signer, "scanner-runner")

    def test_scan_with_single_signature_rejected(self):
        event = {
            "type": "scan",
            "file_hash": HASH_A,
            "pattern_result": "clean",
            "pattern_result_hash": HASH_B,
            "agent_verdict": "clean",
            "inspectability": "inspectable",
        }
        with self.assertRaises(SignatureError):
            self.submit(event, "scanner-runner")

    def test_scan_with_wrong_second_signer_rejected(self):
        event = {
            "type": "scan",
            "file_hash": HASH_A,
            "pattern_result": "clean",
            "pattern_result_hash": HASH_B,
            "agent_verdict": "clean",
            "inspectability": "inspectable",
        }
        with self.assertRaises(SignatureError):
            self.submit(event, "scanner-runner",
                        second_key=self.keys["manager"])

    def test_checkpoint_countersigned_accepted(self):
        event = {
            "type": "checkpoint",
            "checkpoint_hash": HASH_A,
            "set_root": HASH_B,
            "entry_count": 3,
        }
        self.submit(event, "log-service", second_key=self.keys["verifier"])
        self.assertEqual(self.stored()[0].type, "checkpoint")

    def test_checkpoint_without_countersignature_rejected(self):
        event = {
            "type": "checkpoint",
            "checkpoint_hash": HASH_A,
            "set_root": HASH_B,
            "entry_count": 3,
        }
        with self.assertRaises(SignatureError):
            self.submit(event, "log-service")

    def test_checkpoint_with_wrong_countersigner_rejected(self):
        event = {
            "type": "checkpoint",
            "checkpoint_hash": HASH_A,
            "set_root": HASH_B,
            "entry_count": 3,
        }
        with self.assertRaises(SignatureError):
            self.submit(event, "log-service", second_key=self.keys["manager"])


class SchemaTest(LogTestBase):
    def test_valid_request_round_trips(self):
        self.submit(request_event(sha256=HASH_A), "communicator")
        event = self.stored()[0]
        self.assertEqual(event.fields["path"], "notes/plan.md")
        self.assertEqual(event.fields["size"], 128)
        self.assertEqual(event.fields["counterpart"], "agent-b")
        self.assertEqual(event.fields["sha256"], HASH_A)

    def test_missing_required_field_rejected(self):
        event = approve_event()
        del event["artifact_hash"]
        with self.assertRaises(SchemaError):
            self.submit(event, "manager")

    def test_forbidden_field_rejected(self):
        with self.assertRaises(SchemaError):
            self.submit(case_event(decision="approve"), "investigator")

    def test_unlisted_field_rejected(self):
        event = {
            "type": "staged",
            "transfer_id": "tr-1",
            "file_hash": HASH_A,
            "size": 128,
            "staged_name": "plan.md",
            "comment": "looks fine",
        }
        with self.assertRaises(SchemaError):
            self.submit(event, "manager")

    def test_wrong_field_type_rejected(self):
        with self.assertRaises(SchemaError):
            self.submit(request_event(size="big"), "communicator")

    def test_bad_enum_value_rejected(self):
        with self.assertRaises(SchemaError):
            self.submit(request_event(format=3), "communicator")

    def test_format1_request_requires_hash(self):
        event = request_event(format=1)
        del event["reason"]
        with self.assertRaises(SchemaError):
            self.submit(event, "communicator")
        self.submit(request_event(format=1, sha256=HASH_A), "communicator")
        requests = [e for e in self.stored() if e.type == "request"]
        self.assertEqual(len(requests), 1)

    def test_approve_case_ref_required_when_basis_is_case(self):
        event = approve_event()
        del event["case_ref"]
        with self.assertRaises(SchemaError):
            self.submit(event, "manager")

    def test_approve_case_ref_absent_when_basis_is_list(self):
        with self.assertRaises(SchemaError):
            self.submit(approve_event(basis="list"), "manager")
        event = approve_event(basis="list")
        del event["case_ref"]
        self.submit(event, "manager")
        approvals = [e for e in self.stored() if e.type == "approve"]
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0].fields["basis"], "list")

    def test_approve_junk_class_forbidden(self):
        with self.assertRaises(SchemaError):
            self.submit(approve_event(junk_class="spam"), "manager")

    def test_charge_hash_match_forbidden(self):
        event = {
            "type": "charge",
            "counterpart": "agent-b",
            "amount": 5,
            "class": "junk",
            "ref": "evt-req",
            "hash_match": True,
        }
        with self.assertRaises(SchemaError):
            self.submit(event, "ledger-function")

    def test_deleted_requires_exactly_one_ref(self):
        base = {"type": "deleted", "transfer_id": "tr-1", "size": 128}
        with self.assertRaises(SchemaError):
            self.submit(dict(base, receipt_ref="evt-r",
                             disposition_ref="evt-d"), "transfer-agent")
        with self.assertRaises(SchemaError):
            self.submit(dict(base), "transfer-agent")
        self.submit(dict(base, receipt_ref="evt-r"), "transfer-agent")
        deletions = [e for e in self.stored() if e.type == "deleted"]
        self.assertEqual(len(deletions), 1)

    def test_kill_switch_agent_raised_needs_two_signals(self):
        base = {
            "type": "kill-switch",
            "reason": "scanner finding plus security sign-off",
            "evidence_refs": ["evt-scan"],
            "trip_kind": "agent-raised",
        }
        with self.assertRaises(SchemaError):
            self.submit(dict(base), "boss")
        with self.assertRaises(SchemaError):
            self.submit(dict(base, signal_refs=["evt-scan"]), "boss")
        self.submit(dict(base, signal_refs=["evt-scan", "evt-finding"]),
                    "boss")
        trips = [e for e in self.stored() if e.type == "kill-switch"]
        self.assertEqual(len(trips), 1)

    def test_kill_switch_wrong_signer_rejected(self):
        event = {
            "type": "kill-switch",
            "reason": "broken chain",
            "evidence_refs": ["evt-check"],
            "trip_kind": "code-verified",
        }
        with self.assertRaises(SignerError):
            self.submit(event, "manager")
        self.submit(event, "verifier")
        trips = [e for e in self.stored() if e.type == "kill-switch"]
        self.assertEqual(len(trips), 1)

    def test_unknown_event_type_rejected(self):
        with self.assertRaises(SchemaError):
            self.submit({"type": "teleport", "size": 1}, "manager")

    def test_rejections_leave_chain_verifiable(self):
        self.submit(request_event(), "communicator")
        with self.assertRaises(SchemaError):
            self.submit(case_event(decision="approve"), "investigator")
        with self.assertRaises(SignerError):
            self.submit(case_event(), "manager")
        with self.assertRaises(SignatureError):
            self.submit(approve_event(), "manager",
                        key=self.keys["investigator"])
        events = self.stored()
        self.assertEqual(events[0].type, "request")
        self.assertEqual([e.position for e in events],
                         list(range(len(events))))
        accepted_types = [e.type for e in events]
        self.assertNotIn("case", accepted_types)
        self.assertNotIn("approve", accepted_types)


if __name__ == "__main__":
    unittest.main()
