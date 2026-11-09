"""Tests for guard.transfer: the two folders, the lists, the
transfer agent, quarantine, and the spoiler hash check
(DESIGN sections 2.4, 3.2, 3.4, 4.5, 7, 15, Appendix B.2)."""
import hashlib
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.transfer import (
    CheckerFailure,
    CheckerUnavailable,
    ConnectionSevered,
    FolderAccessError,
    Folders,
    KillSwitch,
    KillSwitchTripped,
    SpoilerChecker,
    TransferAgent,
    TransferError,
    TransferInProgress,
    TransferRefused,
    artifact_hash,
    sign_artifact,
    verify_artifact,
)

MANAGER_KEY = "manager-key"
VERIFIER_KEY = "verifier-key"
AGENT_KEY = "transfer-agent-key"

DATA = b"quarterly numbers\n"
OTHER = b"a different file\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FakeLog:
    def __init__(self, entries=()):
        self.entries = list(entries)

    def __contains__(self, transfer_id):
        return transfer_id in self.entries

    def __len__(self):
        return len(self.entries)

    def position_of(self, transfer_id):
        return self.entries.index(transfer_id)


def artifact_dict(transfer_id, file_hash, **over):
    artifact = {
        "transfer_id": transfer_id,
        "basis": "case",
        "file_hash": file_hash,
        "size": 64,
        "decision": "approve",
        "junk_class": None,
        "case_hash": "c" * 64,
    }
    artifact.update(over)
    return artifact


def approval_artifact(transfer_id, file_hash, **over):
    return sign_artifact(
        artifact_dict(transfer_id, file_hash, **over), MANAGER_KEY)


def list_artifact(transfer_id, file_hash, version=3,
                  entry_path="notes/plan.md"):
    raw = artifact_dict(transfer_id, file_hash, basis="list",
                        list_entry=entry_path, list_version=version)
    del raw["case_hash"]
    return sign_artifact(raw, MANAGER_KEY)


def agreement_artifact(transfer_id, file_hash):
    raw = artifact_dict(transfer_id, file_hash, basis="agreement",
                        agreement_id="agr-1")
    del raw["case_hash"]
    return sign_artifact(raw, MANAGER_KEY)


def transfer_ready(transfer_id, staged_hash, artifact=None, **over):
    ready = {
        "transfer_id": transfer_id,
        "staged_hash": staged_hash,
        "approval_artifact_hash": (
            artifact_hash(artifact) if artifact is not None
            else "0" * 64),
    }
    ready.update(over)
    return sign_artifact(ready, MANAGER_KEY)


def gate_pass(transfer_id, staged_hash, **over):
    passed = {
        "pass_id": "pass-1",
        "transfer_id": transfer_id,
        "staged_hash": staged_hash,
        "expiry": 900,
    }
    passed.update(over)
    return sign_artifact(passed, VERIFIER_KEY)


def default_list(entries, version=3):
    return {"counterpart": "agent-b", "version": version,
            "entries": entries, "expiry": 999999}


class TransferTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.checker = SpoilerChecker(set())
        self.kill_switch = KillSwitch()
        self.folders = Folders(Path(self.tmp.name) / "guard",
                               spoiler_checker=self.checker,
                               kill_switch=self.kill_switch)
        self.log = FakeLog(["tid-1", "tid-2", "tid-3"])
        self.alerts = []
        self.agent = self.make_agent()

    def tearDown(self):
        self.tmp.cleanup()

    def make_agent(self, **over):
        args = {
            "agent_key": AGENT_KEY,
            "manager_key": MANAGER_KEY,
            "verifier_key": VERIFIER_KEY,
            "log": self.log,
            "default_list": default_list(
                [{"path": "notes/plan.md", "sha256": sha(DATA)}]),
            "alerts": self.alerts,
        }
        args.update(over)
        return TransferAgent(self.folders, **args)

    def stage(self, transfer_id="tid-1", data=DATA):
        return self.folders.stage("manager", transfer_id, data)

    def ready_move(self, transfer_id="tid-1", data=DATA,
                   artifact=None):
        if artifact is None:
            artifact = approval_artifact(transfer_id, sha(data))
        ready = transfer_ready(transfer_id, sha(data), artifact)
        passed = gate_pass(transfer_id, sha(data))
        return ready, artifact, passed


class FolderPermissionsTest(TransferTestCase):
    def test_manager_stages_into_folder_1(self):
        path = self.stage()
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), DATA)
        self.assertTrue(self.folders.in_staging("tid-1"))

    def test_transfer_agent_cannot_write_folder_1(self):
        with self.assertRaises(FolderAccessError):
            self.folders.stage("transfer-agent", "tid-1", DATA)
        self.assertFalse(self.folders.in_staging("tid-1"))

    def test_other_roles_cannot_write_folder_1(self):
        for role in ("investigator", "scanner", "boss", "gate"):
            with self.subTest(role=role):
                with self.assertRaises(FolderAccessError):
                    self.folders.stage(role, "tid-1", DATA)

    def test_transfer_agent_writes_folder_2(self):
        path = self.folders.write_outbox("transfer-agent", "tid-1",
                                         DATA)
        self.assertEqual(path.read_bytes(), DATA)
        self.assertTrue(self.folders.in_outbox("tid-1"))

    def test_manager_cannot_write_folder_2(self):
        with self.assertRaises(FolderAccessError):
            self.folders.write_outbox("manager", "tid-1", DATA)
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_other_roles_cannot_write_folder_2(self):
        for role in ("investigator", "scanner", "boss"):
            with self.subTest(role=role):
                with self.assertRaises(FolderAccessError):
                    self.folders.write_outbox(role, "tid-1", DATA)

    def test_manager_cannot_rename_into_folder_2(self):
        self.stage()
        with self.assertRaises(FolderAccessError):
            self.folders.move_staged_to_outbox("manager", "tid-1")
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_manager_cannot_drop_into_quarantine(self):
        self.stage()
        with self.assertRaises(FolderAccessError):
            self.folders.move_staged_to_quarantine("manager", "tid-1")
        self.assertTrue(self.folders.in_staging("tid-1"))

    def test_folders_and_copies_have_restrictive_modes(self):
        path = self.stage()
        self.assertEqual(
            self.folders.staging_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(
            self.folders.outbox_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class StagingSpoilerTest(TransferTestCase):
    def test_clean_file_stages_without_tripping(self):
        self.stage()
        self.assertFalse(self.kill_switch.tripped)
        self.assertTrue(self.folders.in_staging("tid-1"))

    def test_spoiler_match_at_staging_trips_and_quarantines(self):
        self.checker.hashes.add(sha(DATA))
        self.stage()
        self.assertTrue(self.kill_switch.tripped)
        self.assertEqual(self.kill_switch.reason, "spoiler")
        self.assertFalse(self.folders.in_staging("tid-1"))
        self.assertTrue(self.folders.in_quarantine("tid-1"))
        self.assertEqual(
            self.folders.quarantine_path("tid-1").read_bytes(), DATA)

    def test_staging_without_a_checker_fails_closed(self):
        folders = Folders(Path(self.tmp.name) / "bare",
                          spoiler_checker=None,
                          kill_switch=KillSwitch())
        with self.assertRaises(CheckerUnavailable):
            folders.stage("manager", "tid-1", DATA)
        self.assertFalse(folders.in_staging("tid-1"))


class HappyMoveTest(TransferTestCase):
    def test_move_on_default_list_via_list_artifact(self):
        self.stage()
        artifact = list_artifact("tid-1", sha(DATA))
        ready = transfer_ready("tid-1", sha(DATA), artifact)
        record = self.agent.move(ready, artifact,
                                 gate_pass("tid-1", sha(DATA)))
        self.assertEqual(record["transfer_id"], "tid-1")
        self.assertEqual(record["file_hash"], sha(DATA))
        self.assertFalse(self.folders.in_staging("tid-1"))
        self.assertTrue(self.folders.in_outbox("tid-1"))
        self.assertEqual(
            self.folders.outbox_path("tid-1").read_bytes(), DATA)
        self.assertEqual(self.alerts, [])

    def test_move_on_per_request_approval_off_the_default_list(self):
        self.stage(data=OTHER)
        ready, artifact, passed = self.ready_move(data=OTHER)
        record = self.agent.move(ready, artifact, passed)
        self.assertEqual(record["file_hash"], sha(OTHER))
        self.assertTrue(self.folders.in_outbox("tid-1"))
        self.assertEqual(
            self.folders.outbox_path("tid-1").read_bytes(), OTHER)

    def test_duplicate_transfer_ready_after_move_is_ignored(self):
        self.stage()
        ready, artifact, passed = self.ready_move()
        self.agent.move(ready, artifact, passed)
        again = self.agent.move(ready, artifact, passed)
        self.assertIsNone(again)
        self.assertTrue(self.folders.in_outbox("tid-1"))
        self.assertEqual(self.alerts, [])

    def test_moved_file_is_the_checked_file(self):
        self.stage()
        ready, artifact, passed = self.ready_move()
        self.agent.move(ready, artifact, passed)
        self.assertEqual(
            sha(self.folders.outbox_path("tid-1").read_bytes()),
            sha(DATA))


class TransferReadyGateTest(TransferTestCase):
    def test_forged_transfer_ready_is_ignored(self):
        self.stage()
        _, artifact, passed = self.ready_move()
        forged = transfer_ready("tid-1", sha(DATA), artifact)
        forged["staged_hash"] = sha(OTHER)
        result = self.agent.move(forged, artifact, passed)
        self.assertIsNone(result)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertEqual(self.alerts, [])

    def test_transfer_ready_signed_by_another_role_is_ignored(self):
        self.stage()
        _, artifact, passed = self.ready_move()
        ready = {
            "transfer_id": "tid-1",
            "staged_hash": sha(DATA),
            "approval_artifact_hash": artifact_hash(artifact),
        }
        ready = sign_artifact(ready, AGENT_KEY)
        self.assertIsNone(self.agent.move(ready, artifact, passed))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_transfer_ready_for_a_different_artifact_is_ignored(self):
        self.stage()
        _, artifact, passed = self.ready_move()
        other_artifact = approval_artifact("tid-1", sha(DATA),
                                           case_hash="d" * 64)
        ready = transfer_ready("tid-1", sha(DATA), other_artifact)
        self.assertIsNone(self.agent.move(ready, artifact, passed))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertEqual(self.alerts, [])


class FailedCheckTest(TransferTestCase):
    def assert_alerted_and_quarantined(self, trigger):
        self.assertFalse(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertTrue(self.folders.in_quarantine("tid-1"))
        self.assertEqual(len(self.alerts), 1)
        alert = self.alerts[0]
        self.assertEqual(set(alert["to"]), {"manager", "boss"})
        record = alert["record"]
        self.assertEqual(record["transfer_id"], "tid-1")
        self.assertEqual(record["file_hash"], sha(DATA))
        self.assertEqual(record["trigger"], trigger)
        self.assertIsInstance(record["chain_position"], int)
        self.assertTrue(record["record_id"])
        self.assertTrue(verify_artifact(record, AGENT_KEY))

    def test_not_on_either_list_alerts_and_quarantines(self):
        self.stage(data=OTHER)
        artifact = list_artifact("tid-1", sha(OTHER))
        ready = transfer_ready("tid-1", sha(OTHER), artifact)
        passed = gate_pass("tid-1", sha(OTHER))
        with self.assertRaises(TransferRefused) as ctx:
            self.agent.move(ready, artifact, passed)
        self.assertEqual(ctx.exception.trigger, "not_on_lists")
        self.assert_alerted_and_quarantined("not_on_lists")

    def test_not_in_logs_alerts_and_quarantines(self):
        ready, artifact, passed = self.ready_move(
            transfer_id="tid-9")
        self.folders.stage("manager", "tid-9", DATA)
        with self.assertRaises(TransferRefused) as ctx:
            self.agent.move(ready, artifact, passed)
        self.assertEqual(ctx.exception.trigger, "not_in_logs")
        self.assertEqual(len(self.alerts), 1)
        alert = self.alerts[0]
        self.assertEqual(set(alert["to"]), {"manager", "boss"})
        record = alert["record"]
        self.assertEqual(record["trigger"], "not_in_logs")
        self.assertEqual(record["transfer_id"], "tid-9")
        self.assertEqual(record["chain_position"], len(self.log))
        self.assertTrue(self.folders.in_quarantine("tid-9"))
        self.assertFalse(self.folders.in_outbox("tid-9"))

    def test_refusal_artifact_authorizes_no_move(self):
        self.stage()
        artifact = approval_artifact("tid-1", sha(DATA),
                                     decision="refuse")
        ready = transfer_ready("tid-1", sha(DATA), artifact)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact,
                            gate_pass("tid-1", sha(DATA)))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertEqual(self.alerts, [])

    def test_missing_approval_artifact_authorizes_no_move(self):
        self.stage()
        ready = transfer_ready("tid-1", sha(DATA), None)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, None, gate_pass("tid-1", sha(DATA)))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_stale_list_version_refuses_the_move(self):
        self.stage()
        artifact = list_artifact("tid-1", sha(DATA), version=2)
        ready = transfer_ready("tid-1", sha(DATA), artifact)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact,
                            gate_pass("tid-1", sha(DATA)))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_tampered_staged_bytes_refuse_the_move(self):
        path = self.stage()
        ready, artifact, passed = self.ready_move()
        path.write_bytes(OTHER)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertEqual(self.alerts, [])

    def test_missing_gate_pass_refuses_the_move(self):
        self.stage()
        ready, artifact, _ = self.ready_move()
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact, None)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_gate_pass_bound_to_another_file_refuses(self):
        self.stage()
        ready, artifact, _ = self.ready_move()
        passed = gate_pass("tid-1", sha(OTHER))
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_gate_pass_signed_by_the_manager_refuses(self):
        self.stage()
        ready, artifact, _ = self.ready_move()
        passed = {
            "pass_id": "pass-1",
            "transfer_id": "tid-1",
            "staged_hash": sha(DATA),
            "expiry": 900,
        }
        passed = sign_artifact(passed, MANAGER_KEY)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_spent_gate_pass_cannot_move_a_second_transfer(self):
        self.stage()
        ready, artifact, passed = self.ready_move()
        self.agent.move(ready, artifact, passed)
        self.folders.stage("manager", "tid-2", DATA)
        artifact2 = approval_artifact("tid-2", sha(DATA))
        ready2 = transfer_ready("tid-2", sha(DATA), artifact2)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready2, artifact2, passed)
        self.assertTrue(self.folders.in_staging("tid-2"))
        self.assertFalse(self.folders.in_outbox("tid-2"))


class SlowChecker:
    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()

    def matches(self, data):
        self.entered.set()
        self.release.wait(10)
        return False


class SingleFlightTest(TransferTestCase):
    def test_concurrent_move_for_same_id_is_refused(self):
        slow = SlowChecker()
        self.folders.spoiler_checker = slow
        self.stage()
        ready, artifact, passed = self.ready_move()
        outcome = {}

        def run_move():
            try:
                outcome["record"] = self.agent.move(
                    ready, artifact, passed)
            except TransferError as exc:
                outcome["error"] = exc

        worker = threading.Thread(target=run_move)
        worker.start()
        self.assertTrue(slow.entered.wait(5))
        with self.assertRaises(TransferInProgress):
            self.agent.move(ready, artifact, passed)
        slow.release.set()
        worker.join(5)
        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["record"]["transfer_id"], "tid-1")
        self.assertTrue(self.folders.in_outbox("tid-1"))
        self.assertEqual(
            self.folders.outbox_path("tid-1").read_bytes(), DATA)


class FolderTwoSpoilerTest(TransferTestCase):
    def test_spoiler_match_at_folder_2_entry_trips_and_quarantines(
            self):
        self.stage()
        self.checker.hashes.add(sha(DATA))
        ready, artifact, passed = self.ready_move()
        with self.assertRaises(KillSwitchTripped):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.kill_switch.tripped)
        self.assertEqual(self.kill_switch.reason, "spoiler")
        self.assertFalse(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertTrue(self.folders.in_quarantine("tid-1"))

    def test_checker_failure_at_move_fails_closed(self):
        class RaisingChecker:
            def matches(self, data):
                raise RuntimeError("checker died")

        self.stage()
        self.folders.spoiler_checker = RaisingChecker()
        ready, artifact, passed = self.ready_move()
        with self.assertRaises(CheckerFailure):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertFalse(self.kill_switch.tripped)

    def test_checker_unavailable_at_move_fails_closed(self):
        self.stage()
        self.folders.spoiler_checker = None
        ready, artifact, passed = self.ready_move()
        with self.assertRaises(CheckerUnavailable):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))
        self.assertFalse(self.kill_switch.tripped)


class KillSwitchTest(TransferTestCase):
    def trip_with_spoiler(self):
        self.checker.hashes.add(sha(OTHER))
        self.folders.stage("manager", "tid-x", OTHER)

    def test_tripped_switch_blocks_further_moves(self):
        self.trip_with_spoiler()
        self.stage()
        ready, artifact, passed = self.ready_move()
        with self.assertRaises(ConnectionSevered):
            self.agent.move(ready, artifact, passed)
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_agent_cannot_reset_the_switch(self):
        self.trip_with_spoiler()
        for signer in ("manager", "boss", "transfer-agent"):
            with self.subTest(signer=signer):
                with self.assertRaises(TransferError):
                    self.kill_switch.reset(signed_by=signer)
        self.assertTrue(self.kill_switch.tripped)

    def test_human_reset_restores_moves(self):
        self.trip_with_spoiler()
        self.kill_switch.reset(signed_by="human")
        self.assertFalse(self.kill_switch.tripped)
        self.stage()
        ready, artifact, passed = self.ready_move()
        record = self.agent.move(ready, artifact, passed)
        self.assertEqual(record["transfer_id"], "tid-1")
        self.assertTrue(self.folders.in_outbox("tid-1"))


class AbsoluteTrustTest(TransferTestCase):
    def make_trust_agent(self, cap=1024):
        return self.make_agent(
            absolute_trust=True,
            agreement={"agreement_id": "agr-1",
                       "roots": ["notes"],
                       "daily_byte_cap": cap})

    def test_agreement_move_needs_no_list_membership(self):
        agent = self.make_trust_agent()
        self.stage(data=OTHER)
        artifact = agreement_artifact("tid-1", sha(OTHER))
        ready = transfer_ready("tid-1", sha(OTHER), artifact)
        record = agent.move(ready, artifact,
                            gate_pass("tid-1", sha(OTHER)))
        self.assertEqual(record["file_hash"], sha(OTHER))
        self.assertTrue(self.folders.in_outbox("tid-1"))

    def test_agreement_basis_without_trust_mode_refuses(self):
        self.stage(data=OTHER)
        artifact = agreement_artifact("tid-1", sha(OTHER))
        ready = transfer_ready("tid-1", sha(OTHER), artifact)
        with self.assertRaises(TransferRefused):
            self.agent.move(ready, artifact,
                            gate_pass("tid-1", sha(OTHER)))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_daily_cap_exceeded_refuses_the_move(self):
        agent = self.make_trust_agent(cap=len(DATA) - 1)
        self.stage()
        artifact = agreement_artifact("tid-1", sha(DATA))
        ready = transfer_ready("tid-1", sha(DATA), artifact)
        with self.assertRaises(TransferRefused):
            agent.move(ready, artifact, gate_pass("tid-1", sha(DATA)))
        self.assertTrue(self.folders.in_staging("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))

    def test_spoiler_trips_even_under_absolute_trust(self):
        agent = self.make_trust_agent()
        self.stage(data=OTHER)
        self.checker.hashes.add(sha(OTHER))
        artifact = agreement_artifact("tid-1", sha(OTHER))
        ready = transfer_ready("tid-1", sha(OTHER), artifact)
        with self.assertRaises(KillSwitchTripped):
            agent.move(ready, artifact, gate_pass("tid-1", sha(OTHER)))
        self.assertTrue(self.kill_switch.tripped)
        self.assertTrue(self.folders.in_quarantine("tid-1"))
        self.assertFalse(self.folders.in_outbox("tid-1"))


if __name__ == "__main__":
    unittest.main()
