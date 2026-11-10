"""Tests for guard.roles: role certificates, role and pair key
rotation, and absolute trust (DESIGN sections 2, 4.5, 10, 12,
Appendix B.2)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.roles import (
    PairKeys,
    RoleRegistry,
    TrustBook,
    countersign_agreement,
    generate_keypair,
    make_agreement,
    make_certificate,
    may,
    pair_hash,
    sign,
)


def envelope(kp, **msg):
    return {"msg": msg, "sig": sign(kp.secret, msg), "signer": kp.public}


def introduction(pair, new_keys, keypairs, epoch=None):
    body = {
        "new_keys": list(new_keys),
        "extends_epoch": pair.epoch + 1 if epoch is None else epoch,
        "current_key_hash": pair.current_hash(),
    }
    sigs = [sign(kp.secret, body) for kp in keypairs]
    return dict(body, sigs=sigs)


class CertificateTest(unittest.TestCase):
    def setUp(self):
        self.master = generate_keypair()
        self.registry = RoleRegistry(self.master.public)
        self.node = generate_keypair()

    def test_master_signed_certificate_registers(self):
        cert = make_certificate(self.master.secret, "node-1", "manager",
                                self.node.public)
        self.assertTrue(self.registry.add_certificate(cert))
        self.assertEqual(self.registry.role_for(self.node.public),
                         "manager")

    def test_self_signed_certificate_rejected(self):
        cert = make_certificate(self.node.secret, "node-1", "manager",
                                self.node.public)
        self.assertFalse(self.registry.add_certificate(cert))
        self.assertIsNone(self.registry.role_for(self.node.public))

    def test_certificate_from_another_issuer_rejected(self):
        stranger = generate_keypair()
        cert = make_certificate(stranger.secret, "node-1", "owner",
                                self.node.public)
        self.assertFalse(self.registry.add_certificate(cert))
        self.assertIsNone(self.registry.role_for(self.node.public))

    def test_tampered_certificate_rejected(self):
        cert = make_certificate(self.master.secret, "node-1", "worker",
                                self.node.public)
        cert["role"] = "owner"
        self.assertFalse(self.registry.add_certificate(cert))
        self.assertIsNone(self.registry.role_for(self.node.public))

    def test_standalone_human_issued_certificate_registers(self):
        human = generate_keypair()
        registry = RoleRegistry(human.public)
        cert = make_certificate(human.secret, "node-1", "scanner",
                                self.node.public)
        self.assertTrue(registry.add_certificate(cert))
        self.assertEqual(registry.role_for(self.node.public), "scanner")

    def test_master_signed_role_change_takes_effect(self):
        first = make_certificate(self.master.secret, "node-1", "worker",
                                 self.node.public, epoch=0)
        second = make_certificate(self.master.secret, "node-1", "owner",
                                  self.node.public, epoch=1)
        self.assertTrue(self.registry.add_certificate(first))
        self.assertTrue(self.registry.add_certificate(second))
        self.assertEqual(self.registry.role_for(self.node.public),
                         "owner")

    def test_unsigned_role_change_has_no_effect(self):
        attacker = generate_keypair()
        first = make_certificate(self.master.secret, "node-1", "worker",
                                 self.node.public, epoch=0)
        forged = make_certificate(attacker.secret, "node-1", "owner",
                                  self.node.public, epoch=1)
        self.assertTrue(self.registry.add_certificate(first))
        self.assertFalse(self.registry.add_certificate(forged))
        self.assertEqual(self.registry.role_for(self.node.public),
                         "worker")

    def test_stale_certificate_does_not_replace_newer(self):
        stale = make_certificate(self.master.secret, "node-1", "worker",
                                 self.node.public, epoch=0)
        current = make_certificate(self.master.secret, "node-1", "owner",
                                   self.node.public, epoch=1)
        self.assertTrue(self.registry.add_certificate(current))
        self.assertFalse(self.registry.add_certificate(stale))
        self.assertEqual(self.registry.role_for(self.node.public),
                         "owner")


class EnvelopeVerificationTest(unittest.TestCase):
    def setUp(self):
        self.master = generate_keypair()
        self.registry = RoleRegistry(self.master.public)
        self.manager = generate_keypair()
        self.worker = generate_keypair()
        self.registry.add_certificate(make_certificate(
            self.master.secret, "node-1", "manager", self.manager.public))
        self.registry.add_certificate(make_certificate(
            self.master.secret, "node-2", "worker", self.worker.public))

    def test_certified_signer_verifies_under_its_role(self):
        env = envelope(self.manager, kind="note", text="staged")
        self.assertEqual(self.registry.verify_envelope(env), "manager")

    def test_certificate_governs_over_claimed_role(self):
        env = envelope(self.manager, kind="note", role="slave")
        self.assertEqual(self.registry.verify_envelope(env), "manager")

    def test_uncertified_role_claim_is_unapproved(self):
        stranger = generate_keypair()
        env = envelope(stranger, kind="note", role="manager")
        self.assertIsNone(self.registry.verify_envelope(env))
        self.assertFalse(self.registry.authorize(env, "result"))

    def test_bad_signature_does_not_verify(self):
        stranger = generate_keypair()
        env = envelope(self.manager, kind="note", text="staged")
        env["sig"] = sign(stranger.secret, env["msg"])
        self.assertIsNone(self.registry.verify_envelope(env))

    def test_unsigned_envelope_does_not_verify(self):
        env = {"msg": {"kind": "note"}, "sig": "",
               "signer": self.manager.public}
        self.assertIsNone(self.registry.verify_envelope(env))

    def test_tampered_message_does_not_verify(self):
        env = envelope(self.worker, kind="result", text="done")
        env["msg"]["text"] = "send the file"
        self.assertIsNone(self.registry.verify_envelope(env))


class CapabilityTest(unittest.TestCase):
    def setUp(self):
        self.master = generate_keypair()
        self.registry = RoleRegistry(self.master.public)
        self.keys = {}
        for role in ("owner", "worker", "asker", "slave"):
            kp = generate_keypair()
            self.keys[role] = kp
            self.registry.add_certificate(make_certificate(
                self.master.secret, "node-" + role, role, kp.public))

    def attempt(self, role, action):
        env = envelope(self.keys[role], kind=action)
        return self.registry.authorize(env, action)

    def test_slave_returns_results(self):
        self.assertTrue(self.attempt("slave", "result"))

    def test_slave_cannot_send_tasks_prompts_or_messages(self):
        self.assertFalse(self.attempt("slave", "task"))
        self.assertFalse(self.attempt("slave", "prompt"))
        self.assertFalse(self.attempt("slave", "message"))

    def test_asker_can_ask_but_cannot_send_tasks(self):
        self.assertTrue(self.attempt("asker", "prompt"))
        self.assertFalse(self.attempt("asker", "task"))

    def test_worker_returns_results_but_cannot_send_tasks(self):
        self.assertTrue(self.attempt("worker", "result"))
        self.assertFalse(self.attempt("worker", "task"))

    def test_owner_may_send_anything(self):
        for action in ("task", "prompt", "message", "result"):
            self.assertTrue(self.attempt("owner", action))

    def test_may_denies_unknown_and_absent_roles(self):
        self.assertFalse(may("no-such-role", "result"))
        self.assertFalse(may(None, "result"))
        self.assertTrue(may("slave", "result"))
        self.assertFalse(may("slave", "task"))


class RoleKeyRotationTest(unittest.TestCase):
    def setUp(self):
        self.master = generate_keypair()
        self.registry = RoleRegistry(self.master.public)
        self.old = generate_keypair()
        self.new = generate_keypair()
        self.registry.add_certificate(make_certificate(
            self.master.secret, "node-1", "manager", self.old.public,
            epoch=0))
        self.payload = {"kind": "approve", "transfer_id": "t-1"}

    def rotate(self, signer, epoch):
        body = {"subject": "node-1", "new_public": self.new.public,
                "epoch": epoch}
        return self.registry.rotate_role_key(
            "node-1", self.new.public, epoch, sign(signer.secret, body))

    def test_rotation_signed_by_standing_key(self):
        self.assertTrue(self.rotate(self.old, 1))
        self.assertEqual(self.registry.role_for(self.new.public),
                         "manager")
        self.assertIsNone(self.registry.role_for(self.old.public))

    def test_rotation_with_wrong_epoch_rejected(self):
        self.assertFalse(self.rotate(self.old, 2))
        self.assertEqual(self.registry.role_for(self.old.public),
                         "manager")

    def test_rotation_signed_by_another_key_rejected(self):
        stranger = generate_keypair()
        self.assertFalse(self.rotate(stranger, 1))
        self.assertIsNone(self.registry.role_for(self.new.public))

    def test_replayed_rotation_rejected(self):
        self.assertTrue(self.rotate(self.old, 1))
        self.assertFalse(self.rotate(self.old, 1))

    def test_artifacts_verify_in_the_epoch_they_were_signed(self):
        old_sig = sign(self.old.secret, self.payload)
        self.assertTrue(self.registry.verify_artifact(
            self.old.public, self.payload, old_sig, 0))
        self.assertTrue(self.rotate(self.old, 1))
        self.assertTrue(self.registry.verify_artifact(
            self.old.public, self.payload, old_sig, 0))
        self.assertFalse(self.registry.verify_artifact(
            self.old.public, self.payload, old_sig, 1))
        new_sig = sign(self.new.secret, self.payload)
        self.assertTrue(self.registry.verify_artifact(
            self.new.public, self.payload, new_sig, 1))
        self.assertFalse(self.registry.verify_artifact(
            self.new.public, self.payload, new_sig, 0))

    def test_revoked_key_stops_verifying_from_revocation_epoch(self):
        sig = sign(self.old.secret, self.payload)
        self.registry.revoke_key(self.old.public, 2)
        self.assertTrue(self.registry.verify_artifact(
            self.old.public, self.payload, sig, 1))
        self.assertFalse(self.registry.verify_artifact(
            self.old.public, self.payload, sig, 2))
        self.assertFalse(self.registry.verify_artifact(
            self.old.public, self.payload, sig, 5))
        self.assertIsNone(self.registry.role_for(self.old.public))

    def test_revoking_an_archived_key_bounds_its_history(self):
        sig = sign(self.old.secret, self.payload)
        self.assertTrue(self.rotate(self.old, 1))
        self.assertTrue(self.registry.verify_artifact(
            self.old.public, self.payload, sig, 0))
        self.registry.revoke_key(self.old.public, 0)
        self.assertFalse(self.registry.verify_artifact(
            self.old.public, self.payload, sig, 0))


class PairRotationTest(unittest.TestCase):
    def setUp(self):
        self.a = generate_keypair()
        self.b = generate_keypair()
        self.pair = PairKeys("agent-b", self.a.public, self.b.public)

    def test_pair_starts_at_epoch_zero_with_both_keys(self):
        self.assertEqual(self.pair.epoch, 0)
        self.assertEqual(self.pair.keys, (self.a.public, self.b.public))
        self.assertTrue(self.pair.is_current(self.a.public))
        self.assertFalse(self.pair.broken)

    def test_co_signed_rotation_replaces_one_key(self):
        c = generate_keypair()
        intro = introduction(self.pair, [self.a.public, c.public],
                             [self.a, self.b])
        self.assertEqual(self.pair.rotate(intro), "applied")
        self.assertEqual(self.pair.keys, (self.a.public, c.public))
        self.assertEqual(self.pair.epoch, 1)

    def test_rotations_chain_one_key_at_a_time(self):
        c = generate_keypair()
        d = generate_keypair()
        first = introduction(self.pair, [c.public, self.b.public],
                             [self.a, self.b])
        self.assertEqual(self.pair.rotate(first), "applied")
        second = introduction(self.pair, [c.public, d.public],
                              [c, self.b])
        self.assertEqual(self.pair.rotate(second), "applied")
        self.assertEqual(self.pair.keys, (c.public, d.public))
        self.assertEqual(self.pair.epoch, 2)

    def test_replayed_rotation_is_rejected(self):
        c = generate_keypair()
        intro = introduction(self.pair, [self.a.public, c.public],
                             [self.a, self.b])
        self.assertEqual(self.pair.rotate(intro), "applied")
        self.assertEqual(self.pair.rotate(intro), "inert")
        self.assertEqual(self.pair.keys, (self.a.public, c.public))
        self.assertEqual(self.pair.epoch, 1)

    def test_skipped_epoch_is_inert(self):
        c = generate_keypair()
        intro = introduction(self.pair, [self.a.public, c.public],
                             [self.a, self.b], epoch=3)
        self.assertEqual(self.pair.rotate(intro), "inert")
        self.assertEqual(self.pair.epoch, 0)

    def test_stale_key_hash_is_inert(self):
        c = generate_keypair()
        intro = introduction(self.pair, [self.a.public, c.public],
                             [self.a, self.b])
        intro["current_key_hash"] = pair_hash(c.public, c.public)
        intro["sigs"] = [sign(kp.secret, {k: v for k, v in intro.items()
                                          if k != "sigs"})
                         for kp in (self.a, self.b)]
        self.assertEqual(self.pair.rotate(intro), "inert")
        self.assertEqual(self.pair.epoch, 0)

    def test_single_signature_rotation_is_inert(self):
        c = generate_keypair()
        intro = introduction(self.pair, [self.a.public, c.public],
                             [self.a, self.b])
        intro["sigs"] = intro["sigs"][:1]
        self.assertEqual(self.pair.rotate(intro), "inert")
        self.assertEqual(self.pair.keys, (self.a.public, self.b.public))

    def test_swapped_signatures_are_inert(self):
        c = generate_keypair()
        intro = introduction(self.pair, [self.a.public, c.public],
                             [self.a, self.b])
        intro["sigs"] = list(reversed(intro["sigs"]))
        self.assertEqual(self.pair.rotate(intro), "inert")

    def test_forged_introduction_is_inert_and_breaks_nothing(self):
        x = generate_keypair()
        y = generate_keypair()
        intro = introduction(self.pair, [self.a.public, x.public],
                             [x, y])
        self.assertEqual(self.pair.rotate(intro), "inert")
        self.assertFalse(self.pair.broken)
        self.assertEqual(self.pair.keys, (self.a.public, self.b.public))

    def test_changing_both_keys_at_once_is_a_violation(self):
        x = generate_keypair()
        y = generate_keypair()
        intro = introduction(self.pair, [x.public, y.public],
                             [self.a, self.b])
        self.assertEqual(self.pair.rotate(intro), "violation")
        self.assertTrue(self.pair.broken)
        self.assertEqual(self.pair.keys, (self.a.public, self.b.public))

    def test_collapsing_the_pair_to_one_key_is_a_violation(self):
        intro = introduction(self.pair,
                             [self.a.public, self.a.public],
                             [self.a, self.b])
        self.assertEqual(self.pair.rotate(intro), "violation")
        self.assertTrue(self.pair.broken)

    def test_revoking_a_current_key_freezes_the_pair(self):
        self.assertTrue(self.pair.revoke(self.a.public))
        self.assertTrue(self.pair.frozen)
        self.assertFalse(self.pair.is_current(self.a.public))

    def test_revoking_an_unknown_key_freezes_nothing(self):
        stranger = generate_keypair()
        self.assertFalse(self.pair.revoke(stranger.public))
        self.assertFalse(self.pair.frozen)


class AbsoluteTrustTest(unittest.TestCase):
    def setUp(self):
        self.a = generate_keypair()
        self.b = generate_keypair()
        self.local_human = generate_keypair()
        self.remote_human = generate_keypair()
        self.deputy = generate_keypair()
        self.now = 1_000_000

    def make_book(self, cap=1000, expiry=100000, cooling_off_s=10):
        pair = PairKeys("agent-b", self.a.public, self.b.public)
        book = TrustBook(pair, self.local_human.public,
                         self.remote_human.public,
                         cooling_off_s=cooling_off_s)
        return pair, book

    def agreement(self, proposer, countersigner, cap=1000,
                  expiry=100000):
        agr = make_agreement("agr-1", "fp-1", ["notes/"], cap, expiry,
                             proposer.secret)
        if countersigner is not None:
            agr = countersign_agreement(agr, countersigner.secret)
        return agr

    def activated(self, cap=1000, expiry=100000, cooling_off_s=10):
        pair, book = self.make_book(cap, expiry, cooling_off_s)
        agr = self.agreement(self.local_human, self.remote_human,
                             cap, expiry)
        self.assertTrue(book.activate(agr, self.now))
        return pair, book

    def test_off_by_default(self):
        pair, book = self.make_book()
        self.assertFalse(book.is_active(self.now))

    def test_pending_agreement_does_not_activate(self):
        pair, book = self.make_book()
        agr = self.agreement(self.local_human, None)
        self.assertFalse(book.activate(agr, self.now))
        self.assertFalse(book.is_active(self.now + 100))

    def test_counterpart_and_deputy_signatures_do_not_activate(self):
        pair, book = self.make_book()
        agr = self.agreement(self.remote_human, self.deputy)
        self.assertFalse(book.activate(agr, self.now))
        self.assertFalse(book.is_active(self.now + 100))

    def test_deputy_cannot_countersign_trust_on(self):
        pair, book = self.make_book()
        agr = self.agreement(self.local_human, self.deputy)
        self.assertFalse(book.activate(agr, self.now))
        self.assertFalse(book.is_active(self.now + 100))

    def test_both_humans_activate_after_cooling_off(self):
        pair, book = self.activated(cooling_off_s=10)
        self.assertFalse(book.is_active(self.now))
        self.assertFalse(book.is_active(self.now + 9))
        self.assertTrue(book.is_active(self.now + 10))

    def test_activation_is_logged_with_who_and_for_whom(self):
        pair, book = self.activated()
        events = [e for e in book.events if e["type"] == "trust-on"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["counterpart"], "agent-b")
        self.assertEqual(events[0]["by"], self.local_human.public)
        self.assertEqual(events[0]["agreement_id"], "agr-1")

    def test_trust_expires(self):
        pair, book = self.activated(expiry=100, cooling_off_s=10)
        self.assertTrue(book.is_active(self.now + 50))
        self.assertFalse(book.is_active(self.now + 500))

    def test_daily_cap_trips_trust_until_a_human_reconfirms(self):
        pair, book = self.activated(cap=100, cooling_off_s=0)
        t = self.now
        self.assertTrue(book.record_send(60, t))
        self.assertFalse(book.record_send(50, t))
        self.assertFalse(book.is_active(t))
        self.assertFalse(book.record_send(10, t))
        book.reconfirm(t)
        self.assertTrue(book.is_active(t))
        self.assertTrue(book.record_send(10, t))

    def test_daily_totals_reset_the_next_day(self):
        pair, book = self.activated(cap=100, cooling_off_s=0)
        self.assertTrue(book.record_send(60, self.now))
        self.assertTrue(book.record_send(60, self.now + 86400))

    def test_turn_off_restores_the_full_gate_immediately(self):
        pair, book = self.activated(cooling_off_s=0)
        self.assertTrue(book.is_active(self.now))
        book.turn_off(self.now)
        self.assertFalse(book.is_active(self.now))
        events = [e for e in book.events if e["type"] == "trust-off"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["counterpart"], "agent-b")

    def test_routine_rotation_keeps_trust(self):
        pair, book = self.activated(cooling_off_s=0)
        c = generate_keypair()
        intro = introduction(pair, [self.a.public, c.public],
                             [self.a, self.b])
        self.assertEqual(pair.rotate(intro), "applied")
        self.assertTrue(book.is_active(self.now))

    def test_rule_breaking_key_change_disables_trust(self):
        pair, book = self.activated(cooling_off_s=0)
        x = generate_keypair()
        y = generate_keypair()
        intro = introduction(pair, [x.public, y.public],
                             [self.a, self.b])
        self.assertEqual(pair.rotate(intro), "violation")
        self.assertFalse(book.is_active(self.now))

    def test_revoked_pair_key_disables_trust(self):
        pair, book = self.activated(cooling_off_s=0)
        self.assertTrue(pair.revoke(self.b.public))
        self.assertFalse(book.is_active(self.now))

    def test_trust_is_per_counterpart(self):
        pair, book = self.activated(cooling_off_s=0)
        other_pair = PairKeys("agent-c", self.a.public, self.b.public)
        other = TrustBook(other_pair, self.local_human.public,
                          self.remote_human.public, cooling_off_s=0)
        self.assertTrue(book.is_active(self.now))
        self.assertFalse(other.is_active(self.now))


class PublicKeyCannotSignTest(unittest.TestCase):
    """Regression for audit C1 / break-it A1: a published "public"
    key must carry no signing power. Before the Ed25519 swap the
    public token was the HMAC secret with its prefix changed, and
    every one of these forgeries succeeded."""

    def test_certificate_forged_from_the_public_key_is_rejected(self):
        master = generate_keypair()
        registry = RoleRegistry(master.public)
        attacker = generate_keypair()
        stripped = master.public.split("-", 1)[1]
        for guess in ("sk-" + stripped, master.public, stripped):
            cert = make_certificate(guess, "node-1", "master",
                                    attacker.public)
            self.assertFalse(registry.add_certificate(cert), guess)
        self.assertIsNone(registry.role_for(attacker.public))

    def test_envelope_forged_from_the_public_key_is_rejected(self):
        master = generate_keypair()
        registry = RoleRegistry(master.public)
        node = generate_keypair()
        cert = make_certificate(master.secret, "node-1", "worker",
                                node.public)
        self.assertTrue(registry.add_certificate(cert))
        stripped = node.public.split("-", 1)[1]
        forged = {"msg": {"kind": "task"},
                  "sig": sign("sk-" + stripped, {"kind": "task"}),
                  "signer": node.public}
        self.assertIsNone(registry.verify_envelope(forged))
        self.assertFalse(registry.authorize(forged, "task"))

    def test_public_and_secret_are_distinct_material(self):
        kp = generate_keypair()
        self.assertNotEqual(kp.secret.split("-", 1)[1],
                            kp.public.split("-", 1)[1])


if __name__ == "__main__":
    unittest.main()
