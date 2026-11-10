"""Tests for guard.ed25519 — the pure-Python Ed25519 (RFC 8032)
implementation the guard's signatures now stand on.

The known-answer vectors are implementation-independent: they were
produced and cross-checked against a reference Ed25519
implementation, so they pin the math, not this code's habits.
"""
import unittest

from guard import ed25519

SEED = bytes(range(32))
PUBLIC = bytes.fromhex(
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
SIG_BRIDGE_GUARD = bytes.fromhex(
    "00ee37792772f6d60796ec8d9ac073d66d42edf85f019f3f7b7220f1a2a800ee"
    "869583165f9c478128f1b4328efb8db09ae8808b1894cba49f23467ee472c405")
SEED2 = bytes([255] * 32)
PUBLIC2 = bytes.fromhex(
    "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5")
SIG_EMPTY = bytes.fromhex(
    "ee00ac6e44a6a43bc3a701c137b467473e32a4bed47d3293fe6186fe9868c7d2"
    "54024f65ffa552487bdbd34aaccd1e82c1a20a191d183dbb64c3523cccd89c0f")


class KnownAnswerTest(unittest.TestCase):
    def test_publickey_matches_reference(self):
        self.assertEqual(ed25519.publickey(SEED), PUBLIC)
        self.assertEqual(ed25519.publickey(SEED2), PUBLIC2)

    def test_sign_matches_reference(self):
        self.assertEqual(ed25519.sign(SEED, b"bridge-guard"),
                         SIG_BRIDGE_GUARD)
        self.assertEqual(ed25519.sign(SEED2, b""), SIG_EMPTY)

    def test_verify_accepts_reference_signatures(self):
        self.assertTrue(
            ed25519.verify(PUBLIC, b"bridge-guard", SIG_BRIDGE_GUARD))
        self.assertTrue(ed25519.verify(PUBLIC2, b"", SIG_EMPTY))


class BehaviourTest(unittest.TestCase):
    def test_roundtrip(self):
        seed = bytes(range(32, 64))
        public = ed25519.publickey(seed)
        sig = ed25519.sign(seed, b"payload")
        self.assertTrue(ed25519.verify(public, b"payload", sig))

    def test_tampered_message_fails(self):
        public = ed25519.publickey(SEED)
        self.assertFalse(
            ed25519.verify(public, b"bridge-guard!", SIG_BRIDGE_GUARD))

    def test_tampered_signature_fails(self):
        bad = bytearray(SIG_BRIDGE_GUARD)
        bad[10] ^= 1
        self.assertFalse(
            ed25519.verify(PUBLIC, b"bridge-guard", bytes(bad)))

    def test_wrong_key_fails(self):
        self.assertFalse(
            ed25519.verify(PUBLIC2, b"bridge-guard", SIG_BRIDGE_GUARD))

    def test_public_key_cannot_sign(self):
        # The C1/C2 defect class: material published as a public key
        # must be useless for producing signatures. Treating the
        # public bytes as a seed yields a different key entirely.
        forged = ed25519.sign(PUBLIC, b"bridge-guard")
        self.assertFalse(ed25519.verify(PUBLIC, b"bridge-guard", forged))

    def test_malformed_inputs_fail_closed(self):
        self.assertFalse(ed25519.verify(b"short", b"m", SIG_BRIDGE_GUARD))
        self.assertFalse(ed25519.verify(PUBLIC, b"m", b"short"))
        self.assertFalse(ed25519.verify(PUBLIC, b"m", b"\xff" * 64))
        self.assertFalse(ed25519.verify(b"\xff" * 32, b"m",
                                         SIG_BRIDGE_GUARD))

    def test_seed_length_enforced(self):
        with self.assertRaises(ValueError):
            ed25519.publickey(b"short")
        with self.assertRaises(ValueError):
            ed25519.sign(b"short", b"m")


if __name__ == "__main__":
    unittest.main()
