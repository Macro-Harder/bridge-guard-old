"""Tests for guard.manifest: the configuration handshake.

Two sides declare a format version, a design revision, a strictness
level, and their manifest values. The version checker refuses the
connection on a version or revision mismatch, the connection and the
transfer run at one shared level (the stricter of the two picks), and
side-local settings stay at each side's own level.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.manifest import (
    DESIGN_REVISION,
    SUPPORTED_FORMAT_VERSIONS,
    ConnectionManifest,
    HandshakeRefused,
    LevelMismatch,
    ManifestError,
    SideDeclaration,
    VersionMismatch,
    agree,
    build_manifest_object,
    resolve_shared_level,
)

REVISION = "bg-2026-11-08.13"


def decl(side="agent-a", **over):
    base = {"side": side, "format_version": 1,
            "design_revision": REVISION, "level": 5}
    base.update(over)
    return SideDeclaration(**base)


class SharedLevelTest(unittest.TestCase):
    def test_equal_picks_agree_at_that_level(self):
        m = agree(decl(level=4), decl(side="agent-b", level=4))
        self.assertIsInstance(m, ConnectionManifest)
        self.assertEqual(m.shared_level, 4)

    def test_stricter_pick_governs(self):
        m = agree(decl(level=3), decl(side="agent-b", level=7))
        self.assertEqual(m.shared_level, 7)

    def test_shared_level_is_symmetric(self):
        a = decl(level=2)
        b = decl(side="agent-b", level=9)
        self.assertEqual(agree(a, b).shared_level,
                         agree(b, a).shared_level)

    def test_shared_level_for_all_pairs(self):
        for low in range(12):
            for high in range(low, 12):
                with self.subTest(low=low, high=high):
                    m = agree(decl(level=low),
                              decl(side="agent-b", level=high))
                    self.assertEqual(m.shared_level, high)

    def test_connection_and_transfer_share_one_level(self):
        m = agree(decl(level=1), decl(side="agent-b", level=10))
        self.assertEqual(m.shared_level, 10)
        self.assertEqual(m.local_level, 1)
        self.assertEqual(m.remote_level, 10)

    def test_resolve_shared_level_picks_stricter(self):
        self.assertEqual(resolve_shared_level(0, 0), 0)
        self.assertEqual(resolve_shared_level(11, 4), 11)
        self.assertEqual(resolve_shared_level(6, 6), 6)

    def test_resolve_shared_level_rejects_out_of_range(self):
        with self.assertRaises(ManifestError):
            resolve_shared_level(12, 3)
        with self.assertRaises(ManifestError):
            resolve_shared_level(3, -1)


class VersionCheckTest(unittest.TestCase):
    def test_matching_version_and_revision_agree(self):
        m = agree(decl(), decl(side="agent-b"))
        self.assertEqual(m.format_version, 1)
        self.assertEqual(m.design_revision, REVISION)

    def test_design_revision_constant_matches_document(self):
        self.assertEqual(DESIGN_REVISION, REVISION)
        self.assertIn(1, SUPPORTED_FORMAT_VERSIONS)

    def test_format_version_mismatch_refused(self):
        with self.assertRaises(VersionMismatch):
            agree(decl(format_version=1),
                  decl(side="agent-b", format_version=2))

    def test_unsupported_version_refused_even_when_both_match(self):
        with self.assertRaises(VersionMismatch):
            agree(decl(format_version=2),
                  decl(side="agent-b", format_version=2))

    def test_design_revision_mismatch_refused(self):
        with self.assertRaises(VersionMismatch):
            agree(decl(design_revision="bg-2026-11-08.12"),
                  decl(side="agent-b"))

    def test_level_mismatch_and_version_mismatch_share_a_surface(self):
        self.assertTrue(issubclass(LevelMismatch, HandshakeRefused))
        self.assertTrue(issubclass(VersionMismatch, HandshakeRefused))

    def test_version_failure_is_not_a_level_failure(self):
        with self.assertRaises(HandshakeRefused) as ctx:
            agree(decl(format_version=1),
                  decl(side="agent-b", format_version=2))
        self.assertIsInstance(ctx.exception, VersionMismatch)
        self.assertNotIsInstance(ctx.exception, LevelMismatch)

    def test_version_refusal_despite_levels_far_apart(self):
        with self.assertRaises(VersionMismatch):
            agree(decl(level=1, format_version=1),
                  decl(side="agent-b", level=11, format_version=2))


class SideLocalSettingsTest(unittest.TestCase):
    def test_per_side_field_stays_local(self):
        m = agree(decl(values={"receipt_ask_delay_s": 600}),
                  decl(side="agent-b"))
        self.assertEqual(m.local_values["receipt_ask_delay_s"], 600)
        self.assertEqual(m.remote_values["receipt_ask_delay_s"], 300)

    def test_per_side_difference_never_refuses(self):
        m = agree(decl(values={"staging_slots": 2}),
                  decl(side="agent-b", values={"staging_slots": 9}))
        self.assertEqual(m.local_values["staging_slots"], 2)
        self.assertEqual(m.remote_values["staging_slots"], 9)

    def test_local_values_carry_shipped_defaults(self):
        m = agree(decl(), decl(side="agent-b"))
        self.assertEqual(m.local_values["size_cap_bytes"], 10485760)
        self.assertEqual(m.local_values["gate_pass_expiry_s"], 900)
        self.assertIs(m.local_values["manager_review_enabled"], True)
        self.assertIs(m.local_values["fast_path_enabled"], True)

    def test_absolute_trust_posture_flag_is_per_side(self):
        m = agree(decl(values={"absolute_trust_enabled": True}),
                  decl(side="agent-b"))
        self.assertIs(m.local_values["absolute_trust_enabled"], True)
        self.assertIs(m.remote_values["absolute_trust_enabled"], False)
        self.assertIs(m.absolute_trust_active, False)


class GoverningValuesTest(unittest.TestCase):
    def test_lower_cap_governs(self):
        m = agree(decl(values={"size_cap_bytes": 5000000}),
                  decl(side="agent-b"))
        self.assertEqual(m.governing_values["size_cap_bytes"], 5000000)

    def test_shorter_interval_governs(self):
        m = agree(decl(values={"checkpoint_interval_s": 600}),
                  decl(side="agent-b",
                       values={"checkpoint_interval_s": 900}))
        self.assertEqual(m.governing_values["checkpoint_interval_s"], 600)

    def test_longer_cooling_off_governs(self):
        m = agree(decl(values={"absolute_trust_cooling_off_s": 172800}),
                  decl(side="agent-b"))
        self.assertEqual(
            m.governing_values["absolute_trust_cooling_off_s"], 172800)

    def test_smaller_file_type_set_governs(self):
        m = agree(
            decl(values={"file_type_allowlist": [".md", ".txt", ".png"]}),
            decl(side="agent-b",
                 values={"file_type_allowlist": [".md", ".txt"]}))
        self.assertEqual(set(m.governing_values["file_type_allowlist"]),
                         {".md", ".txt"})

    def test_larger_sensitive_set_governs(self):
        m = agree(decl(values={"sensitive_type_list": [".pem"]}),
                  decl(side="agent-b",
                       values={"sensitive_type_list": [".env", ".pem"]}))
        self.assertEqual(set(m.governing_values["sensitive_type_list"]),
                         {".pem", ".env"})

    def test_stricter_enum_governs(self):
        m = agree(decl(values={"kill_switch_sensitivity": "standard"}),
                  decl(side="agent-b",
                       values={"kill_switch_sensitivity": "strict"}))
        self.assertEqual(m.governing_values["kill_switch_sensitivity"],
                         "strict")
        m = agree(decl(),
                  decl(side="agent-b", values={
                      "incident_classification_strictness": "strict"}))
        self.assertEqual(
            m.governing_values["incident_classification_strictness"],
            "strict")

    def test_attestation_requirement_from_either_side_governs(self):
        m = agree(
            decl(values={"attestation_expectations":
                         {"require_source_hash": False}}),
            decl(side="agent-b"))
        expectations = m.governing_values["attestation_expectations"]
        self.assertIs(expectations["require_source_hash"], True)
        self.assertIs(expectations["require_code_version"], True)

    def test_governing_values_exclude_per_side_fields(self):
        m = agree(decl(values={"receipt_ask_delay_s": 600}),
                  decl(side="agent-b"))
        self.assertNotIn("receipt_ask_delay_s", m.governing_values)
        self.assertNotIn("staging_slots", m.governing_values)

    def test_shared_field_agrees_when_equal(self):
        both = {"away_window_max_s": 2592000}
        m = agree(decl(values=both), decl(side="agent-b", values=both))
        self.assertEqual(m.governing_values["away_window_max_s"], 2592000)

    def test_shared_field_mismatch_refused(self):
        with self.assertRaises(HandshakeRefused) as ctx:
            agree(decl(values={"away_window_max_s": 2592000}),
                  decl(side="agent-b",
                       values={"away_window_max_s": 1209600}))
        self.assertNotIsInstance(ctx.exception, VersionMismatch)
        self.assertNotIsInstance(ctx.exception, LevelMismatch)


class ManifestContentsTest(unittest.TestCase):
    def test_overrides_collect_values_set_away_from_default(self):
        m = agree(decl(values={"size_cap_bytes": 5000000}),
                  decl(side="agent-b",
                       values={"receipt_ask_delay_s": 600}))
        self.assertEqual(m.overrides, {"size_cap_bytes": 5000000,
                                       "receipt_ask_delay_s": 600})

    def test_no_overrides_when_nothing_set(self):
        m = agree(decl(), decl(side="agent-b"))
        self.assertEqual(m.overrides, {})

    def test_value_set_to_its_default_is_not_an_override(self):
        m = agree(decl(values={"receipt_ask_delay_s": 300}),
                  decl(side="agent-b"))
        self.assertEqual(m.overrides, {})

    def test_cost_ledger_off_by_default(self):
        m = agree(decl(), decl(side="agent-b"))
        self.assertIs(m.cost_ledger_on, False)
        self.assertIs(m.allocation_hash, None)

    def test_cost_ledger_agreed_when_both_sides_on(self):
        catalogue = {"junk_classes": ["known-bad-hash", "forbidden-path"]}
        both = {"cost_ledger_on": True, "allocation_hash": "ab" * 32,
                "cost_catalogue": catalogue}
        m = agree(decl(**both), decl(side="agent-b", **both))
        self.assertIs(m.cost_ledger_on, True)
        self.assertEqual(m.allocation_hash, "ab" * 32)
        self.assertEqual(m.cost_catalogue, catalogue)

    def test_cost_ledger_toggle_disagreement_refused(self):
        with self.assertRaises(HandshakeRefused):
            agree(decl(cost_ledger_on=True), decl(side="agent-b"))

    def test_cost_catalogue_disagreement_refused(self):
        with self.assertRaises(HandshakeRefused):
            agree(decl(cost_ledger_on=True,
                       cost_catalogue={"junk_classes": ["known-bad-hash"]}),
                  decl(side="agent-b", cost_ledger_on=True,
                       cost_catalogue={"junk_classes": ["forbidden-path"]}))

    def test_absolute_trust_active_only_when_both_sides_active(self):
        m = agree(decl(absolute_trust_active=True),
                  decl(side="agent-b", absolute_trust_active=True))
        self.assertIs(m.absolute_trust_active, True)
        m = agree(decl(absolute_trust_active=True), decl(side="agent-b"))
        self.assertIs(m.absolute_trust_active, False)

    def test_allocation_fields_are_not_manifest_values(self):
        with self.assertRaises(ManifestError):
            decl(values={"case_price": 5})

    def test_unknown_field_rejected(self):
        with self.assertRaises(ManifestError):
            decl(values={"no_such_setting": 1})


class ManifestObjectTest(unittest.TestCase):
    def test_object_carries_shipped_defaults(self):
        obj = build_manifest_object()
        self.assertEqual(obj["size_cap_bytes"], 10485760)
        self.assertEqual(obj["receipt_ask_delay_s"], 300)
        self.assertIs(obj["manager_review_enabled"], True)
        self.assertIs(obj["absolute_trust_enabled"], False)

    def test_object_applies_overrides(self):
        obj = build_manifest_object({"size_cap_bytes": 5000000})
        self.assertEqual(obj["size_cap_bytes"], 5000000)
        self.assertEqual(obj["receipt_ask_delay_s"], 300)

    def test_object_carries_version_marks(self):
        obj = build_manifest_object(code_version="guard-0.1.0")
        self.assertEqual(obj["manifest_version"], 1)
        self.assertEqual(obj["design_revision"], REVISION)
        self.assertEqual(obj["code_version"], "guard-0.1.0")

    def test_object_rejects_unknown_and_allocation_fields(self):
        with self.assertRaises(ManifestError):
            build_manifest_object({"no_such_setting": 1})
        with self.assertRaises(ManifestError):
            build_manifest_object({"case_price": 5})


class DeclarationValidationTest(unittest.TestCase):
    def test_level_above_range_rejected(self):
        with self.assertRaises(ManifestError):
            decl(level=12)

    def test_level_below_range_rejected(self):
        with self.assertRaises(ManifestError):
            decl(level=-1)

    def test_boundary_levels_accepted(self):
        m = agree(decl(level=0), decl(side="agent-b", level=11))
        self.assertEqual(m.shared_level, 11)

    def test_format_version_must_be_positive(self):
        with self.assertRaises(ManifestError):
            decl(format_version=0)

    def test_manifest_error_is_a_value_error(self):
        self.assertTrue(issubclass(ManifestError, ValueError))
        self.assertTrue(issubclass(HandshakeRefused, ManifestError))


if __name__ == "__main__":
    unittest.main()
