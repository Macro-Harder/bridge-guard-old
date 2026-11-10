"""Tests for guard.packet: the installer packet.

The packet holds the section 13 who-plays-what questions, each with
options and one shipped default, and the strictness level picker with
a plain-English description and an agent-facing description per level.
A completed packet declares itself in the shape a manifest handshake
consumes. Advanced fine-tuning rides along as overrides.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.packet import (
    DEFAULT_LEVEL,
    PacketError,
    default_packet,
    level_picker,
    questions,
)

QUESTION_IDS = {
    "role_staffing",
    "boss_form",
    "scanner_provider",
    "kill_switch_channel",
    "transfer_ready_authorship",
}


def question(question_id):
    for q in questions():
        if q.id == question_id:
            return q
    raise AssertionError(f"no question {question_id}")


class QuestionsTest(unittest.TestCase):
    def test_packet_holds_every_section_13_who_plays_what_question(self):
        self.assertEqual({q.id for q in questions()}, QUESTION_IDS)

    def test_question_ids_are_unique(self):
        ids = [q.id for q in questions()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_question_offers_at_least_two_options(self):
        for q in questions():
            self.assertGreaterEqual(len(q.options), 2, q.id)

    def test_every_question_has_one_shipped_default_among_its_options(self):
        for q in questions():
            self.assertIsInstance(q.default, str, q.id)
            self.assertIn(q.default, q.options, q.id)

    def test_staffing_options_are_dedicated_per_role_or_one_agent_switching(self):
        q = question("role_staffing")
        self.assertEqual(set(q.options),
                         {"dedicated-per-role", "one-agent-switching"})
        self.assertEqual(q.default, "dedicated-per-role")

    def test_boss_default_is_the_main_agent_as_the_design_assumes(self):
        q = question("boss_form")
        self.assertEqual(set(q.options), {"main-agent", "separate-agent"})
        self.assertEqual(q.default, "main-agent")

    def test_scanner_provider_default_is_bundled_with_the_guard(self):
        self.assertEqual(question("scanner_provider").default, "bundled")

    def test_kill_switch_channel_default_is_the_local_notification(self):
        self.assertEqual(question("kill_switch_channel").default,
                         "os-notification")

    def test_transfer_ready_default_is_the_manager_only(self):
        q = question("transfer_ready_authorship")
        self.assertEqual(set(q.options),
                         {"manager-only", "manager-or-boss-emergency"})
        self.assertEqual(q.default, "manager-only")


class LevelPickerTest(unittest.TestCase):
    def test_picker_offers_every_level_0_to_11(self):
        self.assertEqual([e.level for e in level_picker()],
                         list(range(12)))

    def test_every_level_has_a_plain_english_description(self):
        for e in level_picker():
            self.assertIsInstance(e.human_text, str)
            self.assertTrue(e.human_text.strip(), e.level)

    def test_every_level_has_an_agent_facing_description(self):
        for e in level_picker():
            self.assertIsInstance(e.agent_text, str)
            self.assertTrue(e.agent_text.strip(), e.level)

    def test_the_two_descriptions_are_not_the_same_text(self):
        for e in level_picker():
            self.assertNotEqual(e.human_text, e.agent_text, e.level)

    def test_both_descriptions_name_the_same_level(self):
        for e in level_picker():
            self.assertIn(str(e.level), e.human_text, e.level)
            self.assertIn(str(e.level), e.agent_text, e.level)


class PlaidNameTest(unittest.TestCase):
    def test_level_plaid_is_the_top_level(self):
        from guard.levels import LEVEL_PLAID
        self.assertEqual(LEVEL_PLAID, 11)
        self.assertEqual(LEVEL_PLAID,
                         max(e.level for e in level_picker()))

    def test_plaid_picker_texts_name_plaid(self):
        from guard.levels import LEVEL_PLAID
        entry = [e for e in level_picker()
                 if e.level == LEVEL_PLAID][0]
        self.assertIn("PLAID", entry.human_text)
        self.assertIn("PLAID", entry.agent_text)

    def test_plaid_picker_texts_explain_what_the_auditor_does(self):
        from guard.levels import LEVEL_PLAID
        entry = [e for e in level_picker()
                 if e.level == LEVEL_PLAID][0]
        for text in (entry.human_text, entry.agent_text):
            self.assertIn("trust-but-verify", text)
            self.assertIn("hidden instructions", text)

    def test_plaid_picker_texts_explain_what_the_monitor_does(self):
        from guard.levels import LEVEL_PLAID
        entry = [e for e in level_picker()
                 if e.level == LEVEL_PLAID][0]
        self.assertIn("watches the guard", entry.human_text)
        self.assertIn("watches the guard", entry.agent_text)


class PacketAnswersTest(unittest.TestCase):
    def test_choosing_nothing_yields_the_all_defaults_packet(self):
        decl = default_packet().declaration()
        self.assertEqual(decl["answers"],
                         {q.id: q.default for q in questions()})

    def test_shipped_default_level_is_a_level(self):
        self.assertGreaterEqual(DEFAULT_LEVEL, 0)
        self.assertLessEqual(DEFAULT_LEVEL, 11)
        self.assertEqual(default_packet().declaration()["level"],
                         DEFAULT_LEVEL)

    def test_answer_records_the_chosen_option(self):
        packet = default_packet()
        packet.answer("role_staffing", "one-agent-switching")
        answers = packet.declaration()["answers"]
        self.assertEqual(answers["role_staffing"], "one-agent-switching")

    def test_answer_outside_the_options_is_rejected(self):
        packet = default_packet()
        with self.assertRaises(PacketError):
            packet.answer("role_staffing", "nobody")

    def test_another_questions_option_is_rejected(self):
        packet = default_packet()
        with self.assertRaises(PacketError):
            packet.answer("boss_form", "manager-only")

    def test_unknown_question_is_rejected(self):
        packet = default_packet()
        with self.assertRaises(PacketError):
            packet.answer("lunch_order", "dedicated-per-role")

    def test_a_rejected_answer_changes_nothing(self):
        packet = default_packet()
        with self.assertRaises(PacketError):
            packet.answer("boss_form", "manager-only")
        self.assertEqual(packet.declaration()["answers"],
                         {q.id: q.default for q in questions()})


class LevelChoiceTest(unittest.TestCase):
    def test_pick_level_records_the_choice(self):
        packet = default_packet()
        packet.pick_level(9)
        self.assertEqual(packet.declaration()["level"], 9)

    def test_pick_level_can_choose_the_ends_of_the_spectrum(self):
        for level in (0, 11):
            packet = default_packet()
            packet.pick_level(level)
            self.assertEqual(packet.declaration()["level"], level)

    def test_level_above_11_is_rejected(self):
        with self.assertRaises(PacketError):
            default_packet().pick_level(12)

    def test_level_below_0_is_rejected(self):
        with self.assertRaises(PacketError):
            default_packet().pick_level(-1)


class DeclarationTest(unittest.TestCase):
    def test_declaration_shape_is_manifest_shaped(self):
        decl = default_packet().declaration()
        self.assertEqual(set(decl), {"format_version", "design_revision",
                                     "level", "answers", "overrides"})

    def test_declaration_format_version_is_the_current_version(self):
        self.assertEqual(default_packet().declaration()["format_version"], 1)

    def test_declaration_design_revision_matches_the_design(self):
        self.assertEqual(default_packet().declaration()["design_revision"],
                         "bg-2026-11-08.13")

    def test_declaration_answers_cover_every_question(self):
        decl = default_packet().declaration()
        self.assertEqual(set(decl["answers"]), QUESTION_IDS)


class OverridesTest(unittest.TestCase):
    def test_a_new_packet_has_no_overrides(self):
        self.assertEqual(default_packet().declaration()["overrides"], {})

    def test_fine_tuning_rides_along_as_an_override(self):
        packet = default_packet()
        packet.set_override("manager_review_enabled", False)
        self.assertEqual(packet.declaration()["overrides"],
                         {"manager_review_enabled": False})

    def test_an_override_does_not_replace_the_packet(self):
        packet = default_packet()
        packet.answer("boss_form", "separate-agent")
        packet.set_override("manager_review_enabled", False)
        decl = packet.declaration()
        self.assertEqual(decl["answers"]["boss_form"], "separate-agent")
        self.assertEqual(set(decl["answers"]), QUESTION_IDS)
        self.assertEqual(decl["level"], DEFAULT_LEVEL)


if __name__ == "__main__":
    unittest.main()
