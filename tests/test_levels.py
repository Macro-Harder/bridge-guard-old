"""Tests for the strictness spectrum: levels, presets, and
dependency forcing in guard.levels."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.levels import LevelError, preset_for, resolve, setting, settings


def engaged(preset, name):
    value = preset.values[name]
    return value is not False and value is not None


def edges(name):
    return {d.requires: d for d in setting(name).depends_on}


class PresetTest(unittest.TestCase):
    def test_every_level_resolves(self):
        for level in range(12):
            self.assertEqual(preset_for(level).level, level)

    def test_level_below_range_rejected(self):
        with self.assertRaises(LevelError):
            preset_for(-1)

    def test_level_above_range_rejected(self):
        with self.assertRaises(LevelError):
            preset_for(12)

    def test_non_integer_level_rejected(self):
        with self.assertRaises(LevelError):
            preset_for("3")

    def test_preset_covers_exactly_the_registered_settings(self):
        names = {s.name for s in settings()}
        for level in (0, 6, 11):
            self.assertEqual(set(preset_for(level).values), names)

    def test_level_zero_turns_everything_off_except_logging(self):
        preset = preset_for(0)
        for s in settings():
            value = preset.values[s.name]
            if s.name == "logging_enabled":
                self.assertIs(value, True)
            elif isinstance(s.default, bool):
                self.assertIs(value, False, s.name)
            else:
                self.assertIsNone(value, s.name)

    def test_level_ten_toggles_sit_at_their_shipped_defaults(self):
        preset = preset_for(10)
        for s in settings():
            if isinstance(s.default, bool):
                self.assertIs(preset.values[s.name], s.default,
                              s.name)

    def test_no_preset_turns_the_cost_ledger_on(self):
        # The ledger is a per-pair toggle that comes on only through
        # a jointly negotiated cost allocation (design section 16);
        # no strictness preset may switch it on.
        for level in range(12):
            self.assertIs(preset_for(level).values["ledger_on"],
                          False, level)

    def test_level_ten_engages_the_variables(self):
        preset = preset_for(10)
        for s in settings():
            if not isinstance(s.default, bool):
                self.assertIsNotNone(preset.values[s.name], s.name)

    def test_level_eleven_adds_the_monitor_agent(self):
        self.assertIn("monitor-agent", preset_for(11).components)
        for level in range(11):
            self.assertNotIn("monitor-agent",
                             preset_for(level).components)

    def test_level_eleven_settings_match_level_ten(self):
        self.assertEqual(dict(preset_for(11).values),
                         dict(preset_for(10).values))


class RegistryTest(unittest.TestCase):
    def test_appendix_a_toggle_defaults(self):
        self.assertIs(setting("manager_review_enabled").default, True)
        self.assertIs(setting("fast_path_enabled").default, True)
        self.assertIs(setting("precedent_path_enabled").default, True)
        self.assertIs(setting("absolute_trust_enabled").default, False)
        self.assertIs(setting("ledger_on").default, False)
        self.assertIs(setting("logging_enabled").default, True)

    def test_appendix_a_variable_defaults(self):
        self.assertEqual(setting("size_cap_bytes").default, 10485760)
        self.assertEqual(setting("request_rate_cap_per_hour").default, 20)
        self.assertEqual(
            setting("absolute_trust_daily_byte_cap").default, 10485760)

    def test_dependency_edges_are_declared(self):
        trust = edges("absolute_trust_enabled")
        self.assertIn("logging_enabled", trust)
        self.assertIn("absolute_trust_daily_byte_cap", trust)
        self.assertIn(0, trust["absolute_trust_daily_byte_cap"].fallbacks)
        self.assertIn("fast_path_enabled",
                      edges("precedent_path_enabled"))

    def test_unknown_setting_rejected(self):
        with self.assertRaises(LevelError):
            setting("no_such_setting")


class IndependenceTest(unittest.TestCase):
    def test_no_level_needs_a_higher_levels_component(self):
        registry = {s.name: s for s in settings()}
        for level in range(12):
            preset = preset_for(level)
            for name, s in registry.items():
                if not engaged(preset, name):
                    continue
                for dep in s.depends_on:
                    self.assertTrue(
                        engaged(preset, dep.requires),
                        "level %d engages %s without %s"
                        % (level, name, dep.requires))

    def test_components_never_disappear_at_a_higher_level(self):
        for level in range(11):
            self.assertLessEqual(preset_for(level).components,
                                 preset_for(level + 1).components)


class ForcingTest(unittest.TestCase):
    def test_enabling_a_toggle_forces_its_dependency_on(self):
        res = resolve(0, overrides={"precedent_path_enabled": True})
        self.assertIs(res.values["fast_path_enabled"], True)
        forced = {f.dependency: f for f in res.forced}
        self.assertEqual(forced["fast_path_enabled"].setting,
                         "precedent_path_enabled")
        self.assertIs(forced["fast_path_enabled"].value, True)

    def test_forcing_a_variable_uses_the_depending_levels_fallback(self):
        edge = edges("absolute_trust_enabled")[
            "absolute_trust_daily_byte_cap"]
        res = resolve(0, overrides={"absolute_trust_enabled": True})
        self.assertEqual(res.values["absolute_trust_daily_byte_cap"],
                         edge.fallbacks[0])
        forced = {f.dependency: f for f in res.forced}
        self.assertEqual(
            forced["absolute_trust_daily_byte_cap"].setting,
            "absolute_trust_enabled")
        self.assertEqual(forced["absolute_trust_daily_byte_cap"].value,
                         edge.fallbacks[0])

    def test_absolute_trust_forces_logging_back_on(self):
        res = resolve(4, overrides={"absolute_trust_enabled": True},
                      advanced={"logging_enabled": False})
        self.assertIs(res.values["logging_enabled"], True)
        self.assertIn("logging_enabled",
                      {f.dependency for f in res.forced})

    def test_no_forcing_when_the_dependency_is_already_on(self):
        res = resolve(10, overrides={"precedent_path_enabled": True})
        self.assertEqual(res.forced, ())
        self.assertEqual(res.notifications, ())
        self.assertEqual(res.manager_flags, ())

    def test_disabling_a_setting_forces_nothing(self):
        res = resolve(10, overrides={"manager_review_enabled": False})
        self.assertIs(res.values["manager_review_enabled"], False)
        self.assertEqual(res.forced, ())

    def test_every_forcing_notifies_the_user_and_flags_the_manager(self):
        res = resolve(0, overrides={"precedent_path_enabled": True,
                                    "absolute_trust_enabled": True})
        self.assertEqual(len(res.forced), 2)
        self.assertEqual(len(res.notifications), len(res.forced))
        self.assertEqual(len(res.manager_flags), len(res.forced))
        for f in res.forced:
            self.assertTrue(any(f.dependency in n
                                for n in res.notifications), f.dependency)
            self.assertTrue(any(f.dependency in flag
                                for flag in res.manager_flags), f.dependency)

    def test_resolve_without_overrides_returns_the_preset(self):
        for level in (0, 7):
            res = resolve(level)
            self.assertEqual(dict(res.values),
                             dict(preset_for(level).values))
            self.assertEqual(res.forced, ())
            self.assertEqual(res.notifications, ())
            self.assertEqual(res.manager_flags, ())

    def test_resolve_does_not_change_the_preset(self):
        resolve(0, overrides={"fast_path_enabled": True})
        self.assertIs(preset_for(0).values["fast_path_enabled"], False)

    def test_unknown_setting_override_rejected(self):
        with self.assertRaises(LevelError):
            resolve(0, overrides={"no_such_setting": True})

    def test_resolve_rejects_out_of_range_level(self):
        with self.assertRaises(LevelError):
            resolve(12)


class LoggingTest(unittest.TestCase):
    def test_logging_is_on_at_every_level(self):
        for level in range(12):
            self.assertIs(preset_for(level).values["logging_enabled"],
                          True, level)

    def test_advanced_override_turns_logging_off(self):
        res = resolve(6, advanced={"logging_enabled": False})
        self.assertIs(res.values["logging_enabled"], False)

    def test_advanced_override_alone_forces_nothing(self):
        res = resolve(6, advanced={"logging_enabled": False})
        self.assertEqual(res.forced, ())
        self.assertEqual(res.notifications, ())
        self.assertEqual(res.manager_flags, ())


if __name__ == "__main__":
    unittest.main()
