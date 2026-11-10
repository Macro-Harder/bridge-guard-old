"""Tests for guard.cost: the per-pair cost ledger of DESIGN section 16.

The ledger is a per-pair toggle. Off, a code-enforced case quota
substitutes for price and no charging runs. On, charges follow the
pair's own negotiated cost-allocation catalogue, code-stage checks are
never charged, a Format 2 case escrows a stake equal to the case price,
and an empty account reaches the suspension tier while responses are
never gated and debt stops accruing at the debt floor.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.cost import CostAccount, CostError


def allocation(**over):
    a = {
        "ledger_on": True,
        "prices": {
            "case": 7,
            "scan": 2,
            "security_team": 40,
            "question_round": 2,
            "excess_message": 1,
        },
        "junk_classes": ["known-bad-hash", "forbidden-path"],
        "free_conversation_allowance": 3,
        "daily_refill": 5,
        "new_pair_balance": 30,
        "new_pair_ceiling": 60,
        "debt_floor": -50,
    }
    a.update(over)
    return a


class AmountValidationTest(unittest.TestCase):
    """Regression for audit M2 / break-it A8a: amounts that move a
    balance are validated. A negative top-up drained an account; a
    negative refill or debt accrual ran the same trick backwards."""

    def test_top_up_rejects_non_positive_amounts(self):
        account = CostAccount("pair-b", allocation())
        for bad in (-90, -1, 0, True, "5", None):
            with self.assertRaises(CostError, msg=repr(bad)):
                account.top_up(bad)
        self.assertEqual(account.balance, 30)

    def test_top_up_accepts_a_positive_amount(self):
        account = CostAccount("pair-b", allocation())
        self.assertEqual(account.top_up(10), 40)

    def test_refill_rejects_non_positive_days(self):
        account = CostAccount("pair-b", allocation())
        for bad in (-3, 0, True, "2", None):
            with self.assertRaises(CostError, msg=repr(bad)):
                account.refill(bad)
        self.assertEqual(account.balance, 30)

    def test_accrue_debt_rejects_non_positive_amounts(self):
        account = CostAccount("pair-b", allocation())
        for bad in (-10, 0, True, "5", None):
            with self.assertRaises(CostError, msg=repr(bad)):
                account.accrue_debt(bad)
        self.assertEqual(account.balance, 30)


class EscrowIdempotenceTest(unittest.TestCase):
    """Regression for audit M3 / break-it A8b: one case id escrows
    exactly once. After a burn, the same id could escrow and burn
    a second stake for the same case."""

    def test_burned_case_cannot_escrow_or_burn_again(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        account.settle_case("req-1", "refusal",
                            junk_class="known-bad-hash")
        balance = account.balance
        with self.assertRaises(CostError):
            account.escrow_stake("req-1")
        self.assertEqual(account.balance, balance)
        self.assertEqual(account.escrow_state("req-1"), "burned")

    def test_refunded_case_cannot_escrow_again(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        account.settle_case("req-1", "approved")
        with self.assertRaises(CostError):
            account.escrow_stake("req-1")

    def test_distinct_cases_still_escrow(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        account.settle_case("req-1", "refusal",
                            junk_class="known-bad-hash")
        self.assertEqual(account.escrow_stake("req-2"), 7)


class ChargeFloorTest(unittest.TestCase):
    """Regression for audit L3: charge() had no floor, so a
    balance could fall without bound; debt accrual already stops
    at the pair's debt floor, and charges now stop there too."""

    def test_charge_stops_at_the_debt_floor(self):
        account = CostAccount("pair-b", allocation())
        for _ in range(30):
            account.charge("case")
        self.assertEqual(account.balance, -50)

    def test_charge_above_the_floor_is_unchanged(self):
        account = CostAccount("pair-b", allocation())
        self.assertEqual(account.charge("case"), 7)
        self.assertEqual(account.balance, 23)


class OffByDefaultTest(unittest.TestCase):
    def test_ledger_off_without_allocation(self):
        account = CostAccount("pair-b")
        self.assertFalse(account.ledger_on)

    def test_ledger_off_when_allocation_says_so(self):
        account = CostAccount("pair-b", allocation(ledger_on=False))
        self.assertFalse(account.ledger_on)

    def test_charge_raises_while_off(self):
        account = CostAccount("pair-b")
        with self.assertRaises(CostError):
            account.charge("case")

    def test_refill_raises_while_off(self):
        account = CostAccount("pair-b")
        with self.assertRaises(CostError):
            account.refill(1)

    def test_debt_does_not_accrue_while_off(self):
        account = CostAccount("pair-b")
        with self.assertRaises(CostError):
            account.accrue_debt(10)
        self.assertEqual(account.balance, 0)

    def test_top_up_raises_while_off(self):
        account = CostAccount("pair-b")
        with self.assertRaises(CostError):
            account.top_up(10)

    def test_quota_admits_up_to_limit_then_refuses(self):
        account = CostAccount("pair-b", ledger_off_case_quota=2)
        self.assertTrue(account.admit_case(day=1))
        self.assertTrue(account.admit_case(day=1))
        self.assertFalse(account.admit_case(day=1))

    def test_quota_resets_on_a_new_day(self):
        account = CostAccount("pair-b", ledger_off_case_quota=1)
        self.assertTrue(account.admit_case(day=1))
        self.assertFalse(account.admit_case(day=1))
        self.assertTrue(account.admit_case(day=2))

    def test_quota_is_per_pair(self):
        first = CostAccount("pair-b", ledger_off_case_quota=1)
        second = CostAccount("pair-c", ledger_off_case_quota=1)
        self.assertTrue(first.admit_case(day=1))
        self.assertFalse(first.admit_case(day=1))
        self.assertTrue(second.admit_case(day=1))

    def test_toggle_is_per_pair(self):
        on = CostAccount("pair-b", allocation())
        off = CostAccount("pair-c")
        self.assertTrue(on.ledger_on)
        self.assertFalse(off.ledger_on)


class NegotiatedCatalogueTest(unittest.TestCase):
    def test_charge_uses_the_pairs_negotiated_price(self):
        account = CostAccount("pair-b", allocation())
        charged = account.charge("case")
        self.assertEqual(charged, 7)
        self.assertEqual(account.balance, 23)

    def test_price_accessor_reports_the_negotiated_price(self):
        account = CostAccount("pair-b", allocation())
        self.assertEqual(account.price("scan"), 2)
        self.assertEqual(account.price("security_team"), 40)

    def test_unpriced_work_kind_cannot_be_charged(self):
        prices = {"case": 7, "question_round": 2, "excess_message": 1}
        account = CostAccount("pair-b", allocation(prices=prices))
        with self.assertRaises(CostError):
            account.charge("scan")
        self.assertEqual(account.balance, 30)

    def test_charges_do_not_touch_another_pair(self):
        first = CostAccount("pair-b", allocation())
        second = CostAccount("pair-c", allocation())
        first.charge("case")
        self.assertEqual(second.balance, 30)

    def test_free_allowance_messages_cost_nothing(self):
        account = CostAccount("pair-b", allocation())
        for _ in range(3):
            self.assertEqual(account.charge("message", day=1), 0)
        self.assertEqual(account.balance, 30)

    def test_messages_beyond_the_allowance_are_charged(self):
        account = CostAccount("pair-b", allocation())
        for _ in range(3):
            account.charge("message", day=1)
        self.assertEqual(account.charge("message", day=1), 1)
        self.assertEqual(account.balance, 29)

    def test_allowance_resets_on_a_new_day(self):
        account = CostAccount("pair-b", allocation())
        for _ in range(4):
            account.charge("message", day=1)
        self.assertEqual(account.charge("message", day=2), 0)

    def test_ledger_on_without_prices_is_invalid(self):
        bad = allocation()
        del bad["prices"]
        with self.assertRaises(CostError):
            CostAccount("pair-b", bad)

    def test_price_below_one_credit_is_invalid(self):
        prices = dict(allocation()["prices"], case=0)
        with self.assertRaises(CostError):
            CostAccount("pair-b", allocation(prices=prices))

    def test_empty_junk_class_set_is_invalid_while_on(self):
        with self.assertRaises(CostError):
            CostAccount("pair-b", allocation(junk_classes=[]))

    def test_junk_class_outside_the_catalogue_is_invalid(self):
        with self.assertRaises(CostError):
            CostAccount("pair-b",
                        allocation(junk_classes=["not-a-class"]))

    def test_stake_must_equal_the_case_price(self):
        with self.assertRaises(CostError):
            CostAccount("pair-b", allocation(stake=9))


class CodeChecksFreeTest(unittest.TestCase):
    def test_code_stage_kinds_are_never_charged(self):
        account = CostAccount("pair-b", allocation())
        for kind in ("format_check", "dedup", "pattern_scan"):
            with self.subTest(kind=kind):
                with self.assertRaises(CostError):
                    account.charge(kind)
        self.assertEqual(account.balance, 30)

    def test_agent_scan_is_charged_at_the_negotiated_price(self):
        account = CostAccount("pair-b", allocation())
        self.assertEqual(account.charge("scan"), 2)
        self.assertEqual(account.balance, 28)


class EscrowTest(unittest.TestCase):
    def test_opening_a_case_escrows_the_case_price_as_stake(self):
        account = CostAccount("pair-b", allocation())
        self.assertEqual(account.escrow_stake("req-1"), 7)
        self.assertEqual(account.escrow_state("req-1"), "escrowed")
        self.assertEqual(account.balance, 23)

    def test_approval_refunds_the_stake(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        state = account.settle_case("req-1", "approved")
        self.assertEqual(state, "refunded")
        self.assertEqual(account.balance, 30)

    def test_good_faith_refusal_refunds_the_stake(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        state = account.settle_case("req-1", "good_faith_refusal")
        self.assertEqual(state, "refunded")
        self.assertEqual(account.balance, 30)

    def test_refusal_citing_no_junk_class_refunds_the_stake(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        state = account.settle_case("req-1", "refusal")
        self.assertEqual(state, "refunded")
        self.assertEqual(account.balance, 30)

    def test_refusal_citing_an_unadopted_catalogue_class_refunds(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        state = account.settle_case(
            "req-1", "refusal", junk_class="duplicate-after-cooldown")
        self.assertEqual(state, "refunded")
        self.assertEqual(account.balance, 30)

    def test_refusal_citing_an_adopted_junk_class_burns(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        state = account.settle_case(
            "req-1", "refusal", junk_class="known-bad-hash")
        self.assertEqual(state, "burned")
        self.assertEqual(account.balance, 23)

    def test_escrow_needs_balance_for_the_stake(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=5))
        with self.assertRaises(CostError):
            account.escrow_stake("req-1")

    def test_a_case_cannot_escrow_twice(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        with self.assertRaises(CostError):
            account.escrow_stake("req-1")

    def test_settling_an_unknown_case_raises(self):
        account = CostAccount("pair-b", allocation())
        with self.assertRaises(CostError):
            account.settle_case("req-9", "approved")

    def test_a_settled_case_cannot_settle_again(self):
        account = CostAccount("pair-b", allocation())
        account.escrow_stake("req-1")
        account.settle_case("req-1", "approved")
        with self.assertRaises(CostError):
            account.settle_case("req-1", "approved")

    def test_escrow_state_of_unknown_case_is_none(self):
        account = CostAccount("pair-b", allocation())
        self.assertIsNone(account.escrow_state("req-9"))

    def test_burn_while_off_has_no_account_effect(self):
        account = CostAccount("pair-b")
        self.assertEqual(account.escrow_stake("req-1"), 0)
        state = account.settle_case(
            "req-1", "refusal", junk_class="known-bad-hash")
        self.assertEqual(state, "burned")
        self.assertEqual(account.balance, 0)


class RefillAndCeilingTest(unittest.TestCase):
    def test_new_pair_starts_at_the_negotiated_balance(self):
        account = CostAccount("pair-b", allocation())
        self.assertEqual(account.balance, 30)
        self.assertEqual(account.ceiling, 60)

    def test_refill_adds_the_daily_rate(self):
        account = CostAccount("pair-b", allocation())
        account.charge("case")
        account.refill(1)
        self.assertEqual(account.balance, 28)

    def test_refill_accumulates_over_days(self):
        account = CostAccount("pair-b", allocation())
        account.charge("case")
        account.charge("case")
        account.refill(2)
        self.assertEqual(account.balance, 26)

    def test_refill_never_exceeds_the_ceiling(self):
        account = CostAccount("pair-b", allocation())
        account.refill(100)
        self.assertEqual(account.balance, 60)

    def test_ceiling_grows_with_honest_receipted_history(self):
        account = CostAccount("pair-b", allocation(ceiling_growth=10))
        account.record_honest_transfer()
        self.assertEqual(account.ceiling, 70)
        account.record_honest_transfer()
        self.assertEqual(account.ceiling, 80)

    def test_grown_ceiling_admits_a_larger_refill(self):
        account = CostAccount("pair-b", allocation(ceiling_growth=10))
        account.record_honest_transfer()
        account.refill(100)
        self.assertEqual(account.balance, 70)

    def test_ceiling_is_fixed_without_the_sliding_scale(self):
        account = CostAccount("pair-b", allocation())
        account.record_honest_transfer()
        self.assertEqual(account.ceiling, 60)


class SuspensionTest(unittest.TestCase):
    def test_zero_balance_is_suspended(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=7))
        account.charge("case")
        self.assertEqual(account.balance, 0)
        self.assertTrue(account.suspended)

    def test_funded_account_is_not_suspended(self):
        account = CostAccount("pair-b", allocation())
        self.assertFalse(account.suspended)

    def test_suspended_account_admits_no_case(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=7))
        account.charge("case")
        self.assertFalse(account.admit_case())

    def test_balance_below_the_stake_admits_no_case(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=10))
        account.charge("scan")
        account.charge("scan")
        account.charge("excess_message")
        self.assertEqual(account.balance, 5)
        self.assertFalse(account.admit_case())

    def test_top_up_restores_case_admission(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=7))
        account.charge("case")
        self.assertFalse(account.admit_case())
        account.top_up(7)
        self.assertTrue(account.admit_case())
        self.assertFalse(account.suspended)

    def test_top_up_changes_the_balance_only(self):
        account = CostAccount("pair-b", allocation())
        account.top_up(10)
        self.assertEqual(account.balance, 40)
        self.assertEqual(account.price("case"), 7)
        self.assertEqual(account.ceiling, 60)


class DebtFloorTest(unittest.TestCase):
    def test_debt_accrues_below_zero(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=10))
        account.accrue_debt(15)
        self.assertEqual(account.balance, -5)

    def test_debt_stops_accruing_at_the_floor(self):
        account = CostAccount("pair-b", allocation())
        account.accrue_debt(500)
        self.assertEqual(account.balance, -50)
        account.accrue_debt(500)
        self.assertEqual(account.balance, -50)

    def test_incident_response_is_admitted_at_the_floor(self):
        account = CostAccount("pair-b", allocation())
        account.accrue_debt(500)
        self.assertTrue(account.admit_incident_response())

    def test_incident_response_is_admitted_while_suspended(self):
        account = CostAccount("pair-b", allocation(new_pair_balance=7))
        account.charge("case")
        self.assertTrue(account.suspended)
        self.assertTrue(account.admit_incident_response())

    def test_incident_response_is_admitted_while_off(self):
        account = CostAccount("pair-b")
        self.assertTrue(account.admit_incident_response())


if __name__ == "__main__":
    unittest.main()
