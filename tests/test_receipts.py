"""Tests for guard.receipts: the missing-receipt ladder and the
discharge of retained receipt entries.

A receipt closes its send. Silence past the ask delay earns one
receipt-request. A "working on it" reply from the receiving
counterpart is accepted, logged, and restarts the ask clock, at most
three times per send. At the third ask, or the third restart, an
alert fires at once and a final one-hour wait runs; only silence at
the end of that hour escalates. A receipt arriving at any point
closes the send. A retained receipt entry discharges once mirrored,
or once the counterpart has been silent past the 24-hour discharge
bound, with the shortfall recorded.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guard.receipts import ReceiptTracker

ASK_DELAY = 300
ESCALATION_WINDOW = 3600
DISCHARGE_BOUND = 86400


class FakeClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def kinds(events):
    return [e.kind for e in events]


class ReceiptLadderTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.tracker = ReceiptTracker(self.clock)
        self.tracker.track_send("t-1", to="agent-b")

    def tick_after(self, seconds):
        self.clock.advance(seconds)
        return self.tracker.tick()

    def asks(self):
        return [e for e in self.tracker.events
                if e.kind == "receipt-request"]

    def drive_to_third_ask(self):
        self.tick_after(ASK_DELAY)
        self.tick_after(ASK_DELAY)
        return self.tick_after(ASK_DELAY)

    def test_receipt_closes_send(self):
        self.assertTrue(
            self.tracker.receive_receipt("t-1", sender="agent-b"))
        self.assertEqual(self.tracker.state("t-1"), "closed")
        self.assertIn("received", kinds(self.tracker.events))

    def test_no_ask_before_ask_delay(self):
        self.assertEqual(self.tick_after(ASK_DELAY - 1), [])

    def test_silence_past_ask_delay_produces_exactly_one_ask(self):
        fired = self.tick_after(ASK_DELAY)
        self.assertEqual(kinds(fired), ["receipt-request"])
        self.assertEqual(fired[0].transfer_id, "t-1")
        self.assertEqual(self.tracker.tick(), [])
        self.assertEqual(self.tick_after(1), [])

    def test_asks_stop_at_cap_of_three(self):
        for _ in range(40):
            self.tick_after(ASK_DELAY)
        self.assertEqual(len(self.asks()), 3)

    def test_third_ask_fires_alert_immediately(self):
        self.tick_after(ASK_DELAY)
        self.tick_after(ASK_DELAY)
        self.assertNotIn("alert", kinds(self.tracker.events))
        fired = self.tick_after(ASK_DELAY)
        self.assertEqual(kinds(fired), ["receipt-request", "alert"])
        self.assertEqual(self.tracker.state("t-1"), "open")

    def test_no_escalation_before_final_hour_ends(self):
        self.drive_to_third_ask()
        fired = self.tick_after(ESCALATION_WINDOW - 1)
        self.assertNotIn("escalation", kinds(fired))
        self.assertEqual(self.tracker.state("t-1"), "open")

    def test_silence_at_end_of_final_hour_escalates(self):
        self.drive_to_third_ask()
        fired = self.tick_after(ESCALATION_WINDOW)
        self.assertIn("escalation", kinds(fired))
        self.assertEqual(self.tracker.state("t-1"), "escalated")

    def test_working_on_it_restarts_ask_clock(self):
        self.tick_after(200)
        self.assertTrue(self.tracker.receive_working_on_it(
            "t-1", sender="agent-b"))
        self.assertEqual(self.tick_after(ASK_DELAY - 1), [])
        fired = self.tick_after(1)
        self.assertEqual(kinds(fired), ["receipt-request"])

    def test_working_on_it_is_logged_and_closes_nothing(self):
        self.tracker.receive_working_on_it("t-1", sender="agent-b")
        self.assertIn("working-on-it", kinds(self.tracker.events))
        self.assertEqual(self.tracker.state("t-1"), "open")

    def test_working_on_it_from_wrong_counterpart_restarts_nothing(self):
        self.tick_after(200)
        self.assertFalse(self.tracker.receive_working_on_it(
            "t-1", sender="agent-c"))
        fired = self.tick_after(100)
        self.assertEqual(kinds(fired), ["receipt-request"])

    def test_receipt_from_wrong_counterpart_closes_nothing(self):
        self.assertFalse(
            self.tracker.receive_receipt("t-1", sender="agent-c"))
        self.assertEqual(self.tracker.state("t-1"), "open")
        fired = self.tick_after(ASK_DELAY)
        self.assertEqual(kinds(fired), ["receipt-request"])

    def test_receipt_for_unknown_send_ignored(self):
        self.assertFalse(
            self.tracker.receive_receipt("t-unknown", sender="agent-b"))

    def test_receipt_stops_ladder(self):
        self.tick_after(ASK_DELAY)
        self.tracker.receive_receipt("t-1", sender="agent-b")
        self.assertEqual(self.tick_after(100000), [])
        self.assertEqual(len(self.asks()), 1)
        self.assertEqual(self.tracker.state("t-1"), "closed")

    def test_receipt_during_final_wait_closes_and_prevents_escalation(self):
        self.drive_to_third_ask()
        self.tick_after(ESCALATION_WINDOW // 2)
        self.assertTrue(
            self.tracker.receive_receipt("t-1", sender="agent-b"))
        fired = self.tick_after(ESCALATION_WINDOW)
        self.assertNotIn("escalation", kinds(fired))
        self.assertEqual(self.tracker.state("t-1"), "closed")

    def test_receipt_after_escalation_still_closes(self):
        self.drive_to_third_ask()
        self.tick_after(ESCALATION_WINDOW)
        self.assertEqual(self.tracker.state("t-1"), "escalated")
        self.assertTrue(
            self.tracker.receive_receipt("t-1", sender="agent-b"))
        self.assertEqual(self.tracker.state("t-1"), "closed")

    def test_third_working_on_it_fires_alert_and_starts_final_wait(self):
        for _ in range(3):
            self.clock.advance(100)
            self.assertTrue(self.tracker.receive_working_on_it(
                "t-1", sender="agent-b"))
        self.assertIn("alert", kinds(self.tracker.events))
        fired = self.tick_after(ESCALATION_WINDOW - 1)
        self.assertNotIn("escalation", kinds(fired))
        fired = self.tick_after(1)
        self.assertIn("escalation", kinds(fired))
        self.assertEqual(self.tracker.state("t-1"), "escalated")

    def test_fourth_working_on_it_restarts_nothing(self):
        for _ in range(3):
            self.clock.advance(100)
            self.tracker.receive_working_on_it(
                "t-1", sender="agent-b")
        self.clock.advance(700)
        self.assertFalse(self.tracker.receive_working_on_it(
            "t-1", sender="agent-b"))
        fired = self.tick_after(ESCALATION_WINDOW - 700)
        self.assertIn("escalation", kinds(fired))


class ReceiptDischargeTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.tracker = ReceiptTracker(self.clock)
        self.tracker.record_entry("e-1", counterpart="agent-b")

    def discharges(self):
        return [e for e in self.tracker.events
                if e.kind == "discharge"]

    def test_entry_not_discharged_before_bound(self):
        self.clock.advance(DISCHARGE_BOUND - 1)
        self.tracker.tick()
        self.assertFalse(self.tracker.is_discharged("e-1"))
        self.assertEqual(self.discharges(), [])

    def test_entry_discharged_after_bound_with_shortfall_recorded(self):
        self.clock.advance(DISCHARGE_BOUND)
        self.tracker.tick()
        self.assertTrue(self.tracker.is_discharged("e-1"))
        fired = self.discharges()
        self.assertEqual(len(fired), 1)
        self.assertEqual(fired[0].entry_id, "e-1")
        self.assertTrue(fired[0].shortfall)

    def test_mirrored_entry_discharges_without_shortfall(self):
        self.tracker.mark_mirrored("e-1")
        self.tracker.tick()
        self.assertTrue(self.tracker.is_discharged("e-1"))
        fired = self.discharges()
        self.assertEqual(len(fired), 1)
        self.assertFalse(fired[0].shortfall)


if __name__ == "__main__":
    unittest.main()
