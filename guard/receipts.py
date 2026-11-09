import dataclasses


@dataclasses.dataclass
class Event:
    kind: str
    transfer_id: object = None
    entry_id: object = None
    shortfall: bool = False


@dataclasses.dataclass
class _Send:
    transfer_id: str
    counterpart: object
    anchor: float
    asks: int = 0
    working_on_its: int = 0
    final_deadline: object = None
    state: str = "open"


@dataclasses.dataclass
class _Entry:
    entry_id: str
    counterpart: object
    recorded_at: float
    mirrored: bool = False
    discharged: bool = False


class ReceiptTracker:
    def __init__(self, clock, ask_delay_s=300, escalation_window_s=3600,
                 ask_cap=3, working_on_it_cap=3, discharge_bound_s=86400):
        self.clock = clock
        self.ask_delay_s = ask_delay_s
        self.escalation_window_s = escalation_window_s
        self.ask_cap = ask_cap
        self.working_on_it_cap = working_on_it_cap
        self.discharge_bound_s = discharge_bound_s
        self.events = []
        self._sends = {}
        self._entries = {}

    def track_send(self, transfer_id, to):
        self._sends[transfer_id] = _Send(
            transfer_id=transfer_id, counterpart=to,
            anchor=self.clock())

    def state(self, transfer_id):
        send = self._sends.get(transfer_id)
        if send is None:
            return None
        return send.state

    def receive_receipt(self, transfer_id, sender):
        send = self._sends.get(transfer_id)
        if send is None:
            return False
        if sender != send.counterpart:
            return False
        if send.state == "closed":
            return False
        send.state = "closed"
        self.events.append(Event(kind="received",
                                 transfer_id=transfer_id))
        return True

    def receive_working_on_it(self, transfer_id, sender):
        send = self._sends.get(transfer_id)
        if send is None:
            return False
        if sender != send.counterpart:
            return False
        if send.state == "closed":
            return False
        if send.final_deadline is not None:
            return False
        if send.working_on_its >= self.working_on_it_cap:
            return False
        send.working_on_its += 1
        send.anchor = self.clock()
        self.events.append(Event(kind="working-on-it",
                                 transfer_id=transfer_id))
        if send.working_on_its >= self.working_on_it_cap:
            self.events.append(Event(kind="alert",
                                     transfer_id=transfer_id))
            send.final_deadline = self.clock() + self.escalation_window_s
        return True

    def record_entry(self, entry_id, counterpart):
        self._entries[entry_id] = _Entry(
            entry_id=entry_id, counterpart=counterpart,
            recorded_at=self.clock())

    def mark_mirrored(self, entry_id):
        entry = self._entries.get(entry_id)
        if entry is not None and not entry.discharged:
            entry.mirrored = True

    def is_discharged(self, entry_id):
        entry = self._entries.get(entry_id)
        return bool(entry is not None and entry.discharged)

    def tick(self):
        now = self.clock()
        fired = []
        for send in self._sends.values():
            if send.state == "closed":
                continue
            if send.final_deadline is not None:
                if send.state != "escalated" \
                        and now >= send.final_deadline:
                    send.state = "escalated"
                    fired.append(Event(kind="escalation",
                                       transfer_id=send.transfer_id))
                continue
            if send.asks < self.ask_cap \
                    and now - send.anchor >= self.ask_delay_s:
                send.asks += 1
                send.anchor = now
                fired.append(Event(kind="receipt-request",
                                   transfer_id=send.transfer_id))
                if send.asks >= self.ask_cap:
                    fired.append(Event(kind="alert",
                                       transfer_id=send.transfer_id))
                    send.final_deadline = now + self.escalation_window_s
        for entry in self._entries.values():
            if entry.discharged:
                continue
            if entry.mirrored:
                entry.discharged = True
                fired.append(Event(kind="discharge",
                                   entry_id=entry.entry_id,
                                   shortfall=False))
            elif now - entry.recorded_at >= self.discharge_bound_s:
                entry.discharged = True
                fired.append(Event(kind="discharge",
                                   entry_id=entry.entry_id,
                                   shortfall=True))
        self.events.extend(fired)
        return fired
