"""The per-pair cost ledger of DESIGN section 16.

One account per counterpart pair. The ledger is a toggle: off, no
charging runs and a code-enforced case quota substitutes for price;
on, charges follow the pair's own negotiated cost-allocation
catalogue (section 16 as reshaped by C-A — the pair picks and
combines catalogue rules jointly; nothing here imposes a unilateral
allocation). Code-stage checks are never charged. A Format 2 case
escrows a stake equal to the case price; the stake refunds on
approval or good-faith refusal and burns only on a refusal citing a
junk class the pair adopted from Appendix A's catalogue. Incident
response is never gated on a balance, and debt stops accruing at
the debt floor.
"""


class CostError(Exception):
    pass


# Appendix A's junk-class catalogue (CONSENSUS3 D12/Y17): the only
# classes a refusal may cite. A pair adopts a subset of these in its
# cost-allocation artifact; the catalogue itself is fixed here.
JUNK_CATALOGUE = (
    "malformed-after-format-pass",
    "known-bad-hash",
    "duplicate-after-cooldown",
    "forbidden-path",
    "counterpart-attributable-failure",
)

# Work code does before any agent wakes (section 16, "code eats
# first"). It is never charged, and asking to charge it is an error.
CODE_STAGE_KINDS = ("format_check", "dedup", "pattern_scan")

REFUND_OUTCOMES = ("approved", "good_faith_refusal")


class CostAccount:
    def __init__(self, pair_id, allocation=None, *,
                 ledger_off_case_quota=20):
        self.pair_id = pair_id
        self.ledger_off_case_quota = ledger_off_case_quota
        allocation = allocation if isinstance(allocation, dict) \
            else None
        self.ledger_on = bool(allocation) \
            and bool(allocation.get("ledger_on"))
        self._prices = {}
        self._junk_classes = set()
        self._free_conversation_allowance = 0
        self._daily_refill = 0
        self._debt_floor = 0
        self._ceiling_growth = 0
        self._stake = 0
        self.balance = 0
        self.ceiling = 0
        if allocation is not None:
            self.balance = allocation.get("new_pair_balance", 0)
            self.ceiling = allocation.get("new_pair_ceiling",
                                          self.balance)
            self._free_conversation_allowance = allocation.get(
                "free_conversation_allowance", 0)
            self._daily_refill = allocation.get("daily_refill", 0)
            self._debt_floor = allocation.get("debt_floor", 0)
            self._ceiling_growth = allocation.get(
                "ceiling_growth", 0)
            prices = allocation.get("prices")
            if isinstance(prices, dict):
                self._prices = dict(prices)
            adopted = allocation.get("junk_classes")
            if adopted:
                self._junk_classes = set(adopted)
            case_price = self._prices.get("case")
            stake = allocation.get("stake", case_price)
            self._stake = stake if stake is not None else 0
            if self.ledger_on:
                self._validate(allocation)
        self._escrows = {}
        self._quota_used = {}
        self._messages_used = {}
        self._day_high_water = None

    def _validate(self, allocation):
        prices = allocation.get("prices")
        if not isinstance(prices, dict) or not prices:
            raise CostError(
                "a ledger that is on needs its negotiated price "
                "table")
        for kind, value in prices.items():
            if isinstance(value, bool) \
                    or not isinstance(value, (int, float)) \
                    or value < 1:
                raise CostError(
                    "price for %r is %r; prices are at least one "
                    "credit" % (kind, value))
        adopted = allocation.get("junk_classes")
        if not adopted:
            raise CostError(
                "a ledger that is on needs a non-empty junk-class "
                "set adopted from the catalogue")
        for name in adopted:
            if name not in JUNK_CATALOGUE:
                raise CostError(
                    "junk class %r is not in Appendix A's catalogue"
                    % (name,))
        case_price = prices.get("case")
        stake = allocation.get("stake", case_price)
        if stake is None:
            raise CostError(
                "a ledger that is on needs a case price to stake "
                "against")
        if case_price is not None and stake != case_price:
            raise CostError(
                "the stake must equal the case price (%r != %r)"
                % (stake, case_price))

    def _require_on(self, action):
        if not self.ledger_on:
            raise CostError(
                "the cost ledger is off for pair %r; %s does not "
                "run" % (self.pair_id, action))

    def _require_day(self, day):
        # The day reckons the free-allowance and quota windows, so
        # it is the ledger's clock, not the caller's: a day behind
        # the highest day already seen would reopen a spent
        # window, and is refused. The day only ever moves forward.
        if isinstance(day, bool) or not isinstance(day, int) \
                or day < 0:
            raise CostError(
                "day must be a non-negative integer, got %r" % (day,))
        if self._day_high_water is not None \
                and day < self._day_high_water:
            raise CostError(
                "day %r is behind this ledger's current day %r; "
                "windows do not reopen"
                % (day, self._day_high_water))
        self._day_high_water = day

    @staticmethod
    def _require_positive(action, value):
        if isinstance(value, bool) \
                or not isinstance(value, (int, float)) or value <= 0:
            raise CostError(
                "%s needs a positive amount, got %r" % (action, value))

    @property
    def suspended(self):
        return self.ledger_on and self.balance <= 0

    def price(self, kind):
        if kind not in self._prices:
            raise CostError(
                "no negotiated price for %r on pair %r"
                % (kind, self.pair_id))
        return self._prices[kind]

    def charge(self, kind, day=0):
        self._require_on("charging")
        self._require_day(day)
        if kind in CODE_STAGE_KINDS:
            raise CostError(
                "%r is a code-stage check; code eats first and is "
                "never charged" % (kind,))
        if kind == "message":
            used = self._messages_used.get(day, 0)
            self._messages_used[day] = used + 1
            if used < self._free_conversation_allowance:
                return 0
            kind = "excess_message"
        amount = self.price(kind)
        # The balance stops at the debt floor, exactly as debt
        # accrual does: at the floor the ledger stops deepening.
        self.balance = max(self._debt_floor, self.balance - amount)
        return amount

    def admit_case(self, day=0):
        self._require_day(day)
        if not self.ledger_on:
            used = self._quota_used.get(day, 0)
            if used >= self.ledger_off_case_quota:
                return False
            self._quota_used[day] = used + 1
            return True
        # A balance below the stake is treated as zero for
        # case-opening (section 16, F30): the suspension tier.
        return self.balance >= self._stake

    def admit_incident_response(self):
        # The floor outside the catalogue (F19): incident response
        # is never gated on a balance, a suspension, or the toggle.
        return True

    def escrow_stake(self, request_id):
        existing = self._escrows.get(request_id)
        if existing is not None:
            # A case id escrows exactly once, whatever became of
            # the stake: re-escrowing a settled case would let one
            # case burn (or refund) a second stake.
            raise CostError(
                "case %r already has an escrow record (%s); a "
                "case id escrows exactly once"
                % (request_id, existing))
        if self.ledger_on:
            if self.balance < self._stake:
                raise CostError(
                    "balance %r cannot cover the stake %r for "
                    "case %r" % (self.balance, self._stake,
                                 request_id))
            self.balance -= self._stake
        self._escrows[request_id] = "escrowed"
        return self._stake

    def escrow_state(self, request_id):
        return self._escrows.get(request_id)

    def settle_case(self, request_id, outcome, junk_class=None):
        state = self._escrows.get(request_id)
        if state is None:
            raise CostError(
                "no escrow for case %r" % (request_id,))
        if state != "escrowed":
            raise CostError(
                "case %r is already settled (%s)"
                % (request_id, state))
        if outcome in REFUND_OUTCOMES:
            settled = "refunded"
        elif outcome == "refusal":
            adopted = self._junk_classes if self._junk_classes \
                else set(JUNK_CATALOGUE)
            if junk_class is not None and junk_class in adopted:
                settled = "burned"
            else:
                settled = "refunded"
        else:
            raise CostError(
                "unknown settlement outcome %r" % (outcome,))
        if settled == "refunded" and self.ledger_on:
            self.balance += self._stake
        self._escrows[request_id] = settled
        return settled

    def refill(self, days=1):
        self._require_on("refill")
        self._require_positive("refill", days)
        self.balance = min(
            self.ceiling, self.balance + self._daily_refill * days)
        return self.balance

    def record_honest_transfer(self):
        self._require_on("ceiling growth")
        # The trust sliding scale is catalogue material: the
        # ceiling grows only where the pair adopted a growth rule.
        self.ceiling += self._ceiling_growth
        return self.ceiling

    def top_up(self, amount):
        self._require_on("top-up")
        self._require_positive("top-up", amount)
        # The one credit path (D12/W6): a human top-up changes a
        # balance only, never a parameter.
        self.balance += amount
        return self.balance

    def accrue_debt(self, amount):
        self._require_on("debt accrual")
        self._require_positive("debt accrual", amount)
        # Debt is bounded at the floor: at the floor the ledger
        # stops deepening; the response never does (E33).
        self.balance = max(self._debt_floor, self.balance - amount)
        return self.balance
