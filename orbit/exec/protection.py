"""
orbit/exec/protection.py — WHAT LOSS IS ACTUALLY BOUNDED, AND BY WHAT.

ORBIT-AGENT-ARCH-001, build step 4a.

Two quantities that this project has been careful to keep apart, and which must
never be printed as if they were the same thing:

  planned_risk_usdt
      The MODELLED loss if the stop fills AT the stop price.
      This is an assumption about execution, not a property of the market.
      A stop-market order cannot deliver it through a gap: the fill happens at
      the next available price. `engine.py` already says this in its docstring;
      it survives here into the live layer.

  worst_case_protected_loss
      The strongest bound the ACTUAL exchange and margin architecture can
      legitimately establish, independent of whether any order executes well.

The honest arithmetic:

  * A resting stop-market order bounds NOTHING in the limit. It improves the
    expected outcome; it does not cap the loss.
  * Under ISOLATED margin, loss on the position is capped by the margin posted
    to it. That is a real, structural bound and does not depend on execution.
  * Under CROSS margin, the position is backed by the whole account, so the
    bound is account equity. That is a bound in the same sense that "you cannot
    lose more than you have" is a bound — true, and not reassuring.
  * If the margin mode is UNKNOWN, no bound may be claimed at all.

Ledger §20 records that ORBIT's margin mode is UNVERIFIED and that
`maintenance_margin_rate = 0.005` is an assumption (`check_margin_tiers.py` was
written and never run). Until that is resolved this module returns
`worst_case_protected_loss = None` for the live account, deliberately.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

D = Decimal


class MarginMode(str, Enum):
    ISOLATED = "isolated"
    CROSS = "cross"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProtectionAssessment:
    planned_risk_usdt: Decimal
    protective_order_verified: bool
    margin_mode: MarginMode
    worst_case_protected_loss: Optional[Decimal]
    guarantee_basis: str
    is_guaranteed: bool

    def describe(self) -> str:
        """The only sanctioned wording. Never call planned risk a maximum."""
        lines = [
            f"planned risk (modelled, stop fills at the stop price): "
            f"${self.planned_risk_usdt}",
            f"protective order verified resting on the exchange: "
            f"{'yes' if self.protective_order_verified else 'NO'}",
        ]
        if self.worst_case_protected_loss is None:
            lines.append("worst-case protected loss: NOT ESTABLISHED — "
                         + self.guarantee_basis)
        else:
            lines.append(f"worst-case protected loss: "
                         f"${self.worst_case_protected_loss} "
                         f"({self.guarantee_basis})")
        lines.append("planned risk is NOT a guaranteed maximum loss; a gap "
                     "fills at the next available price.")
        return "\n".join(lines)


def assess(planned_risk_usdt: Decimal,
           protective_order_verified: bool,
           margin_mode: MarginMode,
           isolated_margin_posted: Optional[Decimal] = None,
           account_equity: Optional[Decimal] = None) -> ProtectionAssessment:
    if margin_mode is MarginMode.ISOLATED and isolated_margin_posted is not None:
        return ProtectionAssessment(
            planned_risk_usdt, protective_order_verified, margin_mode,
            isolated_margin_posted,
            "isolated margin: loss on this position is structurally capped by "
            "the margin posted to it, independent of execution quality",
            True)
    if margin_mode is MarginMode.CROSS and account_equity is not None:
        return ProtectionAssessment(
            planned_risk_usdt, protective_order_verified, margin_mode,
            account_equity,
            "cross margin: the position is backed by the entire account, so "
            "the only structural bound is total equity — this is a bound, not "
            "a protection",
            False)
    return ProtectionAssessment(
        planned_risk_usdt, protective_order_verified, margin_mode, None,
        "margin mode is unverified (ledger §20; check_margin_tiers.py has not "
        "been run), so no structural bound may be claimed",
        False)


# ======================================================================
# THE PROTECTION LADDER — SAFETY CLOSURE ROUND 3, finding R3-1
# ======================================================================
#
# THE DEFECT THIS EXISTS TO PREVENT.
#
# Protection used to be judged by two DISCONNECTED analyses: the stop PRICE of
# `prot[0]`, and the stop SIZE as `sum(o.contracts for o in prot)`. A position
# of 2.38 contracts with 1.19 resting at the authorised 29700.1 and 1.19 resting
# at 29000 therefore summed to full coverage and reported
#
#     run=RUNNING  clean=True  findings=[]  adopted_stop=29700.1
#
# with half the position actually protected 700 points further away. Worse:
# REVERSING the order list changed the verdict to NO_NEW_ENTRY. The same account
# state produced two different answers depending on which order the exchange
# happened to list first.
#
# A position is not protected at an authorised stop because the SUM of stop
# quantities equals the position. Each contract is protected at the price of the
# order that covers IT. So protection is a ladder of slices, and every slice is
# evaluated on its own.


# ======================================================================
# EXCHANGE-ORDER IDENTITY — SAFETY CLOSURE ROUND 4A, finding R4-2
# ======================================================================
#
# THE DEFECT THIS EXISTS TO PREVENT.
#
# `_order_findings` de-duplicates FILLS by fill_id, explicitly, because a venue
# can deliver the same fill more than once. `build_ladder` applied no such rule
# to open orders: it mapped every ROW it was handed into a slice and summed the
# contracts. One order returned twice therefore covered twice as much. A 2.38
# position behind a single 1.19 stop reported
#
#     one row  -> codes=['STOP_SIZE_MISMATCH']  run=NO_NEW_ENTRY  clean=False
#     two rows -> codes=[]                      run=RUNNING       clean=True
#                 planned risk $7.989423666 (inside the $8 cap)
#
# with half the position unprotected, no remedy emitted, and a modelled loss
# that was numerically right for the wrong reason — it summed two slices that
# were one order. This is R3-1's shape reappearing inside the mechanism built to
# fix R3-1: ordering was normalised and IDENTITY never was.
#
# THE INVARIANT.
#
#     ONE REAL VENUE ORDER COUNTS AS ONE PROTECTIVE ORDER, REGARDLESS OF HOW
#     MANY TIMES ITS REPRESENTATION APPEARS IN A FETCH.
#
# A repeated representation adds no coverage, no modelled protection, no
# position quantity and no risk capacity. Two representations that CONFLICT on
# an execution-critical field are not a duplicate at all: they are two
# incompatible claims about one order, and ORBIT does not choose between them
# and does not add them. It fails closed.

# The fields that decide what an order DOES. Two representations of one identity
# that disagree on any of these describe different orders, and at most one of
# them is true.
EXECUTION_CRITICAL_FIELDS = ("contracts", "stop_price", "is_protective")


@dataclass(frozen=True)
class OrderIdentityConflict:
    """One identity, two irreconcilable representations, in one fetch."""
    identity: str
    field: str
    values: Tuple[str, ...]

    def describe(self) -> str:
        return (f"order {self.identity} was returned more than once in one "
                f"fetch with conflicting {self.field}: {list(self.values)}")


def order_identity(o) -> Tuple[str, ...]:
    """WHICH ORDER IS THIS, deterministically.

    A client order id IS the identity: it is ours, it is deterministic, and the
    venue echoes it. When one is absent we cannot tell two anonymous rows apart
    from one anonymous row listed twice — so the identity falls back to the
    row's own execution-critical content. Two identical anonymous rows then
    collapse to one, which UNDER-counts coverage if they really were two orders.
    That direction is the safe one: the failure this exists to prevent is
    manufacturing protection that does not exist.
    """
    cid = getattr(o, "client_order_id", None)
    if cid:
        return ("cid", str(cid))
    return ("anon",) + tuple(
        _identity_value(getattr(o, f, None))
        for f in EXECUTION_CRITICAL_FIELDS)


def _identity_value(v) -> str:
    """One VALUE, one spelling.

    Found by the round-4A review of this very function: `str()` alone made
    Decimal("1.19") and Decimal("1.190") two different identities, so two
    anonymous rows for one order covered 2.380 contracts instead of 1.19 —
    the defect being repaired, reintroduced by its own repair through a
    difference of exponent rather than of value. Decimal comparison is numeric;
    its string form is not, and identity must follow the comparison.
    """
    if isinstance(v, Decimal):
        return "0" if v == 0 else str(v.normalize())
    return str(v)


def canonical_orders(open_orders
                     ) -> Tuple[Tuple[Any, ...],
                                Tuple[OrderIdentityConflict, ...]]:
    """(one row per real order, conflicts).

    Applied to the WHOLE open-order list before any protective filter, because
    `is_protective` is itself an execution-critical field: filtering first would
    silently discard the half of a contradiction that says the order is not
    protective, and the contradiction with it.

    Order of the returned rows is first-seen order; every consumer sorts
    deterministically afterwards, and the conflict list is sorted so a verdict
    cannot depend on which representation the venue listed first.
    """
    seen: Dict[Tuple[str, ...], Any] = {}
    order: List[Any] = []
    conflicts: List[OrderIdentityConflict] = []
    for o in open_orders:
        ident = order_identity(o)
        prior = seen.get(ident)
        if prior is None:
            seen[ident] = o
            order.append(o)
            continue
        for f in EXECUTION_CRITICAL_FIELDS:
            a, b = getattr(prior, f, None), getattr(o, f, None)
            if a != b:
                conflicts.append(OrderIdentityConflict(
                    ":".join(ident), f,
                    tuple(sorted({str(a), str(b)}))))
        # identical representation: the duplicate is dropped, and it adds
        # nothing. A conflicting one is ALSO dropped rather than added, and the
        # conflict below is what stops the cycle.
    uniq = tuple(order)
    return uniq, tuple(sorted(
        set(conflicts), key=lambda c: (c.identity, c.field, c.values)))


@dataclass(frozen=True)
class ProtectiveSlice:
    """One resting protective order and everything needed to judge it."""
    client_order_id: Optional[str]
    contracts: Decimal
    stop_price: Optional[Decimal]
    is_owned: bool
    instrument: Optional[str]
    side: Optional[str]
    reduce_only: Optional[bool]
    resting: bool = True

    @property
    def price_known(self) -> bool:
        return self.stop_price is not None


@dataclass(frozen=True)
class ProtectionLadder:
    """Every protective slice against one position, evaluated per slice.

    Ordering is normalised on construction, so no conclusion drawn from a ladder
    can depend on the order the exchange happened to list its orders in."""
    slices: Tuple[ProtectiveSlice, ...]
    position_contracts: Decimal
    position_side: Optional[str]
    conflicts: Tuple[OrderIdentityConflict, ...] = ()
    """SAFETY CLOSURE ROUND 4A, R4-2. Identities the venue returned more than
    once with irreconcilable execution-critical fields. A ladder carrying any of
    these describes contradictory exchange state: NOTHING may be concluded from
    its coverage, and the reconciler fails closed on it."""

    @property
    def contradictory(self) -> bool:
        return bool(self.conflicts)

    # -------------------------------------------------- coverage
    @property
    def covered_contracts(self) -> Decimal:
        return sum((s.contracts for s in self.slices if s.price_known), D("0"))

    @property
    def unknown_price_contracts(self) -> Decimal:
        return sum((s.contracts for s in self.slices if not s.price_known),
                   D("0"))

    @property
    def total_contracts(self) -> Decimal:
        return sum((s.contracts for s in self.slices), D("0"))

    @property
    def uncovered_contracts(self) -> Decimal:
        gap = self.position_contracts - self.covered_contracts
        return gap if gap > 0 else D("0")

    @property
    def over_covered_contracts(self) -> Decimal:
        over = self.total_contracts - self.position_contracts
        return over if over > 0 else D("0")

    # -------------------------------------------------- shape
    @property
    def priced(self) -> Tuple[ProtectiveSlice, ...]:
        return tuple(s for s in self.slices if s.price_known)

    @property
    def uniform(self) -> bool:
        """Every slice priced, and all at the same price. Only then may the
        ladder be spoken about as though it were one stop."""
        p = self.priced
        return (len(p) == len(self.slices) and bool(p)
                and len({s.stop_price for s in p}) == 1)

    @property
    def prices(self) -> Tuple[Decimal, ...]:
        return tuple(s.stop_price for s in self.priced)

    def worst_slice(self, side: Optional[str] = None
                    ) -> Optional[ProtectiveSlice]:
        """The slice whose stop is FURTHEST from entry — the one that decides
        how bad this position can get. For a long that is the lowest stop."""
        side = side or self.position_side
        p = self.priced
        if not p:
            return None
        return (min(p, key=lambda s: s.stop_price) if side == "long"
                else max(p, key=lambda s: s.stop_price))

    def slices_wider_than(self, reference: Decimal,
                          side: Optional[str] = None
                          ) -> Tuple[ProtectiveSlice, ...]:
        side = side or self.position_side
        return tuple(s for s in self.priced
                     if (s.stop_price < reference if side == "long"
                         else s.stop_price > reference))

    def slices_tighter_than(self, reference: Decimal,
                            side: Optional[str] = None
                            ) -> Tuple[ProtectiveSlice, ...]:
        side = side or self.position_side
        return tuple(s for s in self.priced
                     if (s.stop_price > reference if side == "long"
                         else s.stop_price < reference))

    # -------------------------------------------------- risk
    def modeled_total(self, entry_price: Decimal, spec, limits) -> Decimal:
        """Modelled loss summed over EVERY slice at ITS OWN stop.

        Not the whole position at one convenient price. Uncovered contracts are
        deliberately NOT costed here: an unprotected remainder has no modelled
        loss because it has no stop, and pretending otherwise would produce a
        smaller, friendlier number for a strictly worse situation. The coverage
        findings say that separately."""
        from orbit.risk.modeled_loss import modeled_loss
        total = D("0")
        for s in self.priced:
            size_btc = s.contracts * spec.contract_size_btc
            total += modeled_loss(entry_price, s.stop_price, size_btc,
                                  spec, limits).total_usdt
        return total

    def describe(self) -> str:
        rows = "; ".join(
            f"{s.client_order_id}:{s.contracts}@"
            f"{s.stop_price if s.price_known else 'UNKNOWN'}"
            for s in self.slices)
        return (f"{len(self.slices)} protective slice(s) covering "
                f"{self.covered_contracts} of {self.position_contracts} "
                f"contracts [{rows}]")


def build_ladder(open_orders, position_contracts: Decimal,
                 position_side: Optional[str],
                 owned_ids=frozenset()) -> ProtectionLadder:
    """Deterministically ordered: priced slices by stop price then by client
    order id, unpriced last. Two views listing the same orders in different
    sequences produce the same ladder, and therefore the same verdict.

    SAFETY CLOSURE ROUND 4A, R4-2. Canonicalised by IDENTITY first, so two views
    listing the same order a different NUMBER of times also produce the same
    ladder. The de-duplication happens here, in the protection model, and not in
    any caller or fixture: a venue that repeats a row must not be able to
    manufacture coverage no matter who asked it.
    """
    open_orders, conflicts = canonical_orders(open_orders)
    slices = [
        ProtectiveSlice(
            client_order_id=o.client_order_id,
            contracts=o.contracts,
            stop_price=o.stop_price,
            is_owned=(o.client_order_id in owned_ids),
            instrument=getattr(o, "instrument", None),
            side=getattr(o, "side", None),
            reduce_only=getattr(o, "reduce_only", None))
        for o in open_orders if o.is_protective]
    slices.sort(key=lambda s: (s.stop_price is None,
                               s.stop_price if s.stop_price is not None else D("0"),
                               s.client_order_id or ""))
    return ProtectionLadder(tuple(slices), position_contracts, position_side,
                            conflicts)
