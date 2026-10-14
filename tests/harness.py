"""Shared fixtures for the step-6 suites. No network, no credentials, no model."""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal as D

sys.path.insert(0, ".")

from orbit.audit.cycle import CycleRecorder
from orbit.audit.journal import Journal
from orbit.audit.records import E
from orbit.exec.adapter import ForbiddenAdapter, NullAdapter
from orbit.exec.protection import MarginMode
from orbit.exec.recon import (ExchangeOrder, ExchangePosition, ExchangeView,
                              Fill, IntendedPosition, IntendedState,
                              OrderStatus, SubmittedOrder)
from orbit.exec.writer import WriterAuthority
from orbit.risk.gateway import Gateway
from orbit.tools.session import ToolSession

NOW = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)


class Exch:
    """Simulated exchange STATE (not the adapter). What is really out there."""

    def __init__(self, position=None, orders=(), fills=(), reachable=True,
                 consistent=True, age_s=5, equity="1000", can_place=True):
        self.position = position
        self.orders = list(orders)
        self.fills = list(fills)
        self.reachable = reachable
        self.consistent = consistent
        self.age_s = age_s
        self.equity = equity
        self.can_place = can_place
        # SAFETY CLOSURE ROUND 4C4, checkpoint A. The simulated venue's clock,
        # so a test that moves the SESSION clock (UTC-day rollover) can keep
        # the observation fresh relative to it. Defaults to the fixture NOW.
        self.now = NOW

    def view(self):
        return ExchangeView(
            fetched_at=self.now - timedelta(seconds=self.age_s),
            reachable=self.reachable, consistent=self.consistent,
            server_time=self.now, equity=D(self.equity), mark_price=D("30000"),
            margin_mode=MarginMode.UNKNOWN, position=self.position,
            open_orders=tuple(self.orders), fills=tuple(self.fills),
            can_place_orders=self.can_place)


def pos(side="long", contracts="2.38", entry="30000"):
    return ExchangePosition(side, D(contracts), D(entry))


def stop_order(cid="stop1", contracts="2.38", price="29700.1"):
    return ExchangeOrder(cid, D(contracts), True, D(price))


def held(side="long", contracts="2.38", stop="29700.1", cid="stop1",
         orbit_stop=True):
    """Intended state for a position ORBIT opened.

    SAFETY CLOSURE ROUND 4C4, harness rebuild. `orbit_stop` separates two facts
    this fixture used to collapse into one representation:

        the position IS PROTECTED BY the order `cid`      (a reference)
        ORBIT SUBMITTED the order `cid`                   (authorship)

    Through R4C3 the collapse was harmless: authorship came from the durable
    journal and `submitted_orders` was in-memory colour only. Under C4-I1 the
    state is DERIVED from the journal, so seeding a SubmittedOrder writes an
    INTENT - and an operator's manual stop would silently acquire ORBIT
    authorship, which is exactly what R4B/R4B2 exist to forbid.

    With orbit_stop=False the position still names the stop, reconciliation
    still sees it and still counts it for risk, but ORBIT's durable history
    does not claim it. ACCOUNTING IS NOT MUTATION AUTHORITY.
    """
    c = D(contracts)
    # SAFETY CLOSURE ROUND 4C4, checkpoint A. The entry carries its SIDE and its
    # ROLE explicitly: daily accounting is now derived from primitive fills, and
    # a fill whose order has no side cannot be accounted (it fails closed).
    orders = [SubmittedOrder("e1", c, c, OrderStatus.FILLED, NOW,
                             kind="OPEN", side=side, role="ENTRY",
                             reduce_only=False)]
    if orbit_stop:
        orders.append(SubmittedOrder(cid, c, D("0"), OrderStatus.ACK, NOW, True))
    return IntendedState(
        journal_loaded=True, clean_shutdown=True, entries_utc_day=1,
        position=IntendedPosition(side, c, D("30000"), D(stop), cid,
                                  NOW - timedelta(minutes=30)),
        submitted_orders=tuple(orders))


def flat():
    return IntendedState(journal_loaded=True, clean_shutdown=True,
                         entries_utc_day=0)


def owning(rig, *cids, protective=True, contracts="2.38", stop="29700.1"):
    """Record DURABLY that ORBIT created these orders.

    SAFETY CLOSURE, blocker I. The model may act only on orders ORBIT created,
    and ownership comes from ORBIT's own record — not from the order being
    visible in the account, and not from the shape of its id. Fixtures that want
    to exercise a rule ABOUT one of our orders must therefore say that it is
    ours, exactly as the running system would have."""
    for cid in cids:
        # SAFETY CLOSURE ROUND 4C4, harness rebuild. ONE VENUE ORDER COUNTS
        # ONCE - at the operation ledger too. Since the rig now seeds its
        # declared protective orders as durable PROTECTIVE_INTENTs, an
        # additional owning() intent for the same id created a SECOND logical
        # operation for ONE real order: the ledger then reported two unresolved
        # operations (one ACK, one PENDING) where production has exactly one.
        # Declaring ownership of an order the rig already seeded is a no-op.
        if cid in getattr(rig, "_seeded_cids", ()):
            continue
        rig.journal.append_one(
            E.PROTECTIVE_INTENT if protective else E.INTENT, "own-" + cid,
            client_order_id=cid, contracts=contracts,
            instrument="BTC-USDT-SWAP",
            order_kind="PROTECTIVE" if protective else "OPEN",
            role="PROTECTIVE" if protective else "ENTRY",
            reduce_only=bool(protective), stop=stop)
    return rig


class Rig:
    def __init__(self, tmp, name, intended=None, exch=None, forbidden=False,
                 ttl=30.0, owner=None):
        self.path = os.path.join(tmp, name + ".jsonl")
        self.wdir = os.path.join(tmp, name + "_writer")
        self.journal = Journal(self.path, clock=lambda: NOW)
        self.rec = CycleRecorder(self.journal)
        self.authority = WriterAuthority(self.wdir, owner_id=owner,
                                         ttl_seconds=ttl)
        self.adapter = (ForbiddenAdapter if forbidden else NullAdapter)(
            self.authority, self.journal)
        self.gateway = Gateway()
        self.exch = exch or Exch()
        self.intended = intended if intended is not None else flat()
        self.lease = None
        self._seeded = set()
        self._seeded_cids = set()
        # SAFETY CLOSURE ROUND 4C4, harness rebuild. Seed the declared fixture
        # history HERE, at rig setup, not at session() time. Ordering is a
        # safety property, not a convenience: a test that appends
        # ORDER_STATUS=REJECTED after construction is describing an order that
        # went terminal AFTER it was submitted. Seeding at session() replayed
        # the submission on top of that, and a PROTECTIVE_ACK landing after the
        # rejection RESURRECTED a terminal order and handed the model authority
        # over it. Production cannot produce that ordering; neither may a rig.
        self._seed_once(self.intended)

    def acquire(self):
        self.lease = self.authority.acquire()
        return self.lease

    def _seed_once(self, st):
        """Seed a declared fixture state EXACTLY once.

        SAFETY CLOSURE ROUND 4C4, harness rebuild. The WIP seeded on every
        `session()` call. A test that opened two sessions against one rig - the
        normal way to exercise a retry, a successor epoch or a second cycle -
        therefore appended a SECOND INTENT/FILL/POSITION_STATE/COUNTERS set for
        history that had already happened. That re-granted authority over
        terminal orders, double-counted fills, reset daily counters and
        manufactured unresolved operations. Production writes that history once,
        when the event occurs; so does this.
        """
        if st is None:
            return
        if id(st) in self._seeded:
            return
        self._seeded.add(id(st))
        self._seed(st)

    # ------------------------------------------------------------------
    # SAFETY CLOSURE ROUND 4C4, checkpoint A, scope item 5.
    #
    # `entries_utc_day` and `realized_pnl_utc_day` are no longer read from a
    # COUNTERS aggregate. They are DERIVED from primitive fills. A fixture that
    # declares "2 entries today, -20 realized" must therefore WRITE the fills
    # that produce those figures, exactly as the running system would have. The
    # synthesized history is deliberately simple and exact:
    #
    #   * every synthesized round trip is 1 contract (0.01 BTC) so a declared
    #     P&L of X USDT is an exit price of entry + X * 100, with no rounding;
    #   * every seeded fill carries fee_cost_usdt="0", an EXPLICIT normalized
    #     cost, and executed_at, so the derived figure equals the declared
    #     figure to the cent on the declared day. Production fills without a
    #     fee field are charged the modelled taker fee;
    #   * a declared P&L with ZERO entries today is realized by a position that
    #     was ENTERED YESTERDAY and exited today - the only history that can
    #     produce it - and the fixture's clock is moved back to write it.
    #
    # A fixture that declares FEWER entries than the ENTRY fills it already
    # seeds is describing a state the system cannot produce, and raises.
    # ------------------------------------------------------------------
    SYN_ENTRY = "30000"

    def _append_at(self, when, kind, action_id, **payload):
        """Append one event with the journal clock at `when`."""
        saved = self.journal._clock
        self.journal._clock = lambda: when
        try:
            return self.journal.append_one(kind, action_id, **payload)
        finally:
            self.journal._clock = saved

    def _synth_round_trip(self, n, pnl, entry_when, exit_when,
                          entry_exec=None, exit_exec=None):
        """One ENTRY fill and one EXIT fill realizing exactly `pnl` USDT.

        `entry_when`/`exit_when` are the journal COMMIT times; `entry_exec`/
        `exit_exec` are the venue EXECUTION times written as `executed_at`
        (default: the same instant). Checkpoint A.1: the two are distinct on
        purpose, so a fill executed before midnight and committed after it can
        be expressed - that case is what finding 2 was about."""
        e_cid, x_cid = f"syn-entry-{n}", f"syn-exit-{n}"
        entry = D(self.SYN_ENTRY)
        exit_ = entry + D(pnl) * D("100")          # 1 contract = 0.01 BTC
        self._seeded_cids.update((e_cid, x_cid))
        self._append_at(entry_when, E.INTENT, e_cid, client_order_id=e_cid,
                        contracts="1", instrument="BTC-USDT-SWAP",
                        order_kind="OPEN", side="long", reduce_only=False,
                        role="ENTRY", operation_id=f"syn:{n}:entry")
        self._append_at(entry_when, E.SUBMIT_ACK, e_cid, client_order_id=e_cid)
        self._append_at(entry_when, E.FILL, e_cid, client_order_id=e_cid,
                        fill_id=f"seed-{e_cid}", contracts="1",
                        price=str(entry), fee_cost_usdt="0",
                        executed_at=(entry_exec or entry_when).isoformat())
        self._append_at(exit_when, E.INTENT, x_cid, client_order_id=x_cid,
                        contracts="1", instrument="BTC-USDT-SWAP",
                        order_kind="CLOSE", side="short", reduce_only=True,
                        role="EXIT", operation_id=f"syn:{n}:exit")
        self._append_at(exit_when, E.SUBMIT_ACK, x_cid, client_order_id=x_cid)
        self._append_at(exit_when, E.FILL, x_cid, client_order_id=x_cid,
                        fill_id=f"seed-{x_cid}", contracts="1",
                        price=str(exit_), fee_cost_usdt="0",
                        executed_at=(exit_exec or exit_when).isoformat())

    def _seed(self, st):
        """SAFETY CLOSURE ROUND 4C4. Authorization state is now DERIVED from the
        journal, so a fixture must WRITE the history that produces the state it
        declares. Fixtures that described a state the system could not produce
        were the loophole C4-I1 walked through."""
        from orbit.audit.records import E
        from orbit.exec.recon import OrderStatus as OS
        j = self.journal
        p_ = getattr(st, "position", None)
        declared_entries = int(getattr(st, "entries_utc_day", 0) or 0)
        declared_pnl = D(str(getattr(st, "realized_pnl_utc_day", 0) or 0))
        seeded_entries = sum(
            1 for so in (getattr(st, "submitted_orders", ()) or ())
            if not so.is_protective and (so.role in (None, "ENTRY"))
            and so.status in (OS.FILLED, OS.PARTIALLY_FILLED)
            and so.filled_contracts > 0)
        if declared_entries < seeded_entries:
            raise ValueError(
                f"fixture declares entries_utc_day={declared_entries} but "
                f"seeds {seeded_entries} filled ENTRY orders; that history "
                f"cannot exist")
        extra = declared_entries - seeded_entries
        yesterday = NOW - timedelta(days=1)
        # Synthesized history is written FIRST so record timestamps stay
        # monotonic: a yesterday-dated entry must not follow today's records.
        if extra == 0 and declared_pnl != 0:
            self._synth_round_trip(0, declared_pnl, yesterday, NOW)
        else:
            for n in range(extra):
                self._synth_round_trip(
                    n, declared_pnl if n == extra - 1 else D("0"), NOW, NOW)
        for so in (getattr(st, "submitted_orders", ()) or ()):
            cid = so.client_order_id
            prot = bool(so.is_protective)
            self._seeded_cids.add(cid)
            side = so.side
            if side is None and not prot and p_ is not None:
                side = p_.side
            j.append_one(E.PROTECTIVE_INTENT if prot else E.INTENT, cid,
                         client_order_id=cid,
                         contracts=str(so.intended_contracts),
                         instrument=so.instrument or "BTC-USDT-SWAP",
                         order_kind=so.kind or ("PROTECTIVE" if prot else "OPEN"),
                         side=side, reduce_only=so.reduce_only,
                         role=so.role or ("PROTECTIVE" if prot else "ENTRY"),
                         operation_id=so.logical_operation_id, epoch=so.epoch)
            stt = so.status
            if stt is OS.ACK:
                j.append_one(E.PROTECTIVE_ACK if prot else E.SUBMIT_ACK, cid,
                             client_order_id=cid)
            elif stt in (OS.FILLED, OS.PARTIALLY_FILLED):
                j.append_one(E.FILL, cid, client_order_id=cid,
                             fill_id=f"seed-{cid}",
                             contracts=str(so.filled_contracts),
                             price=str(p_.entry_price if p_ is not None
                                       else D(self.SYN_ENTRY)),
                             fee_cost_usdt="0",
                             executed_at=NOW.isoformat())
            elif stt is OS.CANCELLED:
                j.append_one(E.SUBMIT_FAILED, cid, client_order_id=cid)
            elif stt is OS.UNKNOWN:
                j.append_one(E.SUBMIT_UNKNOWN, cid, client_order_id=cid,
                             attempts=so.resolution_attempts)
            elif stt is not OS.SUBMITTED:
                j.append_one(E.ORDER_STATUS, cid, client_order_id=cid,
                             status=stt.value)
        p_ = getattr(st, "position", None)
        if p_ is not None:
            j.append_one(E.POSITION_STATE, None, position={
                "side": p_.side, "contracts": str(p_.contracts),
                "entry_price": str(p_.entry_price),
                "stop_price": (None if p_.stop_price is None
                               else str(p_.stop_price)),
                "stop_client_id": p_.stop_client_id,
                "opened_at": p_.opened_at.isoformat()})
        j.append_one(E.COUNTERS, None,
                     entries_utc_day=getattr(st, "entries_utc_day", 0),
                     realized_pnl_utc_day=str(
                         getattr(st, "realized_pnl_utc_day", 0)))
        if getattr(st, "clean_shutdown", False):
            j.append_one(E.CLEAN_SHUTDOWN, None)

    def session(self, cycle_id="cyc1", lease=..., intended=None, now=NOW,
                memory=None):
        """A session over this rig's journal.

        `intended` is DECLARED HISTORY: it is written to the journal (once) and
        the session's constructor receives it. `memory` is CALLER MEMORY ONLY:
        it goes to the constructor and NOTHING is written. SAFETY CLOSURE ROUND
        4C4, checkpoint A, scope item 2 - the C4-I1 class is "in-memory state
        disagrees with durable history"; a harness that always seeded what it
        was handed could not express that disagreement, which is how the R4C3
        test of it silently stopped testing anything.
        """
        if memory is not None and intended is not None:
            raise ValueError("pass either declared history (intended) or "
                             "unseeded caller memory (memory), not both")
        if memory is None:
            self._seed_once(intended if intended is not None else self.intended)
        ctor_state = (memory if memory is not None
                      else intended if intended is not None else self.intended)
        return ToolSession(
            cycle_id=cycle_id, journal=self.journal, recorder=self.rec,
            authority=self.authority, adapter=self.adapter,
            gateway=self.gateway,
            intended_state=ctor_state,
            exchange_view_fn=self.exch.view, now=now,
            lease=self.lease if lease is ... else lease)
