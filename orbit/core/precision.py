"""
orbit/core/precision.py — EXCHANGE PRECISION AND QUANTIZATION.

ORBIT-AGENT-ARCH-001, build step 1. This module exists because of a specific
historical defect and its near-repeat:

  * Bug #1 (ledger §4): a script sized a position UP to reach the exchange
    minimum, silently breaking the risk cap. Triggered exactly when stops were
    wide -- i.e. when the cap mattered most.
  * The pre-demo blocker (ledger §6/§20): OKX accepts orders in CONTRACTS, not
    raw BTC. The research engine computes a continuous BTC float and never
    quantizes. Rounding UP at that step is bug #1 one layer down.

THEREFORE, THE RULE OF THIS MODULE:
    SIZE ALWAYS ROUNDS DOWN. PRICES ALWAYS ROUND IN THE DIRECTION THAT CANNOT
    INCREASE MAXIMUM LOSS. A ROUNDING THAT WOULD INCREASE RISK IS A REJECTION,
    NEVER AN ADJUSTMENT.

All arithmetic here uses Decimal. Binary floats cannot represent 0.1 exactly,
and this is the layer where "0.1" must mean 0.1.

Instrument specs are the values VERIFIED against the OKX public endpoint on
2026-09-06 by check_specs.py (no API key). They are NOT taken from any document.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_DOWN, ROUND_UP, localcontext
from typing import Literal, Optional

Side = Literal["long", "short"]


# ======================================================================
# INSTRUMENT SPEC — verified values only
# ======================================================================

@dataclass(frozen=True)
class InstrumentSpec:
    """OKX BTC-USDT-SWAP. Every field verified 2026-09-06 via check_specs.py.

    A previous external document claimed contract_size = 0.001 BTC and
    tick = 0.5. Both are wrong (by 10x and 5x). Values here come from the
    exchange, and this docstring exists so nobody 'corrects' them back.
    """
    inst_id: str = "BTC-USDT-SWAP"
    contract_size_btc: Decimal = Decimal("0.01")      # BTC per contract
    lot_step_contracts: Decimal = Decimal("0.01")     # contract increment
    min_contracts: Decimal = Decimal("0.01")          # exchange minimum
    tick_size: Decimal = Decimal("0.1")               # price increment
    maker_fee: Decimal = Decimal("0.0002")
    taker_fee: Decimal = Decimal("0.0005")
    verified_on: str = "2026-09-06"
    source: str = "OKX public /api/v5 via ccxt (check_specs.py); no API key"

    @property
    def min_btc(self) -> Decimal:
        return self.contract_size_btc * self.min_contracts       # 0.0001 BTC

    @property
    def btc_step(self) -> Decimal:
        return self.contract_size_btc * self.lot_step_contracts  # 0.0001 BTC


BTC_USDT_SWAP = InstrumentSpec()


# ======================================================================
# RESULTS
# ======================================================================

@dataclass(frozen=True)
class QuantizedSize:
    ok: bool
    reason: str
    requested_btc: Decimal
    contracts: Decimal
    btc: Decimal
    discarded_btc: Decimal        # requested - executable; always >= 0

    @property
    def shrink_fraction(self) -> Decimal:
        if self.requested_btc == 0:
            return Decimal("0")
        return self.discarded_btc / self.requested_btc


@dataclass(frozen=True)
class QuantizedPrice:
    ok: bool
    reason: str
    requested: Decimal
    price: Decimal
    moved: Decimal                # price - requested (signed)


def _dec(x) -> Decimal:
    """Accept int/str/Decimal exactly; accept float only via repr, never binary."""
    if isinstance(x, Decimal):
        return x
    if isinstance(x, float):
        return Decimal(repr(x))
    return Decimal(str(x))


# ======================================================================
# SIZE — ALWAYS DOWN
# ======================================================================

def quantize_size(requested_btc, spec: InstrumentSpec = BTC_USDT_SWAP) -> QuantizedSize:
    """BTC -> whole lot steps of contracts, ALWAYS FLOORING.

    Never rounds up, never 'bumps to minimum'. If the floored size is below the
    exchange minimum the order is REJECTED, exactly as RiskEngine already does
    for the risk-based minimum. That is the fix for bug #1, applied at the
    exchange-granularity layer.
    """
    req = _dec(requested_btc)
    if req <= 0:
        return QuantizedSize(False, "requested size is not positive",
                             req, Decimal("0"), Decimal("0"), Decimal("0"))

    with localcontext() as ctx:
        ctx.prec = 40
        raw_contracts = req / spec.contract_size_btc
        steps = (raw_contracts / spec.lot_step_contracts).to_integral_value(ROUND_DOWN)
        contracts = steps * spec.lot_step_contracts
        btc = contracts * spec.contract_size_btc
        discarded = req - btc

    if contracts < spec.min_contracts:
        return QuantizedSize(
            False,
            f"executable size {contracts} contracts is below the exchange "
            f"minimum {spec.min_contracts}; REJECTED rather than sized up",
            req, contracts, btc, discarded)

    assert btc <= req, "quantized size exceeded the request — rounding went UP"
    assert discarded >= 0
    return QuantizedSize(True, "ok", req, contracts, btc, discarded)


# ======================================================================
# PRICES — ALWAYS IN THE DIRECTION THAT CANNOT INCREASE RISK
# ======================================================================

def _to_tick(price: Decimal, spec: InstrumentSpec, rounding) -> Decimal:
    with localcontext() as ctx:
        ctx.prec = 40
        return (price / spec.tick_size).to_integral_value(rounding) * spec.tick_size


def quantize_stop(requested, side: Side,
                  spec: InstrumentSpec = BTC_USDT_SWAP) -> QuantizedPrice:
    """Round a stop TOWARD ENTRY, which can only REDUCE maximum loss.

    long  -> stop sits below entry -> round UP   (nearer entry, tighter)
    short -> stop sits above entry -> round DOWN (nearer entry, tighter)

    The opposite choice would widen the stop by up to one tick, i.e. silently
    increase maximum loss. That is forbidden by the A1 rule set, so it is not
    offered as an option.
    """
    req = _dec(requested)
    if req <= 0:
        return QuantizedPrice(False, "stop price is not positive", req, req, Decimal("0"))
    p = _to_tick(req, spec, ROUND_UP if side == "long" else ROUND_DOWN)
    if p <= 0:
        return QuantizedPrice(False, "stop quantized to a non-positive price",
                              req, p, p - req)
    return QuantizedPrice(True, "ok", req, p, p - req)


def quantize_target(requested, side: Side,
                    spec: InstrumentSpec = BTC_USDT_SWAP) -> QuantizedPrice:
    """Round a target TOWARD ENTRY: claims slightly less reward, never more."""
    req = _dec(requested)
    if req <= 0:
        return QuantizedPrice(False, "target price is not positive", req, req, Decimal("0"))
    p = _to_tick(req, spec, ROUND_DOWN if side == "long" else ROUND_UP)
    if p <= 0:
        return QuantizedPrice(False, "target quantized to a non-positive price",
                              req, p, p - req)
    return QuantizedPrice(True, "ok", req, p, p - req)


def quantize_limit_entry(requested, side: Side,
                         spec: InstrumentSpec = BTC_USDT_SWAP) -> QuantizedPrice:
    """Round a limit entry to the PASSIVE side: the fill can never be worse.

    long buy  -> round DOWN (bid lower)
    short sell-> round UP   (offer higher)
    """
    req = _dec(requested)
    if req <= 0:
        return QuantizedPrice(False, "entry price is not positive", req, req, Decimal("0"))
    p = _to_tick(req, spec, ROUND_DOWN if side == "long" else ROUND_UP)
    if p <= 0:
        return QuantizedPrice(False, "entry quantized to a non-positive price",
                              req, p, p - req)
    return QuantizedPrice(True, "ok", req, p, p - req)


def is_on_tick(price, spec: InstrumentSpec = BTC_USDT_SWAP) -> bool:
    with localcontext() as ctx:
        ctx.prec = 40
        return (_dec(price) % spec.tick_size) == 0


def is_on_lot(contracts, spec: InstrumentSpec = BTC_USDT_SWAP) -> bool:
    with localcontext() as ctx:
        ctx.prec = 40
        return (_dec(contracts) % spec.lot_step_contracts) == 0
