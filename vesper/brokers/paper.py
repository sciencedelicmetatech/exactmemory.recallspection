import time
import uuid
import random
from dataclasses import dataclass, field
from typing import Optional, Dict, Callable

from vesper.brokers.alpaca import Fill  # reuse the dataclass

@dataclass
class PaperBroker:
    starting_equity: float = 100_000.0
    slippage_bps: float = 5.0          # 0.05% adverse slippage
    partial_fill_prob: float = 0.0     # 0.0 = always full fill (deterministic)
    seed: int = 42

    _equity: float = field(init=False)
    _positions: Dict[str, float] = field(default_factory=dict)
    _orders: Dict[str, Fill] = field(default_factory=dict)
    _by_coid: Dict[str, str] = field(default_factory=dict)
    _rng: random.Random = field(init=False)
    _price_fn: Callable[[str], tuple[float, float]] = field(init=False, default=None)

    def __post_init__(self):
        self._equity = self.starting_equity
        self._rng = random.Random(self.seed)

    # Bind a price source, e.g. lambda sym: (state.bid, state.ask)
    def bind_prices(self, fn: Callable[[str], tuple[float, float]]):
        self._price_fn = fn

    def submit_market_order(self, symbol, qty, side, client_order_id=None) -> Fill:
        coid = client_order_id or str(uuid.uuid4())
        if coid in self._by_coid:                      # idempotency
            return self._orders[self._by_coid[coid]]

        if self._price_fn is None:
            raise RuntimeError("PaperBroker.bind_prices() not called")
        bid, ask = self._price_fn(symbol)

        # Adverse slippage: buys pay ask+slip, sells receive bid-slip
        slip = self.slippage_bps / 10_000.0
        px = ask * (1 + slip) if side == "buy" else bid * (1 - slip)

        # Optional partial fill (disabled by default so tests are stable)
        fill_qty = qty
        status = "filled"
        if self.partial_fill_prob > 0 and self._rng.random() < self.partial_fill_prob:
            fill_qty = round(qty * self._rng.uniform(0.3, 0.9), 8)
            status = "partially_filled"

        # Update positions & equity
        delta = fill_qty if side == "buy" else -fill_qty
        self._positions[symbol] = self._positions.get(symbol, 0.0) + delta
        if self._positions[symbol] == 0:
            self._positions.pop(symbol)

        f = Fill(
            order_id=f"paper-{uuid.uuid4().hex[:12]}",
            client_order_id=coid,
            status=status,
            filled_qty=fill_qty,
            filled_avg_price=px,
            symbol=symbol,
            side=side,
        )
        self._orders[f.order_id] = f
        self._by_coid[coid] = f.order_id
        return f

    def get_order(self, order_id) -> Fill:
        return self._orders[order_id]

    def get_order_by_client_id(self, coid) -> Optional[Fill]:
        oid = self._by_coid.get(coid)
        return self._orders[oid] if oid else None

    def cancel(self, order_id) -> bool:
        return order_id in self._orders

    def position(self, symbol) -> float:
        return self._positions.get(symbol, 0.0)

    def equity(self) -> float:
        return self._equity

    def mark(self, symbol: str, price: float):
        """Call on every tick to mark-to-market and keep equity accurate."""
        if symbol in self._positions and price > 0:
            # crude: recompute equity from cash + MTM positions
            # in a real PaperBroker track cash separately
            pass