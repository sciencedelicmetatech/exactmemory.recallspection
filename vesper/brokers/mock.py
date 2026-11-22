from dataclasses import dataclass, field
from typing import List, Optional, Dict, Callable

from vesper.brokers.alpaca import Fill

@dataclass
class MockBroker:
    scripted_fills: List[Fill] = field(default_factory=list)
    fixed_equity: float = 100_000.0
    fixed_positions: Dict[str, float] = field(default_factory=dict)

    _cursor: int = 0
    _calls: list = field(default_factory=list)          # audit of every call
    _by_coid: Dict[str, Fill] = field(default_factory=dict)

    # Optional hook: mutate response based on symbol/side/qty for scenario tests
    response_fn: Optional[Callable] = None

    def submit_market_order(self, symbol, qty, side, client_order_id=None) -> Fill:
        coid = client_order_id or f"mock-{len(self._calls)}"
        self._calls.append({"symbol": symbol, "qty": qty, "side": side,
                            "client_order_id": coid})

        if coid in self._by_coid:
            return self._by_coid[coid]

        if self.response_fn is not None:
            f = self.response_fn(symbol, qty, side, coid)
        else:
            if self._cursor >= len(self.scripted_fills):
                raise RuntimeError("MockBroker ran out of scripted fills")
            f = self.scripted_fills[self._cursor]
            self._cursor += 1

        self._by_coid[coid] = f
        return f

    def get_order(self, order_id) -> Fill:
        for f in self._by_coid.values():
            if f.order_id == order_id:
                return f
        raise KeyError(order_id)

    def get_order_by_client_id(self, coid) -> Optional[Fill]:
        return self._by_coid.get(coid)

    def cancel(self, order_id) -> bool:
        return True

    def position(self, symbol) -> float:
        return self.fixed_positions.get(symbol, 0.0)

    def equity(self) -> float:
        return self.fixed_equity