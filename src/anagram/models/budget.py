"""`Gate`: the only spend wrapper. A paid model runs only inside it.

The gate uses the spend ledger (`BudgetLedger`, `check_paid_runs` in
`anagram.models.ledger`); it does not copy or change them.

The constructor refuses to run without:

- an approved, unexpired budget `{approved_by, budget_usd, expires}`,
- prices for the model (from the profile or the price table),
- a ledger whose limit is not more than the approved budget.

For each `generate` call, the gate:

1. asks the model if a call can start (`ready`: for example, a key exists),
2. reserves the upper cost of the call in the ledger: 1 input token for each
   2 bytes of the prompt and the schema (plus 64), and the full output limit,
   for each attempt that the model can bill. If the reservation would go over
   the limit, the ledger refuses and no call is sent.
3. sends the call,
4. records the model id, the tokens, and the cost. The cost is the cost that
   the provider reports, else the tokens times the prices.

A reservation is never refunded. A call that fails keeps its reservation, so
the spend stays below the limit. If a provider reports a cost that is more
than the reservation, the ledger halts. No ledger row holds a prompt, a key,
or a raw response.

The gate does not retry. A caller that retries calls `generate` again, and
that makes a new reservation.

`UsageGate` is the wrapper of a model with no price that is not on this
computer (a university endpoint, for example): it counts calls and characters
against a limit for each day, and refuses a call that would go over it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing
from dataclasses import replace
from datetime import UTC, date, datetime
from decimal import ROUND_CEILING, Decimal
from pathlib import Path

from anagram.models.base import (
    BudgetRefused,
    Capabilities,
    ModelError,
    TextModel,
    TextReply,
    TextRequest,
)
from anagram.models.ledger import (
    LONG_PROMPT_TOKENS,
    BudgetLedger,
    EngineError,
    check_paid_runs,
    nanodollars,
)


def _nano_ceil(usd: Decimal) -> int:
    return int((usd * 10**9).to_integral_value(rounding=ROUND_CEILING))


def ledger_path(home: str | Path, budget: dict) -> Path:
    """`<home>/spend/<16 hex of sha256(budget)>.sqlite`. A new approval gives a
    new ledger, so the ledger of an old approval is not changed."""
    canonical = json.dumps(budget, separators=(",", ":"), sort_keys=True, default=str)
    name = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
    return Path(home) / "spend" / f"{name}.sqlite"


def open_ledger(home: str | Path, budget: dict, today: date | None = None) -> BudgetLedger:
    """The ledger of this approval. The limit is the approved budget."""
    try:
        cfg = check_paid_runs(budget, today)
        return BudgetLedger(ledger_path(home, cfg), cfg["budget_usd"])
    except EngineError as exc:
        raise BudgetRefused(str(exc)) from None


def ledger_state(home: str | Path | None, budget: object, today: date | None = None) -> dict:
    """`{"breached", "budget_usd", "spent_usd"}` of an approval. `spent_usd` is
    the sum of the reservations (a reservation is never refunded). It makes no
    ledger file. Raise `BudgetRefused` if the approval is not valid."""
    try:
        cfg = check_paid_runs(budget, today)
        limit = nanodollars(cfg["budget_usd"])
    except EngineError as exc:
        raise BudgetRefused(str(exc)) from None
    out = {"breached": False, "budget_usd": Decimal(limit) / 10**9, "spent_usd": Decimal(0)}
    if home is not None and ledger_path(home, cfg).exists():
        try:
            snap = BudgetLedger(ledger_path(home, cfg), cfg["budget_usd"]).snapshot()
        except EngineError as exc:
            raise BudgetRefused(str(exc)) from None
        out["breached"] = snap["breached"]
        out["spent_usd"] = Decimal(snap["reserved_nanousd"]) / 10**9
    return out


class Gate(TextModel):
    def __init__(
        self,
        model: TextModel,
        ledger: BudgetLedger,
        budget: dict,
        *,
        today: date | None = None,
    ) -> None:
        try:
            cfg = check_paid_runs(budget, today)
            approved = nanodollars(cfg["budget_usd"])
        except EngineError as exc:
            raise BudgetRefused(str(exc)) from None
        if model.prices is None:
            raise BudgetRefused("no_prices")
        price_in, price_out = model.prices
        if (
            not (price_in.is_finite() and price_out.is_finite())
            or price_in < 0
            or price_out < 0
            or (price_in == 0 and price_out == 0)
        ):
            raise BudgetRefused("invalid_prices")
        if ledger.limit_nano > approved:
            raise BudgetRefused("ledger limit is more than the approved budget")
        self.model = model
        self.ledger = ledger
        self.budget = cfg
        self._today = today
        self._lock = threading.Lock()
        self.stats = {
            "calls": 0,
            "cost_from_provider": 0,
            "cost_nanousd": 0,
            "errors": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "refusals": 0,
        }

    # The disclosure fields are those of the model inside.
    profile_id = property(lambda self: self.model.profile_id)  # type: ignore[assignment]
    model_id = property(lambda self: self.model.model_id)  # type: ignore[assignment]
    external = property(lambda self: self.model.external)  # type: ignore[assignment]
    recipient = property(lambda self: self.model.recipient)  # type: ignore[assignment]
    paid = property(lambda self: self.model.paid)  # type: ignore[assignment]
    reads = property(lambda self: self.model.reads)  # type: ignore[assignment]
    prices = property(lambda self: self.model.prices)  # type: ignore[assignment]

    def capabilities(self) -> Capabilities:
        return self.model.capabilities()

    def probe(self) -> dict:
        return self.model.probe()

    def ready(self) -> None:
        self.model.ready()

    def output_limit(self, request: TextRequest) -> int:
        return self.model.output_limit(request)

    def max_attempts(self, request: TextRequest) -> int:
        return self.model.max_attempts(request)

    # -------------------------------------------------------------- costs

    def usd(self, input_tokens: int, output_tokens: int) -> Decimal:
        if input_tokens < 0 or output_tokens < 0:
            raise BudgetRefused("invalid_tokens")
        price_in, price_out = self.model.prices  # type: ignore[misc]
        return (price_in * input_tokens + price_out * output_tokens) / Decimal(1_000_000)

    def reserve_usd(self, request: TextRequest) -> Decimal:
        """Upper cost of one `generate` call."""
        size = len(request.system.encode("utf-8")) + len(request.user.encode("utf-8"))
        if request.schema is not None:
            # In the "json" and "text" modes the schema is also in the prompt.
            size += 2 * len(json.dumps(request.schema).encode("utf-8")) + 256
        tokens = size // 2 + 64
        if tokens > LONG_PROMPT_TOKENS:
            raise BudgetRefused("prompt too long for the price table")
        out_limit = self.model.output_limit(request)
        if out_limit < 0:
            raise BudgetRefused("invalid_output_limit")
        attempts = max(1, self.model.max_attempts(request))
        return self.usd(tokens, out_limit) * attempts

    def route(self, request: TextRequest) -> str:
        return f"{request.purpose or 'text'}:{self.model.model_id}"

    # ---------------------------------------------------------------- call

    def generate(self, request: TextRequest) -> TextReply:
        try:
            check_paid_runs(self.budget, self._today)  # the approval can expire in a long run
        except EngineError as exc:
            raise BudgetRefused(str(exc)) from None
        self.model.ready()  # no key: refuse before any reservation
        amount = _nano_ceil(self.reserve_usd(request))
        if amount <= 0:
            raise BudgetRefused("invalid_reservation")
        try:
            key = self.ledger.reserve(self.route(request), amount)
        except EngineError as exc:
            raise BudgetRefused(str(exc)) from None
        try:
            reply = self.model.generate(request)
        except ModelError as exc:
            self._close(
                key, {"error": exc.code, "model": self.model.model_id, "status": exc.status}
            )
            raise
        except BaseException as exc:
            self._close(key, {"error": type(exc).__name__, "model": self.model.model_id})
            raise
        return self._record(key, reply)

    def stream(self, request: TextRequest) -> Iterator[str]:
        """One piece, from the gated `generate`. A streamed call reports no
        token count that the ledger can record, so the gate does not stream."""
        reply = self.generate(request)
        if reply.text and not reply.refusal:
            yield reply.text

    def _close(self, key: str, usage: dict) -> None:
        """Close the reservation of a failed call. It is not refunded."""
        with self._lock:
            self.stats["errors"] += 1
        self.ledger.finish(key, usage)

    def _record(self, key: str, reply: TextReply) -> TextReply:
        in_tokens = max(0, reply.input_tokens)
        out_tokens = max(0, reply.output_tokens)
        reported = reply.cost is not None
        cost = reply.cost if reported else self.usd(in_tokens, out_tokens)
        usage = {
            "cost": str(cost),
            "cost_source": "provider" if reported else "tokens",
            "input_tokens": in_tokens,
            "model": reply.model or self.model.model_id,
            "output_tokens": out_tokens,
            "stop_reason": reply.stop,
        }
        if reply.provider:
            usage["provider"] = reply.provider
        try:
            # finish() halts the ledger and raises if the cost is invalid or
            # more than the reservation.
            self.ledger.finish(key, usage)
        except EngineError as exc:
            raise BudgetRefused(str(exc)) from None
        cost_nano = _nano_ceil(cost)  # type: ignore[arg-type]
        with self._lock:
            self.stats["calls"] += 1
            self.stats["input_tokens"] += in_tokens
            self.stats["output_tokens"] += out_tokens
            self.stats["refusals"] += int(reply.refusal)
            self.stats["cost_nanousd"] += cost_nano
            self.stats["cost_from_provider"] += int(reported)
        return replace(reply, input_tokens=in_tokens, output_tokens=out_tokens, cost=cost)


# ----------------------------------------------------------- usage limit

# The limit of a model that has no price (security review): a university
# or other endpoint that is not on this computer. One UTC day of calls and
# characters for each profile. A profile can set its own `limit`.
DEFAULT_USAGE_LIMIT = {"calls": 200, "chars": 2_000_000}


def usage_path(home: str | Path, profile_id: str) -> Path:
    """`<home>/spend/usage-<16 hex of sha256(profile id)>.sqlite`."""
    name = hashlib.sha256(profile_id.encode("utf-8")).hexdigest()[:16]
    return Path(home) / "spend" / f"usage-{name}.sqlite"


class UsageLedger:
    """Counts of calls and characters for each UTC day, in one SQLite file.
    A count is never given back. No row holds a prompt or an answer."""

    def __init__(self, path: str | Path, limit: dict) -> None:
        self.path = Path(path)
        self.limit = {"calls": int(limit["calls"]), "chars": int(limit["chars"])}
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        with self._lock, closing(self._connect()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS usage (day TEXT PRIMARY KEY,"
                " calls INTEGER NOT NULL, chars INTEGER NOT NULL)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30, isolation_level=None)

    def used(self, day: date) -> dict:
        with self._lock, closing(self._connect()) as db:
            row = db.execute(
                "SELECT calls, chars FROM usage WHERE day = ?", (day.isoformat(),)
            ).fetchone()
        return {"calls": row[0], "chars": row[1]} if row else {"calls": 0, "chars": 0}

    def is_open(self, day: date) -> bool:
        used = self.used(day)
        return used["calls"] < self.limit["calls"] and used["chars"] < self.limit["chars"]

    def add(self, day: date, calls: int, chars: int, *, check: bool) -> None:
        """Add to the counts of `day` in one transaction. With `check`, refuse
        (`BudgetRefused("usage_limit")`) and add nothing if a count would go
        over the limit."""
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT calls, chars FROM usage WHERE day = ?", (day.isoformat(),)
                ).fetchone() or (0, 0)
                new_calls, new_chars = row[0] + calls, row[1] + chars
                if check and (new_calls > self.limit["calls"] or new_chars > self.limit["chars"]):
                    raise BudgetRefused("usage_limit")
                db.execute(
                    "INSERT INTO usage (day, calls, chars) VALUES (?, ?, ?) ON CONFLICT (day)"
                    " DO UPDATE SET calls = excluded.calls, chars = excluded.chars",
                    (day.isoformat(), new_calls, new_chars),
                )
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise


class UsageGate(TextModel):
    """The wrapper of a model that has no price and that is not on this
    computer. Before each `generate`, it counts each attempt that the model
    can make (`max_attempts`) as one call, and the characters of the prompt
    and the schema for each attempt. If a count would go over the limit of
    the day, no call is sent. After the call, it adds the characters of the
    answer. It does not retry; a caller that retries makes a new count."""

    # The limit takes the place of the spend gate: a caller does not put this
    # wrapper inside `Gate`.
    usage_limited = True

    def __init__(self, model: TextModel, ledger: UsageLedger, *, today: date | None = None):
        self.model = model
        self.ledger = ledger
        self._today = today

    profile_id = property(lambda self: self.model.profile_id)  # type: ignore[assignment]
    model_id = property(lambda self: self.model.model_id)  # type: ignore[assignment]
    external = property(lambda self: self.model.external)  # type: ignore[assignment]
    recipient = property(lambda self: self.model.recipient)  # type: ignore[assignment]
    paid = property(lambda self: self.model.paid)  # type: ignore[assignment]
    reads = property(lambda self: self.model.reads)  # type: ignore[assignment]
    prices = property(lambda self: self.model.prices)  # type: ignore[assignment]

    def capabilities(self) -> Capabilities:
        return self.model.capabilities()

    def probe(self) -> dict:
        return self.model.probe()

    def ready(self) -> None:
        self.model.ready()

    def output_limit(self, request: TextRequest) -> int:
        return self.model.output_limit(request)

    def max_attempts(self, request: TextRequest) -> int:
        return self.model.max_attempts(request)

    def day(self) -> date:
        return self._today or datetime.now(UTC).date()

    @staticmethod
    def request_chars(request: TextRequest) -> int:
        size = len(request.system) + len(request.user)
        if request.schema is not None:
            size += len(json.dumps(request.schema))
        return size

    def generate(self, request: TextRequest) -> TextReply:
        self.model.ready()
        attempts = max(1, self.model.max_attempts(request))
        day = self.day()
        self.ledger.add(day, attempts, attempts * self.request_chars(request), check=True)
        reply = self.model.generate(request)
        self.ledger.add(day, 0, len(reply.text or ""), check=False)
        return reply

    def stream(self, request: TextRequest) -> Iterator[str]:
        """One piece, from the counted `generate`."""
        reply = self.generate(request)
        if reply.text and not reply.refusal:
            yield reply.text
