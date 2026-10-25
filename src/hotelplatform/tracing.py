"""Request tracing, OpenTelemetry-style, without the OpenTelemetry SDK.

One trace per request, one span per step:

    with tracing.new_trace("hotel-ops-assistant", session_id=sid) as trace:
        with trace.span("input_checks", chars=len(q)) as s:
            ...
            s.set(verdict="allowed")
        with trace.span("model_call", model=MODEL) as s:
            ...
            s.set(tokens_in=812, tokens_out=164, stop_reason="end_turn")

IDs and fields use OpenTelemetry's shapes (32-hex trace ID, 16-hex span ID, parent span, start, duration, status
ok/error, attributes), so moving to a real OTel exporter later means writing an exporter, not changing call sites
(decision 3 in docs/DECISIONS.md). The user sees the first 8 characters on errors ("Reference: 4f1c9a2e"); Admin
shows the whole trace as a waterfall.

Attributes are redacted (PII, secrets) and truncated when the trace is turned into rows, never on the hot path.
"""

import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime

from hotelplatform import pii
from hotelplatform.secrets_mask import mask_value

MAX_ATTR_CHARS = 2000
MAX_SPANS = 200  # a runaway loop can't fill the log

_current_trace: ContextVar["Trace | None"] = ContextVar("hotel_trace", default=None)
_current_span: ContextVar["Span | None"] = ContextVar("hotel_span", default=None)


def new_id(nbytes: int) -> str:
    return secrets.token_hex(nbytes)


def short_id(trace_id: str) -> str:
    return (trace_id or "")[:8]


@dataclass
class Span:
    name: str
    trace_id: str
    span_id: str
    parent_id: str | None
    start_offset_ms: float
    attributes: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    status: str = "ok"  # ok | error | blocked
    duration_ms: float | None = None
    _t0: float = field(default_factory=time.perf_counter, repr=False)

    def set(self, **attrs) -> "Span":
        self.attributes.update(attrs)
        return self

    def event(self, name: str, **attrs) -> None:
        self.events.append({"name": name, "at_ms": round((time.perf_counter() - self._t0) * 1000, 1), **attrs})

    def fail(self, error: BaseException | str, status: str = "error") -> None:
        self.status = status
        if isinstance(error, BaseException):
            self.attributes["error_type"] = type(error).__name__
            self.attributes["error_message"] = str(error)[:300]
        else:
            self.attributes["error_message"] = str(error)[:300]

    def block(self, reason: str) -> None:
        self.status = "blocked"
        self.attributes["blocked_reason"] = reason

    def end(self) -> None:
        if self.duration_ms is None:
            self.duration_ms = round((time.perf_counter() - self._t0) * 1000, 1)


@dataclass
class Trace:
    app: str
    trace_id: str = field(default_factory=lambda: new_id(16))
    session_id: str | None = None
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="milliseconds"))
    spans: list[Span] = field(default_factory=list)
    _t0: float = field(default_factory=time.perf_counter, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def reference(self) -> str:
        return short_id(self.trace_id)

    def elapsed_ms(self) -> float:
        return round((time.perf_counter() - self._t0) * 1000, 1)

    @contextmanager
    def span(self, name: str, parent: Span | None = None, **attrs) -> Iterator[Span]:
        """A step. Exceptions mark the span as error and propagate (the caller decides what the user sees)."""
        parent = parent or _current_span.get()
        span = Span(
            name=name,
            trace_id=self.trace_id,
            span_id=new_id(8),
            parent_id=parent.span_id if parent and parent.trace_id == self.trace_id else None,
            start_offset_ms=self.elapsed_ms(),
            attributes=dict(attrs),
        )
        with self._lock:
            if len(self.spans) < MAX_SPANS:
                self.spans.append(span)
        token = _current_span.set(span)
        try:
            yield span
        except BaseException as exc:
            if span.status == "ok":
                span.fail(exc)
            raise
        finally:
            span.end()
            _current_span.reset(token)

    def record(self, name: str, duration_ms: float, status: str = "ok", **attrs) -> Span:
        """A step measured elsewhere (e.g. inside a streaming loop): added with the given duration."""
        span = Span(name, self.trace_id, new_id(8), None, max(0.0, self.elapsed_ms() - duration_ms), dict(attrs))
        span.status, span.duration_ms = status, round(duration_ms, 1)
        with self._lock:
            if len(self.spans) < MAX_SPANS:
                self.spans.append(span)
        return span

    @property
    def status(self) -> str:
        """error beats blocked beats ok."""
        statuses = {s.status for s in self.spans}
        return "error" if "error" in statuses else "blocked" if "blocked" in statuses else "ok"

    def span_rows(self) -> list[dict]:
        """Redacted, truncated rows for the ops_trace_span table."""
        rows = []
        for s in self.spans:
            s.end()
            rows.append(
                {
                    "trace_id": self.trace_id,
                    "span_id": s.span_id,
                    "parent_id": s.parent_id,
                    "name": s.name,
                    "start_ms": s.start_offset_ms,
                    "duration_ms": s.duration_ms,
                    "status": s.status,
                    "attributes": clean(s.attributes),
                    "events": clean(s.events),
                }
            )
        return rows


def clean(value):
    """PII and secrets removed, long strings cut. Applied to everything a span stores."""
    return _truncate(pii.scrub(mask_value(value)))  # secrets first: PII patterns would break their shapes


def _truncate(value):
    if isinstance(value, str):
        return value if len(value) <= MAX_ATTR_CHARS else value[:MAX_ATTR_CHARS] + f"... [{len(value)} chars]"
    if isinstance(value, dict):
        return {k: _truncate(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_truncate(v) for v in value[:50]]
    if isinstance(value, float):
        return round(value, 4)
    return value


@contextmanager
def new_trace(app: str, session_id: str | None = None) -> Iterator[Trace]:
    trace = Trace(app=app, session_id=session_id)
    token = _current_trace.set(trace)
    try:
        yield trace
    finally:
        _current_trace.reset(token)


def current() -> Trace | None:
    return _current_trace.get()


@contextmanager
def span(name: str, **attrs) -> Iterator[Span | None]:
    """A span on the current trace, or a no-op when there is none (library code can always call it)."""
    trace = current()
    if trace is None:
        yield None
        return
    with trace.span(name, **attrs) as s:
        yield s
