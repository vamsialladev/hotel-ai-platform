"""Structured JSON logs, one format for every app: one line per event on stdout.

    {"ts": "2026-10-25T18:02:11.204Z", "level": "info", "app": "hotel-ops-assistant", "version": "1.7.0+b111480",
     "event": "app_start", ...fields}

Streamlit Cloud's "Manage app" log viewer and `docker logs` show stdout, so nothing else is needed to read them,
and any log shipper can parse them later. Every line goes through secrets masking and PII scrubbing first; a
logging failure is swallowed (and counted), never raised into a request.

Standard events (helpers below): app_start, config_loaded, dependency_health, cap_hit, rate_limited, retry,
slow_request, exception, guardrail_block, log_write_failed.
"""

import json
import sys
import threading
import traceback
from datetime import UTC, datetime

from hotelplatform import pii
from hotelplatform.secrets_mask import describe_settings, mask, mask_value

_STATE = {"app": "unknown", "version": "unknown", "stream": None, "failures": 0}
_LOCK = threading.Lock()


def configure(app: str, version: str, stream=None) -> None:
    _STATE.update(app=app, version=version, stream=stream)


def failures() -> int:
    return _STATE["failures"]


def event(name: str, level: str = "info", **fields) -> dict | None:
    """Write one line. Returns the record (tests read it) or None if writing failed."""
    try:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": level,
            "app": _STATE["app"],
            "version": _STATE["version"],
            "event": name,
            **pii.scrub(mask_value(fields)),  # secrets first: PII patterns would break their shapes
        }
        line = json.dumps(record, default=str, ensure_ascii=False)
        with _LOCK:
            stream = _STATE["stream"] or sys.stdout
            stream.write(line + "\n")
            stream.flush()
        return record
    except Exception:
        _STATE["failures"] += 1
        return None


def app_start(**fields) -> None:
    event("app_start", python=sys.version.split()[0], **fields)


def config_loaded(setting_names: list[str], **non_secret) -> None:
    """Which settings are set or missing (never their values), plus any non-secret settings worth seeing."""
    event("config_loaded", settings=describe_settings(setting_names), **non_secret)


def dependency_health(results: dict[str, str]) -> None:
    """{"anthropic": "ok", "database": "missing", "embeddings": "ok"}"""
    level = "warning" if any(v not in ("ok", "not used") for v in results.values()) else "info"
    event("dependency_health", level=level, dependencies=results)


def cap_hit(cap: str, trace_id: str | None = None, **fields) -> None:
    event("cap_hit", level="warning", cap=cap, trace_id=trace_id, **fields)


def rate_limited(scope: str, trace_id: str | None = None) -> None:
    event("rate_limited", level="warning", scope=scope, trace_id=trace_id)


def retry(what: str, attempt: int, error_type: str, trace_id: str | None = None) -> None:
    event("retry", level="warning", what=what, attempt=attempt, error_type=error_type, trace_id=trace_id)


def slow_request(latency_ms: float, target_ms: float, trace_id: str | None = None, **fields) -> None:
    event("slow_request", level="warning", latency_ms=latency_ms, target_ms=target_ms, trace_id=trace_id, **fields)


def exception(exc: BaseException, trace_id: str | None = None, where: str = "") -> None:
    """Exception with a redacted stack trace (secrets masked, PII scrubbed, last 12 frames)."""
    stack = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)[-12:])
    event(
        "exception",
        level="error",
        where=where,
        error_type=type(exc).__name__,
        error_message=mask(str(exc))[:300],
        stack=stack,
        trace_id=trace_id,
    )
