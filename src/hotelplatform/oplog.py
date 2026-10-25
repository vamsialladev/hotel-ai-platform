"""Request log, trace spans and feedback for every hotel app, in one shared database.

    store = OpsStore("hotel-ops-assistant")                 # DATABASE_URL picks the backend
    store.submit(trace, request_row(trace, request_type="question", status="ok", latency_ms=1210, ...))
    store.feedback(trace_id, "down", "wrong hotel")

Backends (DATABASE_URL):
    postgresql://...        Postgres (Neon free tier on the live apps)
    sqlite:///path.db       SQLite (local runs, tests)
    unset                   JSON Lines files under logs/ (CI never needs a database)

Tables, shared by all apps (the `app` column separates them):
    ops_request_log  one row per request: time, app, session, type, status, error, latency, tokens, cost, model,
                     tool calls, retrieval sources, safety flags, trace ID, source (user | eval | keepawake)
    ops_trace_span   one row per step of a request (the Admin waterfall)
    ops_feedback     thumbs up/down + reason, linked by trace ID

Rules, each with a test:
- PII and secrets are removed before a row is queued, so nothing personal is ever written.
- submit() never blocks and never raises: rows go on a bounded queue; one background thread writes them in
  batches. A full queue drops the row and counts it; a failed write goes to the JSONL file instead and is counted.
- Neon free tier: writes are batched (one round trip per batch), the connection is closed after 60 s idle so the
  database can suspend, at most two connections per process (writer + Admin reads), keep-awake visits are never
  written, and nothing connects at app start.
- Rows older than `retention_days` (30) are deleted at most once a day per process (and by the retention script).
"""

import json
import logging
import math
import os
import queue
import sqlite3
import threading
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from hotelplatform import jsonlog, pii
from hotelplatform.secrets_mask import mask_value

logger = logging.getLogger("hotelplatform.oplog")

STATUSES = ("ok", "refused", "blocked", "error", "timeout", "capped")
FAILURES = ("error", "timeout")
BOT_SOURCES = ("keepawake", "healthcheck")

REQUEST_COLUMNS = (
    "ts",
    "app",
    "trace_id",
    "session_id",
    "request_type",
    "status",
    "error_type",
    "error_message",
    "latency_ms",
    "tokens_in",
    "tokens_out",
    "cost_usd",
    "model",
    "tool_calls",
    "sources",
    "safety_flags",
    "source",
    "version",
    "data",
)
SPAN_COLUMNS = (
    "ts",
    "app",
    "trace_id",
    "span_id",
    "parent_id",
    "name",
    "start_ms",
    "duration_ms",
    "status",
    "attributes",
    "events",
)
FEEDBACK_COLUMNS = ("ts", "app", "trace_id", "rating", "reason")
JSON_COLUMNS = {"tool_calls", "sources", "safety_flags", "data", "attributes", "events"}
TABLES = {"ops_request_log": REQUEST_COLUMNS, "ops_trace_span": SPAN_COLUMNS, "ops_feedback": FEEDBACK_COLUMNS}
NUMERIC = {"latency_ms": "REAL", "tokens_in": "INTEGER", "tokens_out": "INTEGER", "cost_usd": "REAL",
           "start_ms": "REAL", "duration_ms": "REAL"}  # fmt: skip


def schema(pk: str) -> list[str]:
    stmts = []
    for table, cols in TABLES.items():
        defs = ", ".join(f"{c} {NUMERIC.get(c, 'TEXT')}" for c in cols)
        stmts.append(f"CREATE TABLE IF NOT EXISTS {table} (id {pk}, {defs})")
        stmts.append(f"CREATE INDEX IF NOT EXISTS {table}_app_ts ON {table} (app, ts)")
        if "trace_id" in cols:
            stmts.append(f"CREATE INDEX IF NOT EXISTS {table}_trace ON {table} (trace_id)")
    return stmts


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def backend_of(url: str | None) -> str:
    if not url:
        return "file"
    if url.startswith(("postgres://", "postgresql://")):
        return "postgres"
    if url.startswith("sqlite:///"):
        return "sqlite"
    return "invalid"


def safe_error(exc: BaseException) -> str:
    """Error class only: a driver message can contain the host or user name."""
    return type(exc).__name__


def request_row(
    trace,
    *,
    request_type: str,
    status: str,
    latency_ms: float | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    tokens_in: int = 0,
    tokens_out: int = 0,
    cost_usd: float = 0.0,
    model: str | None = None,
    tool_calls: list | None = None,
    sources: list | None = None,
    safety_flags: list | None = None,
    source: str = "user",
    version: str | None = None,
    data: dict | None = None,
) -> dict:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}, got {status!r}")
    return {
        "ts": trace.started_at,
        "app": trace.app,
        "trace_id": trace.trace_id,
        "session_id": trace.session_id,
        "request_type": request_type,
        "status": status,
        "error_type": error_type,
        "error_message": (error_message or None) and str(error_message)[:300],
        "latency_ms": latency_ms if latency_ms is not None else trace.elapsed_ms(),
        "tokens_in": int(tokens_in or 0),
        "tokens_out": int(tokens_out or 0),
        "cost_usd": round(float(cost_usd or 0.0), 6),
        "model": model,
        "tool_calls": list(tool_calls or []),
        "sources": list(sources or []),
        "safety_flags": list(safety_flags or []),
        "source": source,
        "version": version,
        "data": data or {},
    }


def redact_row(row: dict) -> dict:
    return pii.redact_record(mask_value(row))  # secrets first: PII patterns would break their shapes


class OpsStore:
    def __init__(
        self,
        app: str,
        url: str | None = None,
        log_dir: str | Path = "logs",
        retention_days: int = 30,
        batch_size: int = 50,
        flush_interval_s: float = 2.0,
        idle_close_s: float = 60.0,
        max_queue: int = 2000,
    ):
        self.app = app
        self.url = os.environ.get("DATABASE_URL", "") if url is None else url
        self.backend = backend_of(self.url)
        self.log_dir = Path(log_dir)
        self.retention_days = retention_days
        self.batch_size = batch_size
        self.flush_interval_s = flush_interval_s
        self.idle_close_s = idle_close_s
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()
        self._db_lock = threading.RLock()
        self._inflight_lock = threading.Lock()
        self._inflight = 0
        self._conn = None
        self._last_used = 0.0
        self._last_purge = 0.0
        self._schema_ready = False
        self.counters = Counter()  # queued, written, dropped, write_errors, fallback_writes, purged
        self.last_error: str | None = None

    # ---------------------------------------------------------------- writes
    def submit(self, trace, row: dict) -> bool:
        """Queue a request row and the trace's spans. Never blocks, never raises. False if dropped or skipped."""
        try:
            if row.get("source") in BOT_SOURCES:
                self.counters["skipped_bot"] += 1
                return False
            items = [("ops_request_log", redact_row(row))]
            for span in trace.span_rows() if trace is not None else []:
                items.append(("ops_trace_span", {"ts": row["ts"], "app": self.app, **span}))
            return self._enqueue(items)
        except Exception as exc:  # a bad row must not break the request
            self.counters["dropped"] += 1
            self.last_error = safe_error(exc)
            return False

    def feedback(self, trace_id: str, rating: str, reason: str = "") -> bool:
        row = {"ts": now_iso(), "app": self.app, "trace_id": trace_id, "rating": rating,
               "reason": pii.scrub_text(mask_value(reason or ""))[:500]}  # fmt: skip
        return self._enqueue([("ops_feedback", row)])

    def _enqueue(self, items: list) -> bool:
        try:
            self._queue.put_nowait(items)
        except queue.Full:
            self.counters["dropped"] += 1
            jsonlog.event("log_write_failed", level="warning", reason="queue_full")
            return False
        self.counters["queued"] += 1
        self._ensure_thread()
        return True

    def _ensure_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        with self._start_lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._run, name=f"oplog-{self.app}", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while True:
            batch = self._take_batch(self.flush_interval_s)
            if batch:
                self._write(batch)
            elif self._conn is not None and time.monotonic() - self._last_used > self.idle_close_s:
                self._close()

    def _take_batch(self, timeout: float) -> list:
        """Up to batch_size queued items. A non-empty batch counts as in flight until _write finishes it."""
        batch = []
        try:
            first = self._queue.get(timeout=timeout)
        except queue.Empty:
            return batch
        with self._inflight_lock:
            self._inflight += 1
        batch.extend(first)
        while len(batch) < self.batch_size:
            try:
                batch.extend(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def flush(self, timeout_s: float = 10.0) -> None:
        """Write everything queued now, and wait for a batch the writer thread is busy with (tests, Admin before
        reading, shutdown)."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            batch = self._take_batch(0.01)
            if batch:
                self._write(batch)
            elif self._inflight == 0:
                return
            else:
                time.sleep(0.01)

    def _write(self, batch: list) -> None:
        try:
            self._write_batch(batch)
        finally:
            with self._inflight_lock:
                self._inflight -= 1

    def _write_batch(self, batch: list) -> None:
        by_table: dict[str, list[dict]] = {}
        for table, row in batch:
            by_table.setdefault(table, []).append(row)
        try:
            if self.backend in ("postgres", "sqlite"):
                with self._db_lock:
                    conn = self._connection()
                    for table, rows in by_table.items():
                        self._insert(conn, table, rows)
                    if self.backend == "sqlite":
                        conn.commit()
                    self._last_used = time.monotonic()
                    self._maybe_purge(conn)
            else:
                self._write_files(by_table)
            self.counters["written"] += len(batch)
        except Exception as exc:
            self.counters["write_errors"] += 1
            self.last_error = safe_error(exc)
            jsonlog.event("log_write_failed", level="warning", backend=self.backend, error_type=self.last_error)
            self._close()
            try:
                self._write_files(by_table)
                self.counters["fallback_writes"] += len(batch)
            except Exception:
                self.counters["dropped"] += len(batch)

    def _insert(self, conn, table: str, rows: list[dict]) -> None:
        cols = TABLES[table]
        mark = "%s" if self.backend == "postgres" else "?"
        sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join([mark] * len(cols))})"
        values = [tuple(_encode(c, r.get(c)) for c in cols) for r in rows]
        if self.backend == "postgres":
            with conn.cursor() as cur:
                cur.executemany(sql, values)
        else:
            conn.executemany(sql, values)

    def _write_files(self, by_table: dict) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        for table, rows in by_table.items():
            with open(self.log_dir / f"{table}.jsonl", "a", encoding="utf-8") as f:
                for row in rows:
                    f.write(json.dumps(row, default=str, ensure_ascii=False) + "\n")

    # ---------------------------------------------------------------- connections
    def _connection(self):
        if self._conn is None:
            self._conn = self._open()
            if not self._schema_ready:
                self._create_schema(self._conn)
        return self._conn

    def _open(self):
        if self.backend == "postgres":
            import psycopg  # optional dependency: only the live apps need it

            return psycopg.connect(self.url, connect_timeout=5, autocommit=True, application_name=self.app[:60])
        if self.backend == "sqlite":
            path = Path(self.url.removeprefix("sqlite:///"))
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn
        raise RuntimeError(f"no database for backend {self.backend}")

    def _create_schema(self, conn) -> None:
        pk = "BIGSERIAL PRIMARY KEY" if self.backend == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
        for stmt in schema(pk):
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(stmt)
            else:
                conn.execute(stmt)
        if self.backend == "sqlite":
            conn.commit()
        self._schema_ready = True

    def _close(self) -> None:
        with self._db_lock:  # the writer thread and Admin reads share the connection
            conn, self._conn = self._conn, None
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    # ---------------------------------------------------------------- retention
    def _maybe_purge(self, conn) -> None:
        if time.monotonic() - self._last_purge < 24 * 3600 and self._last_purge:
            return
        self._last_purge = time.monotonic()
        self.counters["purged"] += self.purge(conn)

    def purge(self, conn=None) -> int:
        """Delete this app's rows older than retention_days. Returns how many rows went."""
        cutoff = (datetime.now(UTC) - timedelta(days=self.retention_days)).isoformat(timespec="milliseconds")
        if self.backend == "file":
            return self._purge_files(cutoff)
        own = conn is None
        conn = conn or self._open()
        mark = "%s" if self.backend == "postgres" else "?"
        total = 0
        try:
            if own:
                self._create_schema(conn)
            for table in TABLES:
                sql = f"DELETE FROM {table} WHERE app = {mark} AND ts < {mark}"
                if self.backend == "postgres":
                    with conn.cursor() as cur:
                        cur.execute(sql, (self.app, cutoff))
                        total += cur.rowcount or 0
                else:
                    total += conn.execute(sql, (self.app, cutoff)).rowcount or 0
            if self.backend == "sqlite":
                conn.commit()
        finally:
            if own:
                conn.close()
        return total

    def _purge_files(self, cutoff: str) -> int:
        removed = 0
        for table in TABLES:
            path = self.log_dir / f"{table}.jsonl"
            if not path.exists():
                continue
            rows = _read_jsonl(path)
            keep = [r for r in rows if r.get("app") != self.app or (r.get("ts") or "") >= cutoff]
            removed += len(rows) - len(keep)
            path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in keep), encoding="utf-8")
        return removed

    # ---------------------------------------------------------------- reads (Admin)
    def _select(self, table: str, where: str, params: tuple, order: str = "ts DESC", limit: int = 1000) -> list[dict]:
        if self.backend == "file":
            raise AssertionError("file reads go through _file_rows")
        mark = "%s" if self.backend == "postgres" else "?"
        sql = f"SELECT * FROM {table} WHERE {where.replace('?', mark)} ORDER BY {order} LIMIT {int(limit)}"
        with self._db_lock:
            conn = self._connection()
            self._last_used = time.monotonic()
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    names = [d.name for d in cur.description]
                    out = [dict(zip(names, r, strict=True)) for r in cur.fetchall()]
            else:
                out = [dict(r) for r in conn.execute(sql, params).fetchall()]
        return [_decode(r) for r in out]

    def _file_rows(self, table: str) -> list[dict]:
        path = self.log_dir / f"{table}.jsonl"
        return [r for r in _read_jsonl(path) if r.get("app") == self.app] if path.exists() else []

    def requests(self, since: str | None = None, limit: int = 1000, include_bots: bool = False) -> list[dict]:
        since = since or (datetime.now(UTC) - timedelta(days=self.retention_days)).isoformat(timespec="milliseconds")
        if self.backend == "file":
            rows = sorted((r for r in self._file_rows("ops_request_log") if r.get("ts", "") >= since),
                          key=lambda r: r.get("ts", ""), reverse=True)[:limit]  # fmt: skip
        else:
            rows = self._select("ops_request_log", "app = ? AND ts >= ?", (self.app, since), limit=limit)
        return rows if include_bots else [r for r in rows if r.get("source") not in BOT_SOURCES]

    def spans(self, trace_id: str) -> list[dict]:
        if self.backend == "file":
            rows = [r for r in self._file_rows("ops_trace_span") if r.get("trace_id") == trace_id]
        else:
            rows = self._select("ops_trace_span", "app = ? AND trace_id = ?", (self.app, trace_id), "start_ms ASC")
        return sorted(rows, key=lambda r: r.get("start_ms") or 0)

    def feedback_rows(self, since: str | None = None, limit: int = 1000) -> list[dict]:
        since = since or "0"
        if self.backend == "file":
            return [r for r in self._file_rows("ops_feedback") if r.get("ts", "") >= since][-limit:]
        return self._select("ops_feedback", "app = ? AND ts >= ?", (self.app, since), limit=limit)

    def health(self) -> dict:
        """What the Admin System health panel shows. Counts only, never the URL."""
        info = {"backend": self.backend, "queued_now": self._queue.qsize(), **dict(self.counters)}
        if self.backend == "invalid":
            info["status"] = "DATABASE_URL is not a postgres:// or sqlite:/// URL (using files)"
        elif self.backend == "file":
            info["status"] = "files (no DATABASE_URL): logs reset when the app restarts"
        else:
            info["status"] = "ok" if not self.last_error else f"last error: {self.last_error}"
        return info

    def database_size_mb(self) -> float | None:
        """Neon usage: the whole database's size (the free tier's limit is per project). Postgres only."""
        if self.backend != "postgres":
            return None
        try:
            with self._db_lock:
                conn = self._connection()
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_database_size(current_database())")
                    return round(cur.fetchone()[0] / 1_000_000, 1)
        except Exception as exc:
            self.last_error = safe_error(exc)
            return None


def _encode(col: str, value):
    if col in JSON_COLUMNS:
        return json.dumps(value if value is not None else ([] if col != "data" else {}), default=str)
    return value


def _decode(row: dict) -> dict:
    out = dict(row)
    for col in JSON_COLUMNS & out.keys():
        if isinstance(out[col], str):
            try:
                out[col] = json.loads(out[col])
            except ValueError:
                pass
    return out


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


# ---------------------------------------------------------------------------------------------------------------
# Summaries (pure: the Admin page and the daily failure summary both use them)


def percentile(values: list[float], p: float) -> float | None:
    """Nearest-rank percentile, the same definition the eval reports use."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    k = max(0, min(len(vals) - 1, math.ceil(p / 100 * len(vals)) - 1))
    return vals[k]


def summarize(rows: list[dict], now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    today = now.date().isoformat()
    month = today[:7]
    rows = [r for r in rows if r.get("source") not in BOT_SOURCES]
    statuses = Counter(r.get("status") for r in rows)
    total = len(rows)
    failures = sum(statuses[s] for s in FAILURES)
    lat = [r.get("latency_ms") for r in rows if r.get("status") == "ok"]
    blocks = Counter(r.get("error_type") or "unknown" for r in rows if r.get("status") == "blocked")
    errors = Counter(r.get("error_type") or "unknown" for r in rows if r.get("status") in FAILURES)
    return {
        "total": total,
        "statuses": dict(statuses),
        "error_rate": (failures / total) if total else 0.0,
        "p50_ms": percentile(lat, 50),
        "p95_ms": percentile(lat, 95),
        "cost_today": round(sum(r.get("cost_usd") or 0 for r in rows if (r.get("ts") or "")[:10] == today), 4),
        "cost_month": round(sum(r.get("cost_usd") or 0 for r in rows if (r.get("ts") or "")[:7] == month), 4),
        "top_errors": errors.most_common(5),
        "guardrail_blocks": blocks.most_common(10),
    }
