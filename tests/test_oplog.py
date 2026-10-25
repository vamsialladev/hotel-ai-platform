import json
import time
from datetime import UTC, datetime, timedelta

import pytest

from hotelplatform import jsonlog, oplog, tracing


@pytest.fixture(autouse=True)
def quiet(tmp_path):
    import io

    jsonlog.configure("t", "t", stream=io.StringIO())
    yield
    jsonlog.configure("unknown", "unknown", stream=None)


def make_trace(app="hotel-ops-assistant", question="I'm Owen Clarke, owen@example.com — pool hours?"):
    with tracing.new_trace(app, session_id="sess-1") as t:
        with t.span("input_checks", text=question):
            pass
        with t.span("retrieval", query="pool hours", top=[{"doc": "pool.md", "score": 3.2}]):
            pass
        with t.span("model_call", model="claude-haiku-5-5") as s:
            s.set(tokens_in=800, tokens_out=120, stop_reason="end_turn")
    return t


def row(t, **kw):
    base = dict(request_type="question", status="ok", latency_ms=1200, tokens_in=800, tokens_out=120,
                cost_usd=0.0002, model="claude-haiku-5-5", sources=["pool.md"],
                data={"question": "owen@example.com"})  # fmt: skip
    base.update(kw)
    return oplog.request_row(t, **base)


@pytest.fixture(params=["file", "sqlite"])
def store(request, tmp_path):
    url = "" if request.param == "file" else f"sqlite:///{tmp_path / 'ops.db'}"
    return oplog.OpsStore("hotel-ops-assistant", url=url, log_dir=tmp_path / "logs", flush_interval_s=0.05)


def test_round_trip_request_spans_feedback(store):
    t = make_trace()
    assert store.submit(t, row(t))
    store.feedback(t.trace_id, "down", "Wrong hotel, email me at a@b.co")
    store.flush()
    rows = store.requests()
    assert len(rows) == 1 and rows[0]["trace_id"] == t.trace_id and rows[0]["status"] == "ok"
    assert rows[0]["sources"] == ["pool.md"] and rows[0]["latency_ms"] == 1200
    spans = store.spans(t.trace_id)
    assert [s["name"] for s in spans] == ["input_checks", "retrieval", "model_call"]
    assert spans[2]["attributes"]["tokens_in"] == 800
    fb = store.feedback_rows()
    assert fb[0]["rating"] == "down" and "a@b.co" not in fb[0]["reason"]


def test_pii_removed_before_anything_is_written(store, tmp_path):
    t = make_trace()
    store.submit(t, row(t, error_message="guest owen@example.com, card 4111 1111 1111 1111"))
    store.flush()
    if store.backend == "file":
        raw = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "logs").glob("*.jsonl"))
    else:
        import sqlite3

        conn = sqlite3.connect(tmp_path / "ops.db")
        raw = json.dumps([list(r) for tbl in oplog.TABLES for r in conn.execute(f"SELECT * FROM {tbl}")])
        conn.close()
    for planted in ("owen@example.com", "Owen", "4111 1111"):
        assert planted not in raw


def test_bot_visits_never_written(store):
    t = make_trace()
    assert store.submit(t, row(t, source="keepawake")) is False
    store.flush()
    assert store.requests(include_bots=True) == []
    assert store.counters["skipped_bot"] == 1


def test_submit_never_blocks_or_raises_when_the_database_is_down(tmp_path):
    store = oplog.OpsStore("app", url="postgresql://u:p@127.0.0.1:1/db", log_dir=tmp_path / "logs")
    t = make_trace("app")
    started = time.perf_counter()
    assert store.submit(t, row(t)) is True  # queued
    assert time.perf_counter() - started < 0.05  # the request didn't wait for the database
    store.flush()
    assert store.counters["write_errors"] == 1
    assert store.counters["fallback_writes"] >= 1  # nothing lost: written to the JSONL file instead
    assert (tmp_path / "logs" / "ops_request_log.jsonl").exists()
    assert "p@127" not in json.dumps(store.health())
    assert store.health()["status"].startswith("last error:")


def test_bad_row_does_not_raise(store):
    class Weird:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    assert store.submit(Weird(), {"source": "user"}) is False
    assert store.counters["dropped"] == 1


def test_full_queue_drops_and_counts(tmp_path):
    store = oplog.OpsStore("app", url="", log_dir=tmp_path, max_queue=1)
    store._ensure_thread = lambda: None  # no writer: the queue stays full
    t = make_trace("app")
    assert store.submit(t, row(t))
    assert store.submit(t, row(t)) is False
    assert store.counters["dropped"] == 1


def test_background_writer_flushes_on_its_own(tmp_path):
    store = oplog.OpsStore("app", url="", log_dir=tmp_path, flush_interval_s=0.05)
    t = make_trace("app")
    store.submit(t, row(t))
    deadline = time.time() + 3
    while time.time() < deadline and not (tmp_path / "ops_request_log.jsonl").exists():
        time.sleep(0.05)
    assert (tmp_path / "ops_request_log.jsonl").exists()


def test_idle_connection_closed(tmp_path):
    store = oplog.OpsStore("app", url=f"sqlite:///{tmp_path / 'x.db'}", log_dir=tmp_path, flush_interval_s=0.05,
                           idle_close_s=0.1)  # fmt: skip
    t = make_trace("app")
    store.submit(t, row(t))
    deadline = time.time() + 3
    while time.time() < deadline and (store._conn is None or store.counters["written"] == 0):
        time.sleep(0.02)
    deadline = time.time() + 3
    while time.time() < deadline and store._conn is not None:
        time.sleep(0.05)
    assert store._conn is None  # Neon can suspend


def test_retention_purges_only_old_rows_of_this_app(store):
    old = (datetime.now(UTC) - timedelta(days=40)).isoformat(timespec="milliseconds")
    t1 = make_trace()
    t1.started_at = old
    t2 = make_trace()
    other = make_trace("guest-request-agent")
    other.started_at = old
    store.submit(t1, row(t1))
    store.submit(t2, row(t2))
    store.submit(other, row(other))
    store.flush()
    if store.backend == "sqlite":
        store._close()
    removed = store.purge()
    assert removed >= 1
    assert [r["trace_id"] for r in store.requests(since="0")] == [t2.trace_id]
    neighbour = oplog.OpsStore("guest-request-agent", url=store.url, log_dir=store.log_dir)
    assert len(neighbour.requests(since="0")) == 1  # another app's rows are its own business


def test_request_row_validates_status():
    t = make_trace()
    with pytest.raises(ValueError):
        oplog.request_row(t, request_type="q", status="weird")


def test_backend_names_and_safe_error():
    assert oplog.backend_of("") == "file"
    assert oplog.backend_of("postgresql://x") == "postgres"
    assert oplog.backend_of("sqlite:///x.db") == "sqlite"
    assert oplog.backend_of("mysql://x") == "invalid"
    assert oplog.safe_error(ValueError("host secret")) == "ValueError"
    s = oplog.OpsStore("a", url="mysql://x")
    assert "not a postgres" in s.health()["status"]
    assert s.database_size_mb() is None


def test_percentile_and_summary():
    assert oplog.percentile([], 50) is None
    assert oplog.percentile([1, 2, 3, 4], 50) == 2
    assert oplog.percentile(list(range(1, 101)), 95) == 95
    now = datetime(2026, 10, 25, 12, tzinfo=UTC)
    rows = [
        {"ts": "2026-10-25T01:00:00", "status": "ok", "latency_ms": 1000, "cost_usd": 0.001, "source": "user"},
        {"ts": "2026-10-25T02:00:00", "status": "ok", "latency_ms": 3000, "cost_usd": 0.002, "source": "user"},
        {"ts": "2026-10-20T02:00:00", "status": "error", "error_type": "APITimeoutError", "cost_usd": 0.0},
        {"ts": "2026-10-20T03:00:00", "status": "blocked", "error_type": "prompt_injection"},
        {"ts": "2026-10-25T03:00:00", "status": "ok", "latency_ms": 1, "source": "keepawake"},
    ]
    s = oplog.summarize(rows, now)
    assert s["total"] == 4 and s["error_rate"] == 0.25
    assert s["p50_ms"] == 1000 and s["p95_ms"] == 3000
    assert s["cost_today"] == 0.003 and s["cost_month"] == 0.003
    assert s["top_errors"] == [("APITimeoutError", 1)]
    assert s["guardrail_blocks"] == [("prompt_injection", 1)]
