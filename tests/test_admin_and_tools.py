import io
import sqlite3

import pytest

from hotelplatform import admin_gate, admin_ui, bots, daily_summary, jsonlog, oplog, redteam, retention, tracing


@pytest.fixture(autouse=True)
def fresh_gate():
    admin_gate.reset_process_counters()
    jsonlog.configure("t", "t", stream=io.StringIO())
    yield
    admin_gate.reset_process_counters()
    jsonlog.configure("unknown", "unknown", stream=None)


# ------------------------------------------------------------------ admin gate
def test_no_password_means_no_admin():
    assert not admin_gate.enabled(environ={})
    assert admin_gate.enabled(environ={"ADMIN_PASSWORD": "x"})
    ok, msg = admin_gate.attempt(admin_gate.SessionGate(), "anything", "")
    assert not ok and msg == admin_gate.NOT_CONFIGURED


def test_right_password_unlocks_and_idle_signs_out():
    s = admin_gate.SessionGate()
    assert admin_gate.attempt(s, "pw-123456", "pw-123456", now=100) == (True, None)
    assert admin_gate.still_signed_in(s, now=200)
    assert not admin_gate.still_signed_in(s, now=200 + admin_gate.IDLE_S + 1)


def test_lockout_after_five_wrong_tries_even_across_sessions():
    pw = "pw-123456"
    for i in range(4):
        ok, msg = admin_gate.attempt(admin_gate.SessionGate(), "wrong", pw, now=1000 + i)  # a new tab each time
        assert not ok and msg == admin_gate.WRONG
    ok, msg = admin_gate.attempt(admin_gate.SessionGate(), "wrong", pw, now=1005)
    assert not ok and msg.startswith("Too many attempts")
    ok, msg = admin_gate.attempt(admin_gate.SessionGate(), pw, pw, now=1006)  # even the right one, while locked
    assert not ok and "Too many attempts" in msg
    ok, _ = admin_gate.attempt(admin_gate.SessionGate(), pw, pw, now=1006 + admin_gate.LOCKOUT_S)
    assert ok  # the lock expires


def test_scopes_are_separate():
    for i in range(5):
        admin_gate.attempt(admin_gate.SessionGate(), "wrong", "pw", now=10 + i, scope="staff")
    assert admin_gate.attempt(admin_gate.SessionGate(), "pw", "pw", now=20, scope="admin")[0]


# ------------------------------------------------------------------ admin ui helpers
ROWS = [
    {"ts": "2026-10-25T01:00", "status": "ok", "trace_id": "aaaa1111" + "0" * 24, "tool_calls": [{"n": 1}],
     "safety_flags": ["pii_redacted:EMAIL_ADDRESS"], "latency_ms": 900},
    {"ts": "2026-10-25T02:00", "status": "error", "trace_id": "bbbb2222" + "0" * 24, "error_type": "Timeout"},
    {"ts": "2026-10-25T03:00", "status": "blocked", "trace_id": "cccc3333" + "0" * 24},
]  # fmt: skip


def test_filters():
    assert len(admin_ui.filter_rows(ROWS, failures_only=True)) == 2
    assert [r["status"] for r in admin_ui.filter_rows(ROWS, statuses=["ok"])] == ["ok"]
    assert admin_ui.filter_rows(ROWS, trace_query="BBBB")[0]["status"] == "error"


def test_table_rows_and_csv():
    t = admin_ui.table_rows(ROWS)
    assert t[0]["reference"] == "aaaa1111" and t[0]["tools"] == 1 and "EMAIL" in t[0]["flags"]
    csv = admin_ui.csv_text(ROWS)
    assert csv.splitlines()[0].startswith("ts,app,trace_id") and "aaaa1111" in csv


def test_waterfall_rows_depth_and_order():
    spans = [
        {"span_id": "b", "parent_id": "a", "name": "tool:find_booking", "start_ms": 10, "duration_ms": 0},
        {"span_id": "a", "parent_id": None, "name": "agent", "start_ms": 0, "duration_ms": 50},
    ]
    w = admin_ui.waterfall_rows(spans)
    assert [r["step"] for r in w] == ["agent", "  tool:find_booking"]
    assert w[1]["end_ms"] > w[1]["start_ms"]  # zero-length steps stay visible


def test_cap_line_and_ms():
    assert admin_ui.cap_line(0.5, 2.0) == "$0.5000 of $2.00 (25%)"
    assert admin_ui.cap_line(0.5, None) == "$0.5000"
    assert admin_ui.ms(None) == "—" and admin_ui.ms(1500) == "1.50 s"


def test_admin_page_renders_with_apptest(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("ADMIN_PASSWORD", "pw-123456")
    monkeypatch.setenv("OPS_TEST_DIR", str(tmp_path))
    script = """
import os
from hotelplatform import admin_ui, oplog, tracing
store = oplog.OpsStore("demo", url="", log_dir=os.environ["OPS_TEST_DIR"])
if not store.requests():
    with tracing.new_trace("demo") as t:
        with t.span("model_call"):
            pass
    store.submit(t, oplog.request_row(t, request_type="question", status="error", error_type="Timeout"))
    store.flush()
admin_ui.render(store, app_title="Demo", version="1.0+abc", cost_cap_day=1.0, cost_cap_month=10.0,
                dependencies=lambda: {"anthropic": "ok"})
"""
    at = AppTest.from_string(script, default_timeout=30).run()
    assert at.title[0].value == "Demo: Admin"  # the sign-in form
    at.text_input[0].input("wrong")  # form widgets submit with the button, not on their own
    at.button[0].click().run()
    assert at.error and "Incorrect password" in at.error[0].value
    at.text_input[0].input("pw-123456")
    at.button[0].click().run()
    assert not at.exception
    labels = [m.label for m in at.metric]
    assert labels == ["Requests", "Error rate", "p50 / p95", "Cost today", "Cost this month"]
    assert at.metric[0].value == "1" and at.metric[1].value == "100.0%"


# ------------------------------------------------------------------ bots
@pytest.mark.parametrize(
    "params,expected",
    [({"source": "keepawake"}, "keepawake"), ({"source": ["KeepAwake"]}, "keepawake"), ({}, "user"),
     ({"source": "newsletter"}, "user"), (None, "user")],
)  # fmt: skip
def test_bot_source(params, expected):
    assert bots.source_of(params) == expected
    assert bots.is_bot(params) is (expected != "user")


# ------------------------------------------------------------------ daily summary
def test_assess_rules():
    A = daily_summary.AppDay
    assert daily_summary.assess(A("a", 0, 0, 0)) == []
    assert daily_summary.assess(A("a", 0, 0, 0), alert_no_traffic=True) == ["no requests at all"]
    assert daily_summary.assess(A("a", 3, 0, 3))[0].startswith("zero successful")
    assert "error rate" in daily_summary.assess(A("a", 20, 18, 2))[0]
    assert daily_summary.assess(A("a", 100, 96, 4)) == []  # 4% is under 5%
    assert daily_summary.assess(A("a", 2, 1, 1)) == []  # too few requests to judge a rate


def seed_db(path, rows):
    store = oplog.OpsStore("x", url=f"sqlite:///{path}")
    for app, status, source, ts in rows:
        with tracing.new_trace(app) as t:
            pass
        t.started_at = ts
        store.submit(t, oplog.request_row(t, request_type="q", status=status, source=source))
    store.flush()
    store._close()


def test_daily_summary_end_to_end(tmp_path, monkeypatch, capsys):
    db = tmp_path / "ops.db"
    seed_db(db, [("app-a", "error", "user", "2026-10-24T10:00:00.000+00:00")] * 3
            + [("app-b", "ok", "user", "2026-10-24T11:00:00.000+00:00")]
            + [("app-b", "ok", "keepawake", "2026-10-24T11:00:00.000+00:00")]
            + [("app-a", "ok", "user", "2026-10-25T01:00:00.000+00:00")])  # fmt: skip
    monkeypatch.setenv("OPS_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    alert = tmp_path / "alert.md"
    assert daily_summary.main(["--apps", "app-a,app-b,app-c", "--date", "2026-10-24", "--alert-file", str(alert)]) == 0
    body = alert.read_text(encoding="utf-8")
    assert "| app-a | 3 | 0 | 3 | 100% | zero successful requests out of 3 |" in body
    assert "| app-b | 1 | 1 | 0 | 0% | fine |" in body  # the keep-awake visit isn't counted
    assert "| app-c | 0 | 0 | 0 | 0% | no traffic |" in body


def test_daily_summary_quiet_day_writes_no_alert(tmp_path, monkeypatch):
    db = tmp_path / "ops.db"
    seed_db(db, [("app-a", "ok", "user", "2026-10-24T10:00:00.000+00:00")])
    monkeypatch.setenv("OPS_DATABASE_URL", f"sqlite:///{db.as_posix()}")
    alert = tmp_path / "alert.md"
    daily_summary.main(["--apps", "app-a", "--date", "2026-10-24", "--alert-file", str(alert)])
    assert not alert.exists()


def test_daily_summary_without_database_is_a_dry_run(monkeypatch, capsys):
    monkeypatch.delenv("OPS_DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert daily_summary.main(["--apps", "a"]) == 0
    assert "dry run" in capsys.readouterr().out


def test_daily_summary_unreadable_database(tmp_path, monkeypatch):
    monkeypatch.setenv("OPS_DATABASE_URL", "sqlite:///" + (tmp_path / "missing.db").as_posix())
    alert = tmp_path / "alert.md"
    assert daily_summary.main(["--apps", "a", "--alert-file", str(alert)]) == 0
    assert "Could not read" in alert.read_text(encoding="utf-8")


def test_read_only_connection_cannot_write(tmp_path):
    db = tmp_path / "ops.db"
    seed_db(db, [("a", "ok", "user", "2026-10-24T10:00:00.000+00:00")])
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("DELETE FROM ops_request_log")
    conn.close()


def test_retention_cli(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'r.db').as_posix()}")
    seed_db(tmp_path / "r.db", [("app-a", "ok", "user", "2020-01-01T00:00:00.000+00:00")])
    retention.main(["--apps", "app-a", "--days", "30"])
    assert "deleted 1 rows" in capsys.readouterr().out


# ------------------------------------------------------------------ red team
def test_shared_corpus_loads_and_has_every_category():
    cases = redteam.shared_cases()
    cats = {c.category for c in cases}
    assert len(cases) >= 25
    for needed in ("direct_injection", "indirect_injection", "data_exfiltration", "role_escalation",
                   "tool_misuse", "jailbreak", "benign_control"):  # fmt: skip
        assert needed in cats


def test_shared_corpus_passes():
    s = redteam.score(redteam.run(redteam.shared_cases()))
    assert s["passed"] == s["cases"], s


def test_case_validation_and_duplicates(tmp_path):
    with pytest.raises(ValueError):
        redteam.Case("x", "c", "nowhere", "t", "block")
    with pytest.raises(ValueError):
        redteam.Case("x", "c", "input", "t", "maybe")
    p = tmp_path / "c.jsonl"
    p.write_text('{"id": "a", "category": "c", "layer": "input", "text": "t", "expect": "allow"}\n' * 2)
    with pytest.raises(ValueError, match="duplicate"):
        redteam.load_cases(p)


def test_custom_tool_handler_and_crash_is_a_failure():
    cases = [redteam.Case("t1", "tool_misuse", "tool", "cancel_booking(all)", "block"),
             redteam.Case("t2", "tool_misuse", "tool", "boom", "block")]  # fmt: skip

    def tool(case):
        if case.text == "boom":
            raise RuntimeError("bug")
        return redteam.Outcome("block", "role_denied")

    results = redteam.run(cases, {"tool": tool})
    assert results[0].passed and not results[1].passed and results[1].outcome.verdict == "error"


def test_report_and_cli(tmp_path):
    out = tmp_path / "report.md"
    assert redteam.main(["--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "Attacks stopped" in text and "| rt01 |" in text
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id": "b1", "category": "c", "layer": "input", "text": "hello there friend", "expect": "block"}\n')
    assert redteam.main(["--cases", str(bad)]) == 1
