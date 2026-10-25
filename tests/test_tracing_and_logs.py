import io
import json

import pytest

from hotelplatform import jsonlog, secrets_mask, tracing, version


def test_trace_ids_have_otel_shapes():
    with tracing.new_trace("app", session_id="s1") as t:
        with t.span("retrieval", query="pool hours") as s:
            s.set(top_k=5)
    assert len(t.trace_id) == 32 and int(t.trace_id, 16) >= 0
    assert len(s.span_id) == 16
    assert t.reference == t.trace_id[:8]
    assert s.duration_ms is not None and s.duration_ms >= 0
    assert tracing.current() is None  # reset after the block


def test_nested_spans_record_parent():
    with tracing.new_trace("app") as t:
        with t.span("agent") as outer:
            with t.span("tool:find_booking") as inner:
                pass
    assert inner.parent_id == outer.span_id and outer.parent_id is None


def test_exception_marks_span_error_and_propagates():
    with tracing.new_trace("app") as t:
        with pytest.raises(TimeoutError):
            with t.span("model_call"):
                raise TimeoutError("stream stalled")
    assert t.spans[0].status == "error"
    assert t.spans[0].attributes["error_type"] == "TimeoutError"
    assert t.status == "error"


def test_block_and_record():
    with tracing.new_trace("app") as t:
        with t.span("output_checks") as s:
            s.block("policy_promise")
        t.record("model_call", 812.4, tokens_in=10)
    assert t.status == "blocked"
    assert t.spans[1].duration_ms == 812.4


def test_span_rows_are_redacted_and_truncated(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-1234567890")
    with tracing.new_trace("app") as t:
        with t.span("input_checks", text="I'm Owen Clarke, owen@example.com, key sk-ant-test-1234567890") as s:
            s.set(big="x" * 5000)
            s.event("note", detail="call +1 415 555 0134")
    row = t.span_rows()[0]
    attrs = json.dumps(row)
    assert "owen@example.com" not in attrs and "Owen" not in attrs and "sk-ant-test" not in attrs
    assert "415 555" not in attrs
    assert len(row["attributes"]["big"]) < 2100
    assert row["trace_id"] == t.trace_id  # IDs are never scrubbed


def test_module_span_is_noop_without_trace():
    with tracing.span("x") as s:
        assert s is None
    with tracing.new_trace("app") as t:
        with tracing.span("x", a=1) as s:
            assert s is not None
    assert t.spans[0].name == "x"


def test_max_spans_cap():
    with tracing.new_trace("app") as t:
        for _ in range(tracing.MAX_SPANS + 20):
            t.record("loop", 1.0)
    assert len(t.spans) == tracing.MAX_SPANS


# ------------------------------------------------------------------ jsonlog
@pytest.fixture
def log_stream():
    buf = io.StringIO()
    jsonlog.configure("hotel-ops-assistant", "1.7.0+abc1234", stream=buf)
    yield buf
    jsonlog.configure("unknown", "unknown", stream=None)


def lines(buf):
    return [json.loads(x) for x in buf.getvalue().splitlines()]


def test_event_format(log_stream):
    jsonlog.app_start(port=8501)
    rec = lines(log_stream)[0]
    assert rec["event"] == "app_start" and rec["app"] == "hotel-ops-assistant" and rec["version"] == "1.7.0+abc1234"
    assert rec["level"] == "info" and rec["ts"].endswith("Z") and "python" in rec


def test_config_loaded_never_logs_values(log_stream, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse-battery")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    jsonlog.config_loaded(["ADMIN_PASSWORD", "DATABASE_URL"], model="claude-haiku-5-5")
    text = log_stream.getvalue()
    assert "correct-horse" not in text
    rec = lines(log_stream)[0]
    assert rec["settings"] == {"ADMIN_PASSWORD": "set", "DATABASE_URL": "missing"}


def test_exception_has_redacted_stack(log_stream, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://neon_user:hunter2secret@ep-x.neon.tech/db")
    try:
        raise ConnectionError("could not connect to postgresql://neon_user:hunter2secret@ep-x.neon.tech/db")
    except ConnectionError as exc:
        jsonlog.exception(exc, trace_id="t" * 32, where="store")
    text = log_stream.getvalue()
    assert "hunter2secret" not in text and "neon_user" not in text
    rec = lines(log_stream)[0]
    assert rec["error_type"] == "ConnectionError" and "Traceback" in rec["stack"] and rec["trace_id"] == "t" * 32


def test_other_helpers(log_stream):
    jsonlog.dependency_health({"anthropic": "ok", "database": "error: OperationalError"})
    jsonlog.cap_hit("daily_cost", trace_id="abc")
    jsonlog.rate_limited("session")
    jsonlog.retry("anthropic", 1, "APITimeoutError")
    jsonlog.slow_request(9100, 4000, trace_id="abc")
    events = [r["event"] for r in lines(log_stream)]
    assert events == ["dependency_health", "cap_hit", "rate_limited", "retry", "slow_request"]
    assert lines(log_stream)[0]["level"] == "warning"


def test_logging_failure_is_swallowed_and_counted():
    class Broken:
        def write(self, _):
            raise OSError("disk full")

    jsonlog.configure("a", "b", stream=Broken())
    before = jsonlog.failures()
    assert jsonlog.event("x") is None
    assert jsonlog.failures() == before + 1
    jsonlog.configure("unknown", "unknown", stream=None)


# ------------------------------------------------------------------ secrets
def test_mask_shapes_and_values():
    fake = "abcdef" + "123456"  # built at runtime so no secret-shaped literal sits in the repo
    env = {"MY_TOKEN": fake, "DEBUG": "true"}
    text = f"t={fake} sk-ant-api03-zzzzzzzzzz ghp_" + "a" * 30 + " postgresql://u:p4ss@h/db password=xyz true"
    out = secrets_mask.mask(text, env)
    for leaked in ("abcdef123456", "sk-ant-api03", "ghp_", "p4ss", "xyz"):
        assert leaked not in out
    assert out.endswith("true")  # short, non-secret values left alone
    assert secrets_mask.mask_value({"a": ["sk-ant-api03-zzzzzzzzzz"]}, env) == {"a": ["[secret]"]}


# ------------------------------------------------------------------ version
def test_version_from_env_and_git(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_COMMIT", "b111480deadbeef")
    assert version.version_string("1.7.0", tmp_path) == "1.7.0+b111480"
    monkeypatch.delenv("GIT_COMMIT")
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "refs" / "heads" / "main").write_text("1234567abcdef\n")
    assert version.git_commit(tmp_path) == "1234567"
    (git / "refs" / "heads" / "main").unlink()
    (git / "packed-refs").write_text("# pack\nfeedface00 refs/heads/main\n")
    assert version.git_commit(tmp_path) == "feedfac"
    (git / "HEAD").write_text("abcdef0123\n")
    assert version.git_commit(tmp_path) == "abcdef0"
    assert version.git_commit(tmp_path / "nowhere") == "unknown"
