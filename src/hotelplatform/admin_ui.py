"""The Admin page every app shares (Streamlit). The pure helpers at the top are unit-tested; `render()` draws them.

    from hotelplatform import admin_ui
    admin_ui.render(store, app_title="Knowledge Assistant", version=VERSION, cost_cap_day=2.0,
                    cost_cap_month=20.0, dependencies=check_dependencies)

Sections: totals (requests, error rate, p50/p95, cost today and this month against the caps), the request list
("Failures only" filter, status filter, trace search), one request's redacted details and its step-by-step
waterfall, top error types, guardrail blocks, feedback, System health (dependencies, deployed version, log store,
Neon size) and a CSV download. Keep-awake visits are excluded everywhere.
"""

import csv
import io
import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from hotelplatform import admin_gate, oplog, tracing

TABLE_COLUMNS = ("ts", "status", "request_type", "latency_ms", "cost_usd", "tokens_in", "tokens_out", "model",
                 "error_type", "trace_id")  # fmt: skip


def filter_rows(rows: list[dict], failures_only: bool = False, statuses: list[str] | None = None,
                trace_query: str = "") -> list[dict]:  # fmt: skip
    out = rows
    if failures_only:
        out = [r for r in out if r.get("status") in (*oplog.FAILURES, "blocked", "capped")]
    if statuses:
        out = [r for r in out if r.get("status") in statuses]
    q = (trace_query or "").strip().lower()
    if q:
        out = [r for r in out if (r.get("trace_id") or "").lower().startswith(q)]
    return out


def table_rows(rows: list[dict]) -> list[dict]:
    out = []
    for r in rows:
        row = {c: r.get(c) for c in TABLE_COLUMNS}
        row["reference"] = tracing.short_id(r.get("trace_id") or "")
        row["tools"] = len(r.get("tool_calls") or [])
        row["flags"] = ", ".join(r.get("safety_flags") or [])
        out.append(row)
    return out


def waterfall_rows(spans: list[dict]) -> list[dict]:
    """One bar per span: where it starts and ends relative to the request, its depth for indenting the name."""
    by_id = {s.get("span_id"): s for s in spans}

    def depth(s, seen=0):
        parent = by_id.get(s.get("parent_id"))
        return 0 if parent is None or seen > 10 else 1 + depth(parent, seen + 1)

    ordered = sorted(spans, key=lambda s: s.get("start_ms") or 0)
    total = max([float(s.get("start_ms") or 0) + float(s.get("duration_ms") or 0) for s in ordered] or [0.0])
    sliver = max(total * 0.01, 1.0)  # a zero-length check still gets a visible bar on a 4-second axis
    rows = []
    for i, s in enumerate(ordered):
        start = float(s.get("start_ms") or 0)
        dur = float(s.get("duration_ms") or 0)
        rows.append({
            "order": i,
            # Numbered so every row is its own label (two spans with one name would otherwise share a row)
            "step": f"{i + 1}. " + ("· " * depth(s)) + (s.get("name") or "?"),
            "start_ms": start,
            "end_ms": start + max(dur, sliver),
            "duration_ms": dur,
            "status": s.get("status") or "ok",
        })  # fmt: skip
    return rows


def csv_text(rows: list[dict]) -> str:
    buf = io.StringIO()
    cols = list(oplog.REQUEST_COLUMNS)
    writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({c: json.dumps(r.get(c)) if isinstance(r.get(c), list | dict) else r.get(c) for c in cols})
    return buf.getvalue()


def cap_line(spent: float, cap: float | None = None) -> str:
    """The metric value: just the amount, so it fits a laptop-width column. Dollar signs escaped: Streamlit renders
    "$0.0002 ... $1.00" as LaTeX and the signs vanish (both seen on the first check of the Traces page)."""
    return f"\\${spent:.4f}"


def cost_label(name: str, cap: float | None, spent: float = 0.0) -> str:
    """The metric label carries the cap: "Cost today · 0% of the $1.00 cap"."""
    return f"{name} · {spent / cap:.0%} of the \\${cap:.2f} cap" if cap else name


def ms(value) -> str:
    return "—" if value is None else f"{value / 1000:.2f} s"


# ---------------------------------------------------------------------------------------------------------------


def gate(st, scope: str = "admin", password_env: str = "ADMIN_PASSWORD", title: str = "Admin") -> bool:
    """Draw the sign-in form if needed. True when the owner is signed in."""
    key = f"_gate_{scope}"
    state = st.session_state.setdefault(key, admin_gate.SessionGate())
    if admin_gate.still_signed_in(state):
        return True
    st.title(title)
    with st.form(f"{scope}_sign_in"):
        given = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        ok, message = admin_gate.attempt(state, given, admin_gate.secret(password_env), scope=scope)
        if ok:
            st.rerun()
        time.sleep(1.0)  # slows guessing
        st.error(message)
    return False


def render(
    store: oplog.OpsStore,
    *,
    app_title: str,
    version: str,
    cost_cap_day: float | None = None,
    cost_cap_month: float | None = None,
    dependencies: Callable[[], dict[str, str]] | None = None,
    scope: str = "admin",
    password_env: str = "ADMIN_PASSWORD",
    require_gate: bool = True,
    title: str | None = None,
) -> None:
    """require_gate=False: the app has already checked its own sign-in (stage 1's Admin gate); no second form."""
    import streamlit as st

    if require_gate and not gate(st, scope, password_env, f"{app_title}: Admin"):
        return
    store.flush(timeout_s=2.0)
    st.title(title or f"{app_title}: Admin")
    top = st.columns([4, 1])
    days = top[0].radio("Period", [1, 7, 30], index=1, horizontal=True, format_func=lambda d: f"{d} day(s)")
    if require_gate and top[1].button("Sign out"):
        admin_gate.sign_out(st.session_state[f"_gate_{scope}"])
        st.rerun()

    since = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
    try:
        rows = store.requests(since=since, limit=2000)
    except Exception as exc:
        st.error(f"Couldn't read the request log ({oplog.safe_error(exc)}). The app itself is unaffected.")
        rows = []
    month_rows = rows if days == 30 else _safe(lambda: store.requests(limit=5000), [])
    s = oplog.summarize(rows)
    sm = oplog.summarize(month_rows)

    # Two rows of short values: five long ones in one row were cut off ("2.87 ...") on a laptop-width window.
    c = st.columns(4)
    c[0].metric("Requests", s["total"])
    c[1].metric("Error rate", f"{s['error_rate']:.1%}")
    c[2].metric("p50", ms(s["p50_ms"]))
    c[3].metric("p95", ms(s["p95_ms"]))
    c = st.columns(2)
    c[0].metric(cost_label("Cost today", cost_cap_day, sm["cost_today"]), cap_line(sm["cost_today"]))
    c[1].metric(cost_label("Cost this month", cost_cap_month, sm["cost_month"]), cap_line(sm["cost_month"]))

    st.subheader("Requests")
    f = st.columns([1, 2, 2])
    failures_only = f[0].toggle("Failures only", value=False)
    statuses = f[1].multiselect("Status", list(oplog.STATUSES))
    trace_query = f[2].text_input("Trace reference", placeholder="e.g. 4f1c9a2e")
    shown = filter_rows(rows, failures_only, statuses, trace_query)
    st.dataframe(table_rows(shown), hide_index=True, use_container_width=True)
    st.download_button("Download CSV", csv_text(shown), file_name=f"{store.app}-requests.csv", mime="text/csv")

    if shown:
        refs = [r["trace_id"] for r in shown[:200]]
        pick = st.selectbox(
            "Request details", refs, format_func=lambda t: f"{tracing.short_id(t)} · "
            + next((f"{r['ts'][:19]} · {r['status']}" for r in shown if r["trace_id"] == t), "")
        )  # fmt: skip
        row = next(r for r in shown if r["trace_id"] == pick)
        spans = _safe(lambda: store.spans(pick), [])
        st.markdown(f"**Reference {tracing.short_id(pick)}** · full trace ID `{pick}`")
        _waterfall(st, spans)
        with st.expander("Redacted request record"):
            st.json(row)
        with st.expander(f"Spans ({len(spans)})"):
            st.json(spans)

    a, b = st.columns(2)
    a.subheader("Top error types")
    a.dataframe([{"error": e, "count": n} for e, n in s["top_errors"]] or [{"error": "none", "count": 0}],
                hide_index=True)  # fmt: skip
    b.subheader("Guardrail blocks")
    b.dataframe([{"reason": e, "count": n} for e, n in s["guardrail_blocks"]] or [{"reason": "none", "count": 0}],
                hide_index=True)  # fmt: skip

    st.subheader("Feedback")
    fb = _safe(lambda: store.feedback_rows(since=since), [])
    ups = sum(1 for r in fb if r.get("rating") == "up")
    st.caption(f"{ups} 👍 · {len(fb) - ups} 👎 in the period")
    if fb:
        st.dataframe([{"ts": r.get("ts"), "rating": r.get("rating"), "reason": r.get("reason"),
                       "reference": tracing.short_id(r.get("trace_id") or "")} for r in fb],
                     hide_index=True)  # fmt: skip

    st.subheader("System health")
    deps = _safe(dependencies, {"checks": "failed to run"}) if dependencies else {}
    h = st.columns(3)
    h[0].markdown("**Dependencies**\n\n" + "\n".join(f"- {k}: {v}" for k, v in deps.items()) if deps else "—")
    h[1].markdown(f"**Deployed version**\n\n`{version}`")
    health = store.health()
    size = store.database_size_mb()
    h[2].markdown(
        "**Log store**\n\n"
        + "\n".join(f"- {k}: {v}" for k, v in health.items())
        + (f"\n- database size: {size} MB of 512 MB (Neon free tier)" if size is not None else "")
    )
    st.caption("Personal data is removed before anything is stored. Rows are deleted after 30 days. "
               "Keep-awake visits are not counted.")  # fmt: skip


def _waterfall(st, spans: list[dict]) -> None:
    rows = waterfall_rows(spans)
    if not rows:
        st.info("No steps were recorded for this request.")
        return
    try:
        import altair as alt

        chart = (
            alt.Chart(alt.Data(values=rows))
            .mark_bar()
            .encode(
                y=alt.Y(
                    "step:N",
                    sort=[r["step"] for r in rows],  # explicit order, one row each
                    title=None,
                    axis=alt.Axis(labelLimit=280, labelOverlap=False),  # never hide a step's name
                ),
                x=alt.X("start_ms:Q", title="milliseconds from the start of the request"),
                x2="end_ms:Q",
                color=alt.Color(
                    "status:N",
                    scale=alt.Scale(domain=["ok", "blocked", "error"], range=["#2e7d5b", "#b8860b", "#c0392b"]),
                ),  # fmt: skip
                tooltip=["step:N", "duration_ms:Q", "status:N"],
            )
        )
        # Height passed to Streamlit itself: a chart property alone rendered about 40 px tall on the first check
        st.altair_chart(chart, width="stretch", height=max(140, 30 * len(rows) + 50))
    except Exception:
        st.dataframe(rows, hide_index=True)


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default
