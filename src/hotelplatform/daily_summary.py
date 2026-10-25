"""Daily failure summary for every app that writes to the shared ops tables.

Run once a day by streamlit-keep-awake's GitHub Action:

    python -m hotelplatform.daily_summary --apps hotel-ops-assistant,guest-request-agent --alert-file alert.md

For yesterday (UTC) and each app: requests, successes, failures, error rate. An app needs a person when
- its error rate (error + timeout) is above 5% (with at least --min-requests requests), or
- it had requests but zero successful ones.

An app with no requests at all is listed as "no traffic", not an alarm (decision 6): demo apps often have quiet
days, and a daily false alarm teaches the owner to ignore the alarm. `--alert-no-traffic` makes it one.

With an alarm: writes the issue body to --alert-file (the workflow opens a GitHub issue from it) and, if
SLACK_WEBHOOK_URL is set, posts the same text to Slack. Reads with a read-only transaction (and, ideally, a
read-only database role: docs/NEON_READONLY_ROLE.sql). Prints counts only; never the URL, never log content.
"""

import argparse
import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from hotelplatform.oplog import BOT_SOURCES, FAILURES, backend_of, safe_error


@dataclass
class AppDay:
    app: str
    requests: int
    ok: int
    failures: int

    @property
    def error_rate(self) -> float:
        return self.failures / self.requests if self.requests else 0.0


def assess(day: AppDay, max_error_rate: float = 0.05, min_requests: int = 5, alert_no_traffic: bool = False):
    """List of reasons this app needs a person (empty = fine). Pure."""
    reasons = []
    if day.requests == 0:
        if alert_no_traffic:
            reasons.append("no requests at all")
        return reasons
    if day.ok == 0:
        reasons.append(f"zero successful requests out of {day.requests}")
    if day.requests >= min_requests and day.error_rate > max_error_rate:
        reasons.append(f"error rate {day.failures}/{day.requests} ({day.error_rate:.0%}) is over {max_error_rate:.0%}")
    return reasons


def count_rows(rows: list[dict], apps: list[str]) -> list[AppDay]:
    """rows: dicts with app, status, source. Pure."""
    out = []
    for app in apps:
        mine = [r for r in rows if r.get("app") == app and r.get("source") not in BOT_SOURCES]
        out.append(
            AppDay(
                app,
                len(mine),
                sum(1 for r in mine if r.get("status") == "ok"),
                sum(1 for r in mine if r.get("status") in FAILURES),
            )
        )
    return out


def fetch(url: str, start: str, end: str) -> list[dict]:
    kind = backend_of(url)
    sql = "SELECT app, status, source FROM ops_request_log WHERE ts >= {m} AND ts < {m}"
    if kind == "postgres":
        import psycopg

        with psycopg.connect(url, connect_timeout=10, options="-c default_transaction_read_only=on") as conn:
            with conn.cursor() as cur:
                cur.execute(sql.format(m="%s"), (start, end))
                return [{"app": a, "status": s, "source": src} for a, s, src in cur.fetchall()]
    if kind == "sqlite":
        import sqlite3

        path = url.removeprefix("sqlite:///")
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as conn:
            return [
                {"app": a, "status": s, "source": src} for a, s, src in conn.execute(sql.format(m="?"), (start, end))
            ]
    raise ValueError("DATABASE_URL must be postgres:// or sqlite:///")


def report(days: list[AppDay], day: str, verdicts: dict[str, list[str]], run_url: str | None = None) -> str:
    lines = [f"## Daily failure summary for {day} (UTC)", "",
             "| App | Requests | OK | Failures | Error rate | Status |",
             "|---|---|---|---|---|---|"]  # fmt: skip
    for d in days:
        status = "; ".join(verdicts[d.app]) if verdicts[d.app] else ("no traffic" if not d.requests else "fine")
        lines.append(f"| {d.app} | {d.requests} | {d.ok} | {d.failures} | {d.error_rate:.0%} | {status} |")
    lines += ["", "How to debug a failed request: hotel-ai-handoff `docs/RUNBOOKS.md` → "
              "\"Debug a failed request using its trace ID\". "
              "Admin → Failures only → pick the row → waterfall."]  # fmt: skip
    if run_url:
        lines += ["", f"Workflow run: {run_url}"]
    return "\n".join(lines) + "\n"


def post_slack(webhook: str, text: str) -> bool:
    req = urllib.request.Request(webhook, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})  # fmt: skip
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apps", required=True, help="comma-separated app names (the `app` column)")
    ap.add_argument("--date", help="YYYY-MM-DD (UTC); default yesterday")
    ap.add_argument("--max-error-rate", type=float, default=0.05)
    ap.add_argument("--min-requests", type=int, default=5)
    ap.add_argument("--alert-no-traffic", action="store_true")
    ap.add_argument("--alert-file")
    args = ap.parse_args(argv)

    url = os.environ.get("OPS_DATABASE_URL") or os.environ.get("DATABASE_URL") or ""
    if not url:
        print("No OPS_DATABASE_URL / DATABASE_URL set: nothing to check (dry run).")
        return 0
    day = args.date or (datetime.now(UTC) - timedelta(days=1)).date().isoformat()
    start = datetime.fromisoformat(day).replace(tzinfo=UTC)
    end = start + timedelta(days=1)
    apps = [a.strip() for a in args.apps.split(",") if a.strip()]
    try:
        rows = fetch(url, start.isoformat(timespec="milliseconds"), end.isoformat(timespec="milliseconds"))
    except Exception as exc:
        print(f"Could not read the ops log ({safe_error(exc)}).")
        if args.alert_file:
            with open(args.alert_file, "w", encoding="utf-8") as f:
                f.write(f"## Daily failure summary for {day}\n\nCould not read the ops log ({safe_error(exc)}).\n")
        return 0
    days = count_rows(rows, apps)
    verdicts = {d.app: assess(d, args.max_error_rate, args.min_requests, args.alert_no_traffic) for d in days}
    body = report(days, day, verdicts, os.environ.get("RUN_URL"))
    print(body)
    if any(verdicts.values()):
        if args.alert_file:
            with open(args.alert_file, "w", encoding="utf-8") as f:
                f.write(body)
        webhook = os.environ.get("SLACK_WEBHOOK_URL")
        if webhook:
            print("Slack:", "posted" if post_slack(webhook, body) else "failed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
