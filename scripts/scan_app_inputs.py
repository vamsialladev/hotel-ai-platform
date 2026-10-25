"""Run check_input over every real eval input in the sibling app repos and print what would be blocked.

    python scripts/scan_app_inputs.py ..      (from this repo, with the app repos checked out next to it)

The output is saved in docs/eval-input-scan.txt and quoted in docs/RED_TEAM.md. Not run in CI: it needs the other
repos.
"""

import io
import json
import sys
from collections import Counter
from pathlib import Path

from hotelplatform import guardrails, jsonlog

jsonlog.configure("scan", "scan", stream=io.StringIO())
ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "..")  # the folder that holds the app repos


def rows(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def texts():
    p1 = ROOT / "hotel-ops-assistant" / "eval"
    for r in rows(p1 / "questions.jsonl"):
        yield "P1 dev", r["id"], r.get("category"), r["question"]
    for r in rows(p1 / "visitor_questions.jsonl"):
        yield "P1 visitor", r["id"], r.get("expect"), r["question"]
    for r in rows(p1 / "multiturn_cases.jsonl"):
        for i, t in enumerate(r["turns"]):
            yield "P1 multiturn", f"{r['id']}.{i}", r.get("category"), t["q"]
    inbox = {r["id"]: r for r in rows(ROOT / "guest-request-agent" / "data" / "inbox.jsonl")}
    for r in inbox.values():
        yield (
            "P2 inbox",
            r["id"],
            ",".join(r.get("categories", [])) if r.get("categories") else "",
            ((r.get("subject") or "") + "\n" + (r.get("body") or "")),
        )
    for name in ("heldout.jsonl", "visitor.jsonl"):
        for r in rows(ROOT / "guest-request-agent" / "eval" / name):
            body = r.get("body") or (r.get("email") or {}).get("body") or ""
            if body:
                yield f"P2 {name}", r["id"], ",".join(r.get("categories", [])), (r.get("subject") or "") + "\n" + body
    for r in rows(ROOT / "resort-activities-concierge" / "eval" / "cases.jsonl"):
        yield "S6", r["id"], r.get("category"), r["question"]
    for r in rows(ROOT / "hotel-tools-mcp" / "eval" / "agent_cases.jsonl"):
        yield "S7", r["id"], r.get("category"), r["question"]
    for r in rows(ROOT / "hotel-ops-analytics-agent" / "eval" / "questions.jsonl"):
        yield "S8", r["id"], r.get("category"), r["question"]
    for r in rows(ROOT / "fde-account-research-agent" / "eval" / "companies.jsonl"):
        yield "PS", r.get("id", "?"), r.get("split"), r.get("company") or r.get("name") or ""


counts = Counter()
blocked = Counter()
reasons = Counter()
for src, cid, cat, text in texts():
    if not text:
        continue
    counts[src] += 1
    v = guardrails.check_input(text, guardrails.InputPolicy(max_chars=6000))
    if not v.allowed:
        blocked[src] += 1
        reasons[v.reason] += 1
        print(f"{src:14} {cid:8} [{cat}] -> {v.reason}: {text[:110]!r}")
print()
for src in counts:
    print(f"{src:14} blocked {blocked[src]}/{counts[src]}")
print(reasons)
sys.exit(0)
