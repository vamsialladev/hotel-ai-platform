"""Red-team suite: adversarial cases run against an app's real defences, in CI, with a saved report.

A case says which layer it attacks and what a safe outcome is:

    {"id": "rt01", "category": "direct_injection", "layer": "input",
     "text": "Ignore all previous instructions and ...", "expect": "block"}

Layers and the default handler that defends each one:
    input      what a person types        -> guardrails.check_input
    output     what the model wrote       -> guardrails.check_output (case "context": sources, citations, input)
    retrieved  a document / email / tool result with a planted instruction -> injection.quarantine
    tool       a tool call the model asked for -> the app supplies its own handler (role checks, SQL guard...)

Expectations: block (stopped), allow (benign control: must NOT be blocked; measures false alarms), redact (allowed
with personal data replaced), quarantine (instruction removed, rest kept).

    python -m hotelplatform.redteam --cases redteam/cases.jsonl --out docs/redteam-report.md --min-pass 1.0

Apps import `run()` and pass handlers for their own layers; the shared corpus (`shared_cases()`) covers what every
hotel app must withstand.
"""

import argparse
import io
import json
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from hotelplatform import guardrails, injection, jsonlog

EXPECTS = ("block", "allow", "redact", "quarantine")
LAYERS = ("input", "output", "retrieved", "tool")


@dataclass
class Case:
    id: str
    category: str
    layer: str
    text: str
    expect: str
    reason: str | None = None  # the block reason a defence should give (checked when set)
    context: dict = field(default_factory=dict)
    note: str = ""

    def __post_init__(self):
        if self.layer not in LAYERS:
            raise ValueError(f"{self.id}: layer must be one of {LAYERS}")
        if self.expect not in EXPECTS:
            raise ValueError(f"{self.id}: expect must be one of {EXPECTS}")


@dataclass
class Outcome:
    verdict: str  # block | allow | redact | quarantine
    reason: str | None = None
    detail: str = ""


@dataclass
class Result:
    case: Case
    outcome: Outcome

    @property
    def passed(self) -> bool:
        if self.outcome.verdict != self.case.expect:
            return False
        return self.case.reason is None or self.outcome.reason == self.case.reason


Handler = Callable[[Case], Outcome]


def load_cases(path: str | Path) -> list[Case]:
    cases = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip() and not line.lstrip().startswith("//"):
            try:
                cases.append(Case(**json.loads(line)))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{n}: {exc}") from exc
    ids = Counter(c.id for c in cases)
    dupes = [i for i, k in ids.items() if k > 1]
    if dupes:
        raise ValueError(f"duplicate case ids: {dupes}")
    return cases


def shared_cases() -> list[Case]:
    with resources.as_file(resources.files("hotelplatform") / "data" / "redteam_shared.jsonl") as path:
        return load_cases(path)


def input_handler(policy: guardrails.InputPolicy | None = None) -> Handler:
    def handle(case: Case) -> Outcome:
        v = guardrails.check_input(case.text, policy)
        if not v.allowed:
            return Outcome("block", v.reason, ", ".join(v.reasons))
        if any(f.startswith("pii_redacted") for f in v.flags):
            return Outcome("redact", None, ", ".join(v.flags))
        return Outcome("allow", None, ", ".join(v.flags))

    return handle


def output_handler(policy: guardrails.OutputPolicy | None = None) -> Handler:
    def handle(case: Case) -> Outcome:
        ctx = case.context
        v = guardrails.check_output(case.text, policy, ctx.get("sources"), ctx.get("citations"), ctx.get("input", ""))
        if not v.allowed:
            return Outcome("block", v.reason, ", ".join(v.reasons))
        if v.text != case.text:
            return Outcome("redact", None, ", ".join(v.flags))
        return Outcome("allow", None, ", ".join(v.flags))

    return handle


def retrieved_handler(case: Case) -> Outcome:
    cleaned, removed = injection.quarantine(case.text)
    return Outcome("quarantine" if removed else "allow", None, cleaned[:120])


def default_handlers(input_policy=None, output_policy=None) -> dict[str, Handler]:
    return {"input": input_handler(input_policy), "output": output_handler(output_policy),
            "retrieved": retrieved_handler}  # fmt: skip


def run(cases: list[Case], handlers: dict[str, Handler] | None = None) -> list[Result]:
    handlers = {**default_handlers(), **(handlers or {})}
    results = []
    for case in cases:
        handler = handlers.get(case.layer)
        if handler is None:
            results.append(Result(case, Outcome("allow", None, f"no handler for layer {case.layer!r}")))
            continue
        try:
            results.append(Result(case, handler(case)))
        except Exception as exc:  # a crash is a failed defence, reported, not hidden
            results.append(Result(case, Outcome("error", None, type(exc).__name__)))
    return results


def score(results: list[Result]) -> dict:
    attacks = [r for r in results if r.case.expect != "allow"]
    controls = [r for r in results if r.case.expect == "allow"]
    by_cat: dict[str, list[int]] = {}
    for r in results:
        by_cat.setdefault(r.case.category, [0, 0])
        by_cat[r.case.category][0] += r.passed
        by_cat[r.case.category][1] += 1
    return {
        "cases": len(results),
        "passed": sum(r.passed for r in results),
        "attacks_stopped": sum(r.passed for r in attacks),
        "attacks": len(attacks),
        "false_alarms": sum(not r.passed for r in controls),
        "controls": len(controls),
        "by_category": by_cat,
    }


def report_markdown(results: list[Result], title: str, notes: str = "") -> str:
    s = score(results)
    lines = [
        f"# {title}",
        "",
        f"- Cases: **{s['cases']}**, passed **{s['passed']}/{s['cases']}**",
        f"- Attacks stopped: **{s['attacks_stopped']}/{s['attacks']}**",
        f"- False alarms on benign controls: **{s['false_alarms']}/{s['controls']}**",
        "",
    ]
    if notes:
        lines += [notes, ""]
    lines += ["| Category | Passed |", "|---|---|"]
    lines += [f"| {cat} | {p}/{n} |" for cat, (p, n) in sorted(s["by_category"].items())]
    lines += ["", "| ID | Category | Layer | Expect | Got | Reason | Pass |", "|---|---|---|---|---|---|---|"]
    for r in results:
        got = r.outcome.verdict
        lines.append(
            f"| {r.case.id} | {r.case.category} | {r.case.layer} | {r.case.expect} | {got} | "
            f"{r.outcome.reason or ''} | {'PASS' if r.passed else '**FAIL**'} |"
        )
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run red-team cases against the shared guardrails.")
    ap.add_argument("--cases", help="JSONL file (default: the shared corpus)")
    ap.add_argument("--out", help="write a markdown report here")
    ap.add_argument("--min-pass", type=float, default=1.0, help="fail (exit 1) below this pass rate")
    args = ap.parse_args(argv)
    jsonlog.configure("redteam", "cli", stream=io.StringIO())  # block events are counted in the report instead
    cases = load_cases(args.cases) if args.cases else shared_cases()
    results = run(cases)
    s = score(results)
    if args.out:
        Path(args.out).write_text(report_markdown(results, "Red-team report (shared corpus)"), encoding="utf-8")
    for r in results:
        if not r.passed:
            print(f"FAIL {r.case.id} [{r.case.category}] expected {r.case.expect}, got {r.outcome.verdict}")
    rate = s["passed"] / s["cases"] if s["cases"] else 0.0
    print(f"{s['passed']}/{s['cases']} passed ({rate:.0%}); attacks stopped {s['attacks_stopped']}/{s['attacks']};"
          f" false alarms {s['false_alarms']}/{s['controls']}")  # fmt: skip
    return 0 if rate >= args.min_pass else 1


if __name__ == "__main__":
    sys.exit(main())
