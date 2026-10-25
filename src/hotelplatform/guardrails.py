"""Input and output guardrails shared by every hotel app.

    v = check_input(question, InputPolicy(...))      before retrieval and the model
    if not v.allowed: show v.message, log v.reason
    ...model answers from v.text (PII the model doesn't need already replaced)...
    o = check_output(answer, OutputPolicy(...), sources=passages, citations=cited, input_text=question)
    show o.text (blocked answers become the policy's fallback message)

Input checks, in order: empty, length, language, attack patterns (injection, jailbreak, prompt leak, data
exfiltration, role escalation, tool misuse), personal data (sensitive kinds blocked, contact details replaced),
off-topic (the app's own scope rule).

Output checks: citation required, numbers grounded in the sources, personal data the user didn't give and the
sources don't contain, promises staff must approve (refunds, waivers, free items, "I've booked"), off-brand or
unsafe text, prompt leaks.

Every check is a pure function of its inputs: no model, no network, unit-tested, and cheap enough to run on every
request. When a trace is active the verdict is recorded on it, and every block is a structured log line with the
trace ID and reason.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from hotelplatform import injection, jsonlog, language, pii, tracing

ATTACKS = ("prompt_injection", "jailbreak", "prompt_leak", "data_exfiltration", "role_escalation", "tool_misuse")

INPUT_MESSAGES = {
    "empty": "Please type a question.",
    "too_long": "That message is too long for me. Could you shorten it to the main question?",
    "language": "Sorry, I can answer in English or Spanish. / Lo siento, puedo responder en inglés o español.",
    "prompt_injection": "I can't change how I work, but I'm happy to help with a question about the hotel.",
    "jailbreak": "I can't change how I work, but I'm happy to help with a question about the hotel.",
    "prompt_leak": "I can't share how I'm set up, but I'm happy to help with a question about the hotel.",
    "data_exfiltration": "I can't share other guests' details or system information.",
    "role_escalation": "I can't change roles or approve things here. A staff member can help with that.",
    "tool_misuse": "I can't run that. Could you ask the question in plain words?",
    "sensitive_pii": "Please don't share card numbers or ID numbers here. I don't need them to help.",
    "off_topic": "I can only help with questions about the hotel.",
}


@dataclass
class Verdict:
    allowed: bool
    stage: str  # input | output
    text: str  # what the app should use next: the sanitized input, or the answer to show
    reason: str | None = None  # the first blocking reason (a code from the messages tables)
    reasons: list[str] = field(default_factory=list)  # every blocking reason
    flags: list[str] = field(default_factory=list)  # noted, not blocking (e.g. "pii_redacted:EMAIL_ADDRESS")
    message: str | None = None  # what the user sees when blocked
    language: str | None = None

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "stage": self.stage,
            "reason": self.reason,
            "reasons": list(self.reasons),
            "flags": list(self.flags),
            "language": self.language,
        }


@dataclass
class InputPolicy:
    max_chars: int = 2000
    languages: tuple[str, ...] = ("en", "es")  # empty tuple = any language
    block: tuple[str, ...] = ATTACKS  # attack categories that stop the request
    flag: tuple[str, ...] = ()  # attack categories that are noted but let through (e.g. guest emails, quarantined)
    pii_block: frozenset[str] = pii.SENSITIVE
    pii_redact: frozenset[str] = frozenset({"EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", "IBAN_CODE"})
    on_topic: Callable[[str], bool] | None = None  # the app's scope rule; None = no topic check
    messages: dict[str, str] = field(default_factory=dict)

    def message(self, reason: str) -> str:
        return self.messages.get(reason) or INPUT_MESSAGES.get(reason, INPUT_MESSAGES["off_topic"])


def check_input(text: str, policy: InputPolicy | None = None) -> Verdict:
    policy = policy or InputPolicy()
    text = text or ""
    reasons: list[str] = []
    flags: list[str] = []
    lang = None

    if not text.strip():
        reasons.append("empty")
    elif len(text) > policy.max_chars:
        reasons.append("too_long")
    else:
        lang = language.detect(text)
        if policy.languages and lang not in (*policy.languages, "unknown"):
            reasons.append("language")
        for hit in injection.scan(text):
            if hit.category in policy.block:
                reasons.append(hit.category)
            elif hit.category in policy.flag:
                flags.append(hit.category)
        found = pii.find_pii(text)
        kinds = {f.entity for f in found}
        if kinds & policy.pii_block:
            reasons.append("sensitive_pii")
        redact = [f for f in found if f.entity in policy.pii_redact]
        if redact:
            text = _replace(text, redact)
            flags.extend(sorted({f"pii_redacted:{f.entity}" for f in redact}))
        if not reasons and policy.on_topic is not None and not policy.on_topic(text):
            reasons.append("off_topic")

    verdict = Verdict(
        allowed=not reasons,
        stage="input",
        text=text,
        reason=reasons[0] if reasons else None,
        reasons=reasons,
        flags=flags,
        message=policy.message(reasons[0]) if reasons else None,
        language=lang,
    )
    _record(verdict)
    return verdict


PLACEHOLDER = {
    "EMAIL_ADDRESS": "[email]",
    "PHONE_NUMBER": "[phone]",
    "IP_ADDRESS": "[ip]",
    "IBAN_CODE": "[iban]",
    "CREDIT_CARD": "[card]",
    "US_SSN": "[ssn]",
    "PERSON": "[name]",
    "BOOKING_ID": "[booking]",
}


def _replace(text: str, findings: list[pii.Finding]) -> str:
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        text = text[: f.start] + PLACEHOLDER.get(f.entity, "[pii]") + text[f.end :]
    return text


# ---------------------------------------------------------------------------------------------------------------
# Output

PROMISE_FIRST_PERSON = re.compile(
    r"\b(?:i|we)(?:'ll|'ve|\s+will|\s+have|\s+can|\s+am\s+going\s+to|\s+are\s+going\s+to)?\s+"
    r"(?:go\s+ahead\s+and\s+|happily\s+|gladly\s+)?"
    r"(?:refund(?:ed)?|waive(?:d)?|comp(?:ed|'d)?|credit(?:ed)?|upgrade(?:d)?|cancel(?:led|ed)?|book(?:ed)?|"
    r"charge(?:d)?|approve(?:d)?|reimburse(?:d)?|guarantee(?:d)?)\b",
    re.I,
)
PROMISE_TERMS = re.compile(
    r"\b(?:free\s+of\s+charge|at\s+no\s+(?:extra\s+)?(?:cost|charge)|on\s+the\s+house|full\s+refund|"
    r"complimentary|guaranteed|(?:fee|charge)s?\s+(?:is|are|has\s+been|have\s+been)\s+waived)\b",
    re.I,
)
# A commitment the model hedges or routes to a person is not a promise.
HEDGE = re.compile(
    r"\b(?:not|n't|cannot|can't|unable|never|won't|no\s+one|manager|staff|team|request|ask|check\s+(?:with|whether)|"
    r"may|might|whether|if|would\s+need|needs?\s+approval|approval)\b",
    re.I,
)
DEFAULT_BANNED = (
    "as an ai language model",
    "as a large language model",
    "i am just an ai",
    "fuck",
    "shit",
    "bitch",
    "asshole",
    "bastard",
)
PROMPT_LEAK = re.compile(
    r"\b(?:my|the)\s+(?:system\s+prompt|hidden\s+instructions|initial\s+instructions)\b|<\s*/?\s*system\s*>|"
    r"\byou\s+are\s+a\s+(?:helpful\s+)?(?:hotel\s+)?assistant\s+(?:for|that|who)\b",
    re.I,
)
NUMBER = re.compile(
    r"(?:[$€£]\s?\d[\d,]*(?:\.\d+)?)|(?:\b\d[\d,]*(?:\.\d+)?\s?(?:%|percent|dollars|usd|eur|euros))|"
    r"(?:\b\d{1,2}(?::\d{2})?\s?(?:a\.?m\.?|p\.?m\.?)\b)|(?:\b\d{1,2}:\d{2}\b)",
    re.I,
)

OUTPUT_FALLBACK = "I'm not able to answer that reliably. A member of staff can help."
OUTPUT_MESSAGES = {
    "uncited": "I couldn't find that in the hotel's documents, so I won't guess. A member of staff can help.",
    "policy_promise": "I can't promise that here, but I can pass it to a staff member who can decide.",
    "off_brand": OUTPUT_FALLBACK,
    "prompt_leak": "I can't share how I'm set up, but I'm happy to help with a question about the hotel.",
    "ungrounded_number": OUTPUT_FALLBACK,
}


@dataclass
class OutputPolicy:
    require_citation: bool = True
    numbers: str = "flag"  # flag | block | off: numbers in the answer must appear in the sources
    promises: str = "block"  # block | flag | off
    pii_leak: str = "redact"  # redact | block | off
    banned: tuple[str, ...] = DEFAULT_BANNED
    competitors: tuple[str, ...] = ()
    refusal_markers: tuple[str, ...] = (
        "i don't know",
        "i couldn't find",
        "i can't find",
        "isn't in the",
        "not in the documents",
        "not covered",
        "i can only help",
        "please contact",
        "a member of staff",
        "front desk can",
        "no lo sé",
        "no encuentro",
    )
    messages: dict[str, str] = field(default_factory=dict)

    def message(self, reason: str) -> str:
        return self.messages.get(reason) or OUTPUT_MESSAGES.get(reason, OUTPUT_FALLBACK)


def is_refusal(answer: str, policy: OutputPolicy) -> bool:
    low = answer.lower()
    return any(m in low for m in policy.refusal_markers)


TIME_12H = re.compile(r"^(\d{1,2})(?::(\d{2}))?(am|pm)$")


def _norm_number(s: str) -> str:
    """ "$1,200.00" -> "1200", "4:00 p.m." / "4 PM" / "16:00" -> "16:00", "15 percent" -> "15%"."""
    s = s.lower().replace(",", "").replace(" ", "")
    s = re.sub(r"([ap])\.?m\.?$", r"\1m", s)
    s = re.sub(r"(?:dollars|usd|euros|eur)$", "", s)
    s = s.replace("$", "").replace("€", "").replace("£", "").replace("percent", "%")
    s = re.sub(r"\.0+(?=%|$)", "", s)
    t = TIME_12H.match(s)
    if t:
        hour = int(t.group(1)) % 12 + (12 if t.group(3) == "pm" else 0)
        return f"{hour:02d}:{t.group(2) or '00'}"
    if re.fullmatch(r"\d:\d{2}", s):
        s = "0" + s
    return s


def ungrounded_numbers(answer: str, sources: list[str]) -> list[str]:
    """Money, percentages and times in the answer that no source contains (the "$75 bug" class). A number the
    guest typed doesn't count as grounded: echoing a wrong number from the question was exactly that bug."""
    pool = {_norm_number(m.group(0)) for src in sources for m in NUMBER.finditer(src or "")}
    return [m.group(0).strip() for m in NUMBER.finditer(answer) if _norm_number(m.group(0)) not in pool]


def promises(answer: str, sources: list[str]) -> list[str]:
    """Commitments only staff can make. First-person commitments count unless hedged in the same sentence;
    impersonal terms ("complimentary") count unless a source says the same (a policy statement, not a promise)."""
    found = []
    source_text = " ".join(sources).lower()
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", answer):
        for m in PROMISE_FIRST_PERSON.finditer(sentence):
            if not HEDGE.search(sentence):
                found.append(m.group(0))
        for m in PROMISE_TERMS.finditer(sentence):
            term = m.group(0).lower()
            if term not in source_text and not HEDGE.search(sentence):
                found.append(m.group(0))
    return found


def check_output(
    answer: str,
    policy: OutputPolicy | None = None,
    sources: list[str] | None = None,
    citations: list[str] | None = None,
    input_text: str = "",
) -> Verdict:
    policy = policy or OutputPolicy()
    sources = [s for s in (sources or []) if s]
    answer = answer or ""
    reasons: list[str] = []
    flags: list[str] = []
    text = answer
    refusal = is_refusal(answer, policy)

    low = answer.lower()
    if any(term in low for term in policy.banned) or any(c.lower() in low for c in policy.competitors):
        reasons.append("off_brand")
    if PROMPT_LEAK.search(answer):
        reasons.append("prompt_leak")
    if policy.require_citation and not refusal and not (citations or []):
        reasons.append("uncited")
    if policy.numbers != "off" and not refusal:
        missing = ungrounded_numbers(answer, sources)
        if missing:
            (reasons if policy.numbers == "block" else flags).append("ungrounded_number")
    if policy.promises != "off":
        if promises(answer, sources):
            (reasons if policy.promises == "block" else flags).append("policy_promise")
    if policy.pii_leak != "off":
        allowed_text = input_text + " " + " ".join(sources)
        leaked = [f for f in pii.find_pii(answer) if answer[f.start : f.end] not in allowed_text]
        leaked = [f for f in leaked if f.entity not in ("PERSON", "BOOKING_ID")]  # names: too noisy to block on
        if leaked:
            flags.append("pii_leak")
            if policy.pii_leak == "block":
                reasons.append("pii_leak")
            else:
                text = _replace(text, leaked)

    verdict = Verdict(
        allowed=not reasons,
        stage="output",
        text=text if not reasons else policy.message(reasons[0]),
        reason=reasons[0] if reasons else None,
        reasons=reasons,
        flags=flags,
        message=policy.message(reasons[0]) if reasons else None,
    )
    _record(verdict)
    return verdict


def _record(verdict: Verdict) -> None:
    """Put the verdict on the current span (or a new one) and log every block with its trace ID."""
    trace = tracing.current()
    if trace is not None:
        trace.record(
            f"guardrails.{verdict.stage}", 0.0, status="ok" if verdict.allowed else "blocked", **verdict.to_dict()
        )
    if not verdict.allowed:
        jsonlog.event(
            "guardrail_block",
            level="warning",
            stage=verdict.stage,
            reason=verdict.reason,
            reasons=verdict.reasons,
            trace_id=trace.trace_id if trace else None,
        )
