"""Personal data: find it (guardrails) and remove it (before anything is stored).

Two jobs, one set of patterns:

    find_pii(text)       -> [Finding(entity, start, end, score)]   used by the input and output guardrails
    scrub_text(text)     -> text with every finding replaced         used before a log row or span is written
    redact_record(dict)  -> copy of a record with PII removed at any depth

Entity names follow Microsoft Presidio's predefined recognizers (EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN,
IBAN_CODE, IP_ADDRESS, PERSON) plus BOOKING_ID for the hotel group's own IDs. It is a Presidio-*equivalent*, not
Presidio: regular expressions with checksums (Luhn for cards, mod-97 for IBANs) and context words for names, no
spaCy model. Why: the apps run on Streamlit Community Cloud's free tier, where a 500 MB NLP model next to the
embeddings would not fit, and every check must run in CI without downloads (decision 2 in docs/DECISIONS.md).
The cost is recall on names in free text; that's listed in SECURITY.md and measured by tests/test_pii.py.

The `scrub*` functions are the same code the hotel apps used since Project 4 (`src/pii.py`), moved here so there is
one copy.
"""

import hashlib
import re
from dataclasses import dataclass

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
PHONE = re.compile(r"(?<![\w$.,:])(?:\+?\d{1,3}[ -]?)?(?:\(\d{2,4}\)|\d{2,4})[ -]?\d{3,4}[ -]?\d{3,4}(?![\w.,]?\d)")
SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
BOOKING = re.compile(r"\b(?:BR|ML)-\d{3,5}\b", re.I)
NAME = r"[A-ZÁÉÍÓÚÑ][a-záéíóúñ'’-]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ'’-]+){0,2}"
NAME_CONTEXT = re.compile(
    rf"(?P<lead>\b(?i:my name is|this is|i am|i'm|me llamo|soy|mi nombre es|guest named|guest called|"
    rf"(?:Mr|Mrs|Ms|Miss|Dr|Sr|Sra|Srta)\.?|(?:Hi|Hello|Dear|Hola|Estimado|Estimada|Estimado/a)[ \t]*,?)"
    rf"[ \t]+)(?P<name>{NAME})"
)
# The last line(s) of an email: "Thanks,\nPriya" / "Gracias,\nLucía Romero" / "Best regards,\nOwen Clarke"
SIGN_OFF = re.compile(
    rf"(?P<lead>\b(?i:thanks|thank you|cheers|regards|best regards|best|kind regards|many thanks|gracias|saludos|"
    rf"un saludo|atentamente)\s*[,!.]?\s*\n+\s*)(?P<name>{NAME})"
)
SAFE_WORDS = {
    "Guest",
    "Services",
    "Guest Services",
    "Beach",
    "Resort",
    "Mountain",
    "Lodge",
    "Front",
    "Desk",
    "Team",
    "Gold",
    "Silver",
    "Platinum",
    "Member",
    "Manager",
    "Staff",
    "Here",
    "Sorry",
    "Looking",
    "Interested",
    "Wondering",
    "Not",
    "Just",
    "Able",
    "Going",
    "Trying",
    "Staying",
    "The",
}

# Entities that are never needed to answer a hotel question; the input guardrail blocks them by default.
SENSITIVE = frozenset({"CREDIT_CARD", "US_SSN", "IBAN_CODE"})


@dataclass(frozen=True)
class Finding:
    entity: str
    start: int
    end: int
    score: float

    def to_dict(self) -> dict:
        return {"entity": self.entity, "start": self.start, "end": self.end, "score": self.score}


def luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    s = value.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    try:
        number = int("".join(str(int(c, 36)) for c in moved))
    except ValueError:
        return False
    return number % 97 == 1


def _name_ok(name: str) -> bool:
    return name not in SAFE_WORDS and name.split()[0] not in SAFE_WORDS


def find_pii(text: str, names: tuple[str, ...] = ()) -> list[Finding]:
    """Every piece of personal data found, longest-first where spans overlap. Pure, no I/O."""
    if not text:
        return []
    found: list[Finding] = []
    for m in EMAIL.finditer(text):
        found.append(Finding("EMAIL_ADDRESS", m.start(), m.end(), 1.0))
    for m in IBAN.finditer(text):
        if iban_ok(m.group(0)):
            found.append(Finding("IBAN_CODE", m.start(), m.end(), 1.0))
    for m in CARD.finditer(text):
        # Luhn-valid 13-19 digit runs are cards (high score); other long digit runs are probably phones.
        if luhn_ok(m.group(0)):
            found.append(Finding("CREDIT_CARD", m.start(), m.end(), 1.0))
    for m in SSN.finditer(text):
        found.append(Finding("US_SSN", m.start(), m.end(), 0.85))
    for m in IPV4.finditer(text):
        found.append(Finding("IP_ADDRESS", m.start(), m.end(), 0.6))
    for m in PHONE.finditer(text):
        found.append(Finding("PHONE_NUMBER", m.start(), m.end(), 0.7))
    for m in BOOKING.finditer(text):
        found.append(Finding("BOOKING_ID", m.start(), m.end(), 1.0))
    for pattern in (NAME_CONTEXT, SIGN_OFF):
        for m in pattern.finditer(text):
            if _name_ok(m.group("name")):
                found.append(Finding("PERSON", m.start("name"), m.end("name"), 0.6))
    for name in {n.strip() for n in names if n and len(n.strip()) > 2}:
        for m in re.finditer(rf"\b{re.escape(name)}\b", text):
            found.append(Finding("PERSON", m.start(), m.end(), 1.0))
    return _dedupe(found)


def _dedupe(found: list[Finding]) -> list[Finding]:
    """Drop findings inside a longer (or equal, higher-score) one, e.g. a phone match inside a card number."""
    found.sort(key=lambda f: (f.start, -(f.end - f.start), -f.score))
    kept: list[Finding] = []
    for f in found:
        if any(k.start <= f.start and f.end <= k.end for k in kept):
            continue
        kept.append(f)
    return kept


def entities(text: str) -> set[str]:
    return {f.entity for f in find_pii(text)}


def booking_pseudonym(booking_id: str) -> str:
    return "BK-" + hashlib.sha256(booking_id.upper().encode()).hexdigest()[:8]


def _name_sub(match: re.Match) -> str:
    if not _name_ok(match.group("name")):
        return match.group(0)
    return match.group("lead") + "[name]"


def scrub_text(text: str, names: tuple[str, ...] = ()) -> str:
    text = EMAIL.sub("[email]", text)
    text = IBAN.sub(lambda m: "[iban]" if iban_ok(m.group(0)) else m.group(0), text)
    text = CARD.sub("[card]", text)
    text = SSN.sub("[ssn]", text)
    text = PHONE.sub("[phone]", text)
    text = BOOKING.sub(lambda m: booking_pseudonym(m.group(0)), text)
    for name in sorted({n.strip() for n in names if n and len(n.strip()) > 1}, key=len, reverse=True):
        for part in [name, *name.split()]:
            if len(part) > 2:
                text = re.sub(rf"\b{re.escape(part)}\b", "[name]", text)
    text = NAME_CONTEXT.sub(_name_sub, text)
    return SIGN_OFF.sub(_name_sub, text)


# Fields that are personal data as a whole (stage 2 records the sender): replaced, not pattern-matched.
WHOLE_FIELDS = {
    "sender": "[email]",
    "from": "[email]",
    "sender_email": "[email]",
    "sender_name": "[name]",
    "name": "[name]",
    "guest_name": "[name]",
    "member_number": "[member]",
}
# Identifiers and enums: never personal data, and pattern-matching them would corrupt them (a trace ID is hex).
KEEP_FIELDS = {
    "request_id",
    "trace_id",
    "span_id",
    "parent_id",
    "turn_id",
    "session_id",
    "time",
    "ts",
    "schema_version",
    "model",
    "property",
    "outcome",
    "status",
    "kind",
    "source",
    "mode",
    "error_type",
    "page",
    "code",
    "category",
    "app",
    "version",
    "request_type",
}


def scrub(value, names: tuple[str, ...] = (), key: str | None = None):
    """Copy of a record with personal data removed from every string, at any depth."""
    if key in WHOLE_FIELDS and isinstance(value, str) and value:
        return WHOLE_FIELDS[key]
    if key in KEEP_FIELDS:
        return value
    if isinstance(value, str):
        return scrub_text(value, names)
    if isinstance(value, dict):
        return {k: scrub(v, names, k) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [scrub(v, names) for v in value]
    return value


def known_names(record: dict) -> tuple[str, ...]:
    """Names the record itself reveals (sender, guest name on a booking), masked wherever else they appear."""
    found = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("sender_name", "name", "guest_name") and isinstance(v, str):
                    found.append(v)
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(record)
    return tuple(found)


def redact_record(record: dict) -> dict:
    return scrub(record, known_names(record))
