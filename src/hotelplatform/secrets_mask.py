"""Secret values never reach a log line, a span, a stored row or the Admin page.

Two layers, both applied by `mask()`:
1. Known values: every environment variable whose name looks secret (KEY, TOKEN, PASSWORD, SECRET, DATABASE_URL,
   WEBHOOK, DEMO_CODE) is replaced wherever its value appears.
2. Shapes: Anthropic keys (`sk-ant-...`), GitHub tokens, Slack webhooks, `user:password@` in connection URLs and
   `password=...` pairs, in case a value arrives from somewhere other than the environment.
"""

import os
import re

SECRET_NAME = re.compile(r"(KEY|TOKEN|PASSWORD|SECRET|DATABASE_URL|WEBHOOK|DEMO_CODE)", re.I)
SHAPES = [
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), "[secret]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[secret]"),
    (re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "[secret]"),
    (re.compile(r"(?P<scheme>[a-z][a-z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@"), r"\g<scheme>[user]:[secret]@"),
    (re.compile(r"(?i)\b(password|passwd|pwd|api_key|apikey|token)\s*[=:]\s*[^\s,;&]+"), r"\1=[secret]"),
]
MIN_VALUE_LEN = 6  # shorter values (e.g. "1", "true") would mask ordinary words


def secret_values(environ=None) -> list[str]:
    env = os.environ if environ is None else environ
    values = {v for k, v in env.items() if SECRET_NAME.search(k) and v and len(v) >= MIN_VALUE_LEN}
    return sorted(values, key=len, reverse=True)


def mask(text: str, environ=None) -> str:
    if not text:
        return text
    for value in secret_values(environ):
        text = text.replace(value, "[secret]")
    for pattern, repl in SHAPES:
        text = pattern.sub(repl, text)
    return text


def mask_value(value, environ=None):
    """mask() applied to every string in a nested structure."""
    if isinstance(value, str):
        return mask(value, environ)
    if isinstance(value, dict):
        return {k: mask_value(v, environ) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [mask_value(v, environ) for v in value]
    return value


def describe_settings(names: list[str], environ=None) -> dict[str, str]:
    """{"ANTHROPIC_API_KEY": "set", "DATABASE_URL": "missing"}: what the config-loaded log line shows. No values."""
    env = os.environ if environ is None else environ
    return {n: ("set" if env.get(n) else "missing") for n in names}
