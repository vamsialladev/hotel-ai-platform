"""Password gate for the owner-only Admin page (Staff page in the concierge).

- No ADMIN_PASSWORD set -> no Admin page at all (the app doesn't register it).
- Constant-time comparison; the message never says how close a guess was.
- Lockout after 5 wrong tries, for 15 minutes, counted per *process* as well as per browser session: opening a
  new tab doesn't reset the count. The trade-off: someone guessing can lock the owner out for 15 minutes too.
  That's acceptable for a demo; a real deployment puts Admin behind SSO (hotel-ai-handoff docs/SSO.md).
- Signed out after 30 minutes without activity.

Same rules as the stage 1 gate (`src/admin.py`, Project 4), moved here so every app shares one tested copy.
"""

import hmac
import math
import os
import threading
import time
from dataclasses import dataclass

MAX_ATTEMPTS = 5
LOCKOUT_S = 15 * 60
IDLE_S = 30 * 60
WRONG = "Incorrect password."
NOT_CONFIGURED = "The admin page is not configured."


@dataclass
class _Counter:
    failures: int = 0
    locked_until: float = 0.0


@dataclass
class SessionGate:
    """Per browser session (kept in st.session_state)."""

    failures: int = 0
    locked_until: float = 0.0
    unlocked: bool = False
    last_active: float = 0.0


_PROCESS: dict[str, _Counter] = {}
_LOCK = threading.Lock()


def secret(env: str = "ADMIN_PASSWORD", environ=None) -> str:
    return ((os.environ if environ is None else environ).get(env) or "").strip()


def enabled(env: str = "ADMIN_PASSWORD", environ=None) -> bool:
    return bool(secret(env, environ))


def _locked_message(until: float, now: float) -> str | None:
    if now < until:
        minutes = math.ceil((until - now) / 60)
        return f"Too many attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}."
    return None


def attempt(state: SessionGate, given: str, password: str, now: float | None = None, scope: str = "admin"):
    """(unlocked, message). `scope` separates gates in one process (Admin vs Staff)."""
    now = time.time() if now is None else now
    if not password:
        return False, NOT_CONFIGURED
    with _LOCK:
        proc = _PROCESS.setdefault(scope, _Counter())
        for c in (proc, state):
            if c.locked_until and now >= c.locked_until:
                c.failures, c.locked_until = 0, 0.0
        locked = _locked_message(max(proc.locked_until, state.locked_until), now)
        if locked:
            return False, locked
        if hmac.compare_digest((given or "").encode("utf-8"), password.encode("utf-8")):
            state.failures, state.unlocked, state.last_active = 0, True, now
            return True, None
        proc.failures += 1
        state.failures += 1
        if proc.failures >= MAX_ATTEMPTS or state.failures >= MAX_ATTEMPTS:
            proc.locked_until = state.locked_until = now + LOCKOUT_S
            return False, _locked_message(proc.locked_until, now)
        return False, WRONG


def still_signed_in(state: SessionGate, now: float | None = None, idle_s: float = IDLE_S) -> bool:
    now = time.time() if now is None else now
    if not state.unlocked:
        return False
    if now - state.last_active > idle_s:
        sign_out(state)
        return False
    state.last_active = now
    return True


def sign_out(state: SessionGate) -> None:
    state.unlocked = False
    state.last_active = 0.0


def reset_process_counters() -> None:
    """Tests only."""
    with _LOCK:
        _PROCESS.clear()
