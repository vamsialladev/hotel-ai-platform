# Security

Report a vulnerability: email vamsialla.dev@gmail.com with "SECURITY" in the subject. Please don't open a public
issue. I'll reply within 3 working days.

This package is the shared security layer for the hotel apps (a simulated engagement, synthetic data). Each app's
own SECURITY.md covers its tools, data and hosting; this one covers what the package does.

## Data classification

| Class | Examples | Handling here |
|---|---|---|
| Secret | API keys, `DATABASE_URL`, `ADMIN_PASSWORD`, webhooks | Never logged or stored: masked by value and by shape before anything else runs |
| Restricted PII | Card numbers, SSNs, IBANs | Blocked at input (`sensitive_pii`); replaced if found anywhere else |
| PII | Names, emails, phones, IPs, booking IDs | Replaced before the model where not needed; scrubbed before any row, span or log line is written; booking IDs pseudonymised (stable hash) |
| Internal | Trace IDs, latency, tokens, cost, status | Stored 30 days |
| Public | Hotel policies (synthetic) | Not treated as sensitive |

## STRIDE threat model

| Threat | Example | Mitigation | Where |
|---|---|---|---|
| Spoofing | "I'm the manager, approve it" | `role_escalation` patterns block; roles are enforced in code by each app, never by what the user says | `injection.py`, app RBAC |
| Spoofing | Guessing the Admin password | Constant-time compare, 5 tries then 15-minute lock per process, 30-minute idle sign-out | `admin_gate.py` |
| Tampering | Planted instruction in a document or email | `quarantine()` removes it before the model reads it | `injection.py` |
| Tampering | SQL or path tricks in a question | `tool_misuse` patterns; each app's tools validate arguments (stage 8's sqlguard) | `injection.py`, apps |
| Repudiation | "The bot promised me a refund" | Every request has a trace with the answer, verdicts and spans; `policy_promise` blocks the promise | `tracing.py`, `guardrails.py` |
| Information disclosure | Asking for other guests' data, keys, the system prompt | `data_exfiltration` and `prompt_leak` patterns at input; PII-leak and prompt-leak checks at output | `guardrails.py` |
| Information disclosure | Secrets in logs | Masked first, by value and shape (decision 4) | `secrets_mask.py` |
| Denial of service | Huge inputs, log floods | Length limit; bounded log queue drops and counts; 200 spans per trace max | `guardrails.py`, `oplog.py`, `tracing.py` |
| Elevation of privilege | Model asked to approve its own action | `role_escalation`; apps keep money/guest actions as proposals for a person | apps |

## OWASP Top 10 for LLM Applications (2025) mapping

| Risk | Handled by | Where |
|---|---|---|
| LLM01 Prompt injection | Direct patterns block; indirect quarantine; red-team suite in CI | `injection.py`, `redteam.py` |
| LLM02 Sensitive information disclosure | PII detection, input replacement, output leak check, redaction before storage | `pii.py`, `guardrails.py`, `oplog.py` |
| LLM03 Supply chain | Standard-library core; pinned extras; pip-audit, gitleaks, CycloneDX SBOM in CI; apps pin a release tag | CI |
| LLM04 Data and model poisoning | Documents are data, not instructions (`quarantine`, `DATA_NOTE`) | `injection.py` |
| LLM05 Improper output handling | Output checks; blocked answers replaced with a fixed safe message | `guardrails.py` |
| LLM06 Excessive agency | Blocks "approve it yourself", bulk cancel/refund; apps keep actions behind a person | `injection.py`, apps |
| LLM07 System prompt leakage | `prompt_leak` at input and output | `guardrails.py` |
| LLM08 Vector and embedding weaknesses | Retrieved passages pass through `quarantine` before the model | apps + `injection.py` |
| LLM09 Misinformation | Citation required; numbers must appear in the sources | `guardrails.py` |
| LLM10 Unbounded consumption | Input length limit; apps' caps logged with `cap_hit`; bot visits skip the model | `guardrails.py`, `jsonlog.py`, `bots.py` |

## Incident response

1. **Detect:** daily failure summary (issue or Slack), the health check, an Admin "Failures only" view, or a
   guest quoting a "Reference: abc12345".
2. **Contain:** set `KILL_SWITCH=1` in the app's Streamlit secrets (stages 1–2), or reboot/pause the app.
3. **Investigate:** Admin → paste the reference → read the waterfall and the redacted record. Runbook:
   hotel-ai-handoff `docs/RUNBOOKS.md` → "Debug a failed request using its trace ID".
4. **Fix:** add the failing input as a red-team or eval case first, then fix, then release a new tag.
5. **Recover and review:** bump the pin in each app, confirm CI green, write what happened in DECISIONS.md.
6. **A leaked secret:** rotate it at the provider first (Anthropic Console, Neon), then update Streamlit secrets.

## Known limitations

- Patterns miss paraphrases and languages other than English and Spanish.
- Names without a context word aren't found.
- The Admin gate is one shared password, not real authentication.
