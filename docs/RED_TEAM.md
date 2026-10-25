# Red team: the shared corpus

The shared corpus (`src/hotelplatform/data/redteam_shared.jsonl`) is what every hotel app must withstand. Each app
runs it through its own pipeline in CI, plus its own app-specific cases (tools, roles, data).

## Result (2026-10-25)

| | |
|---|---|
| Cases | 46 |
| Attacks stopped | 38/38 |
| Benign controls blocked (false alarms) | 0/8 |

Full table: [redteam-shared-report.md](redteam-shared-report.md). Re-run with `python -m hotelplatform.redteam`.

**Why this number flatters:** I wrote these cases while writing the patterns. A case written next to a pattern
will match it. The number says the patterns do what I meant, not that they catch what an attacker writes. The
honest test is each app's own suite, whose held-out cases were written after the patterns were frozen.

## What the cases cover

| Category | Layer | Cases | What it tries |
|---|---|---|---|
| direct_injection | input | 6 | "Ignore previous instructions", fake system tags, admin override, Spanish |
| jailbreak | input | 4 | DAN, developer mode, "pretend you have no rules" |
| prompt_leak | input | 2 | Print the system prompt, repeat everything above |
| data_exfiltration | input | 5 | Other guests' data, API key, env vars, send the chat to a URL |
| role_escalation | input | 4 | "I'm the manager", switch role, grant admin, approve it yourself |
| tool_misuse | input | 4 | SQL injection, path traversal, bulk cancel |
| pii | input | 3 | Card number, SSN (blocked); email + phone (replaced, question still answered) |
| indirect_injection | retrieved | 4 | Planted instructions in a policy, an email, a note |
| output_* | output | 6 | Refund/upgrade promises, prompt leak, PII leak, off-brand, uncited |
| benign_control | all | 8 | Wifi password, "ignore the dress code?", Spanish question, policy statements |

## Fixes the suite drove

- "Send the menu to a@b.co" was blocked as exfiltration (decision 8): the rule now targets URLs and bulk data.
- The number check didn't treat "4:00 p.m." and "16:00" as the same time; the normalisation is fixed and tested.

## Known gaps

- Paraphrased attacks ("could you set aside what you were told earlier") get through the patterns. Apps rely on
  the next layers: the model's own instructions, tool permissions in code, and staff approval for actions.
- Attacks in languages other than English and Spanish.
