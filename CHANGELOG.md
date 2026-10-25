# Changelog

All notable changes are listed here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-25

### Added

- `guardrails`: input checks (length, language, 6 attack categories, PII, off-topic) and output checks (citation,
  grounded numbers, PII leak, promises, off-brand, prompt leak).
- `injection`, `pii` (Presidio-style entities with checksums), `language`, `secrets_mask`.
- `tracing` (OpenTelemetry-shaped), `oplog` (shared Neon tables, batched writer, file fallback, retention),
  `jsonlog` (one JSON format for every app).
- `admin_gate` (per-process lockout), `admin_ui` (Admin page with waterfall), `bots` (keep-awake visits skipped).
- `redteam` with a 48-case shared corpus; `daily_summary`; `retention`.
- Injection and jailbreak sentences are cut out of a question when a real question remains (decision 9).
