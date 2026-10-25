# Changelog

All notable changes are listed here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/).

## [0.1.2] - 2026-10-25

### Fixed

- Admin metrics in two rows with short values (cost and p50/p95 were cut off at laptop width); the cost cap and
  its percentage moved into the label. Waterfall height set on the chart element (it rendered about 40 px tall)
  and step names never hidden.

## [0.1.1] - 2026-10-25

### Fixed

- Admin waterfall: steps are numbered and ordered explicitly, so every span gets its own row (the Altair sort
  collapsed five steps into two labels on the first live check); zero-length checks get a visible bar.
- Cost metrics: dollar signs escaped (Streamlit rendered "$0.0002 of $1.00" as LaTeX and the signs vanished).

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
