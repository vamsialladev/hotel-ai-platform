# Architecture

## Components

| Component | Responsibility | State |
|---|---|---|
| `guardrails` | Input and output verdicts; records each on the current trace; logs blocks | none (pure) |
| `injection` | Attack patterns; quarantine of retrieved text | none |
| `pii`, `secrets_mask` | Find and remove personal data; mask secrets | none |
| `language` | en / es / other, offline | none |
| `tracing` | One trace per request (context variable), spans with parents | per request, in memory |
| `oplog.OpsStore` | Queue → writer thread → Postgres / SQLite / JSONL; Admin reads; retention | one per app process |
| `jsonlog` | JSON lines on stdout | none |
| `admin_gate`, `admin_ui` | Password gate with lockout; Streamlit Admin page | lockout counters per process |
| `daily_summary` | Read-only daily error check for all apps | none |

## Request flow

```mermaid
sequenceDiagram
    participant A as App request handler
    participant T as tracing
    participant G as guardrails
    participant Q as OpsStore queue
    participant W as writer thread
    participant D as Neon
    A->>T: new_trace(app, session)
    A->>G: check_input(text)
    G->>T: record guardrails.input span
    A->>T: span(retrieval / model_call / tool:...)
    A->>G: check_output(answer, sources, citations)
    G->>T: record guardrails.output span
    A->>Q: submit(trace, request_row), redacted, returns at once
    W->>Q: take up to 50 items
    W->>D: executemany per table
    W-->>W: close connection after 60 s idle
```

## Tables

```mermaid
erDiagram
    ops_request_log ||--o{ ops_trace_span : trace_id
    ops_request_log ||--o{ ops_feedback : trace_id
    ops_request_log {
        text ts
        text app
        text trace_id
        text session_id
        text request_type
        text status
        text error_type
        real latency_ms
        int tokens_in
        int tokens_out
        real cost_usd
        text model
        text tool_calls
        text sources
        text safety_flags
        text source
        text version
    }
    ops_trace_span {
        text trace_id
        text span_id
        text parent_id
        text name
        real start_ms
        real duration_ms
        text status
        text attributes
    }
    ops_feedback {
        text trace_id
        text rating
        text reason
    }
```

Status values: `ok`, `refused`, `blocked` (guardrail), `error`, `timeout`, `capped`. Source values: `user`, `eval`,
`keepawake` and `healthcheck` (these two are never written).

## Scaling path

1. Today: one writer thread per app process, one free Neon database shared by all apps.
2. More traffic: partition the tables by day and drop old partitions instead of `DELETE`.
3. Much more: replace the row writer with an OpenTelemetry exporter to a collector (the trace and span shapes
   already match), and keep `ops_request_log` as a small summary table.
