-- A read-only role for the daily failure summary (streamlit-keep-awake's GitHub Action).
-- Run once in the Neon SQL editor as the database owner. Choose your own long random password.
-- Then put the role's connection string in the Actions secret OPS_DATABASE_URL.
CREATE ROLE ops_reader WITH LOGIN PASSWORD 'choose-a-long-random-password';
GRANT CONNECT ON DATABASE neondb TO ops_reader;
GRANT USAGE ON SCHEMA public TO ops_reader;
GRANT SELECT ON ops_request_log, ops_trace_span, ops_feedback TO ops_reader;
