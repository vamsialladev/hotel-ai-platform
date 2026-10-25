"""Keep-awake and health-check visits are not users.

streamlit-keep-awake opens each app with `?source=keepawake` so free hosting doesn't put it to sleep. The apps
check this before anything else: no model call, no log row, no database connection (so Neon can stay suspended),
and Admin numbers stay about real visitors.
"""

BOT_SOURCES = ("keepawake", "healthcheck")


def source_of(query_params) -> str:
    """'keepawake' | 'healthcheck' | 'user'. Accepts st.query_params or a plain dict (values may be lists)."""
    try:
        value = query_params.get("source", "")
    except Exception:
        return "user"
    if isinstance(value, list | tuple):
        value = value[0] if value else ""
    value = str(value or "").strip().lower()
    return value if value in BOT_SOURCES else "user"


def is_bot(query_params) -> bool:
    return source_of(query_params) in BOT_SOURCES
