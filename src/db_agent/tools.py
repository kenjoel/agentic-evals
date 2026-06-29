from sqlalchemy import text

from db_agent.db import get_engine


ALLOWED_TABLES = {
    "projects",
    "assessables",
    "findings",
    "test_cases",
    "domains",
    "users",
    "vendors",
    "weekly_updates",
    "evidence",
}


def get_record(table_name: str, record_id: int | str) -> dict | None:
    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Table not allowed: {table_name}")

    engine = get_engine()

    query = text(f"SELECT * FROM {table_name} WHERE id = :record_id LIMIT 1")

    with engine.connect() as conn:
        row = conn.execute(query, {"record_id": record_id}).mappings().first()

    return dict(row) if row else None


def list_records(
    table_name: str,
    limit: int = 20,
) -> list[dict]:
    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Table not allowed: {table_name}")

    limit = min(limit, 100)

    engine = get_engine()

    query = text(f"SELECT * FROM {table_name} ORDER BY id LIMIT :limit")

    with engine.connect() as conn:
        rows = conn.execute(query, {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]
