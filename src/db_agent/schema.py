from sqlalchemy import inspect

from db_agent.db import get_engine


def list_tables() -> list[str]:
    engine = get_engine()
    inspector = inspect(engine)
    return sorted(inspector.get_table_names())


def describe_table(table_name: str) -> list[dict]:
    engine = get_engine()
    inspector = inspect(engine)

    if table_name not in inspector.get_table_names():
        raise ValueError(f"Unknown table: {table_name}")

    columns = inspector.get_columns(table_name)

    return [
        {
            "name": col["name"],
            "type": str(col["type"]),
            "nullable": col.get("nullable", True),
        }
        for col in columns
    ]
