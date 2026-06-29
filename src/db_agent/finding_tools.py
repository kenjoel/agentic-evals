from sqlalchemy import text

from db_agent.db import get_engine


def list_open_findings(
    risk_rating: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """
    List open findings, optionally filtered by risk rating.
    Read-only.
    """
    limit = min(limit, 100)

    base_query = """
        SELECT
            id,
            project_id,
            assessable_id,
            title,
            description,
            risk_rating,
            status,
            recommendation,
            created_at
        FROM findings
        WHERE lower(status) = 'open'
    """

    params = {"limit": limit}

    if risk_rating:
        base_query += " AND lower(risk_rating) = lower(:risk_rating)"
        params["risk_rating"] = risk_rating

    base_query += " ORDER BY created_at DESC LIMIT :limit"

    engine = get_engine()

    with engine.connect() as conn:
        rows = conn.execute(text(base_query), params).mappings().all()

    return [dict(row) for row in rows]


def get_finding(finding_id: int) -> dict | None:
    """
    Get one finding by ID.
    Read-only.
    """
    query = """
        SELECT
            id,
            project_id,
            assessable_id,
            title,
            description,
            risk_rating,
            status,
            recommendation,
            created_at
        FROM findings
        WHERE id = :finding_id
        LIMIT 1
    """

    engine = get_engine()

    with engine.connect() as conn:
        row = conn.execute(text(query), {"finding_id": finding_id}).mappings().first()

    return dict(row) if row else None


def list_project_findings(
    project_id: int,
    status: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """
    List findings for a specific project.
    Read-only.
    """
    limit = min(limit, 100)

    query = """
        SELECT
            id,
            project_id,
            assessable_id,
            title,
            description,
            risk_rating,
            status,
            recommendation,
            created_at
        FROM findings
        WHERE project_id = :project_id
    """

    params = {
        "project_id": project_id,
        "limit": limit,
    }

    if status:
        query += " AND lower(status) = lower(:status)"
        params["status"] = status

    query += " ORDER BY created_at DESC LIMIT :limit"

    engine = get_engine()

    with engine.connect() as conn:
        rows = conn.execute(text(query), params).mappings().all()

    return [dict(row) for row in rows]


def risk_summary() -> list[dict]:
    """
    Count findings by risk and status.
    Read-only.
    """
    query = """
        SELECT
            lower(risk_rating) AS risk_rating,
            lower(status) AS status,
            COUNT(*) AS count
        FROM findings
        GROUP BY lower(risk_rating), lower(status)
        ORDER BY
            CASE lower(risk_rating)
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            lower(status)
    """

    engine = get_engine()

    with engine.connect() as conn:
        rows = conn.execute(text(query)).mappings().all()

    return [dict(row) for row in rows]