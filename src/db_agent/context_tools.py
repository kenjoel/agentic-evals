from sqlalchemy import text

from db_agent.db import get_engine


def get_finding_context(finding_id: int) -> dict | None:
    """
    Return one finding with project, assessable, test case, and evidence context.
    Read-only.
    """
    finding_query = """
        SELECT
            f.id AS finding_id,
            f.title AS finding_title,
            f.description AS finding_description,
            f.risk_rating AS finding_risk_rating,
            f.status AS finding_status,
            f.recommendation AS finding_recommendation,
            f.created_at AS finding_created_at,

            p.id AS project_id,
            p.name AS project_name,
            p.owner AS project_owner,
            p.status AS project_status,
            p.risk_rating AS project_risk_rating,

            a.id AS assessable_id,
            a.asset_name,
            a.asset_type,
            a.environment,
            a.criticality

        FROM findings f
        JOIN projects p
            ON f.project_id = p.id
        JOIN assessables a
            ON f.assessable_id = a.id
        WHERE f.id = :finding_id
        LIMIT 1
    """

    test_case_query = """
        SELECT
            id,
            domain,
            test_name,
            result,
            evidence_summary
        FROM test_cases
        WHERE finding_id = :finding_id
        ORDER BY id
    """

    evidence_query = """
        SELECT
            id,
            evidence_type,
            storage_ref,
            summary
        FROM evidence
        WHERE finding_id = :finding_id
        ORDER BY id
    """

    engine = get_engine()

    with engine.connect() as conn:
        row = conn.execute(text(finding_query), {"finding_id": finding_id}).mappings().first()
        if not row:
            return None

        test_cases = conn.execute(
            text(test_case_query),
            {"finding_id": finding_id},
        ).mappings().all()
        evidence_rows = conn.execute(
            text(evidence_query),
            {"finding_id": finding_id},
        ).mappings().all()

    return {
        "finding": {
            "id": row["finding_id"],
            "title": row["finding_title"],
            "description": row["finding_description"],
            "risk_rating": row["finding_risk_rating"],
            "status": row["finding_status"],
            "recommendation": row["finding_recommendation"],
            "created_at": row["finding_created_at"],
        },
        "project": {
            "id": row["project_id"],
            "name": row["project_name"],
            "owner": row["project_owner"],
            "status": row["project_status"],
            "risk_rating": row["project_risk_rating"],
        },
        "assessable": {
            "id": row["assessable_id"],
            "asset_name": row["asset_name"],
            "asset_type": row["asset_type"],
            "environment": row["environment"],
            "criticality": row["criticality"],
        },
        "test_cases": [dict(test_case) for test_case in test_cases],
        "evidence": [dict(evidence) for evidence in evidence_rows],
    }
