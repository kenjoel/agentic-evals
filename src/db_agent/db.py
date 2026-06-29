import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

load_dotenv()

DEFAULT_DEMO_DATABASE_URL = "sqlite:///data/assurance_demo.db"


def get_engine() -> Engine:
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is missing. Add it to your .env file.")

    return create_engine(database_url, future=True)


def test_connection() -> bool:
    engine = get_engine()

    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))

    return True


def initialize_demo_database(reset: bool = False) -> str:
    database_url = os.getenv("DATABASE_URL", DEFAULT_DEMO_DATABASE_URL)

    if not database_url.startswith("sqlite:///"):
        raise RuntimeError(
            "Demo database initialization only supports SQLite. "
            "Set DATABASE_URL to a local sqlite:/// path first."
        )

    db_path = Path(database_url.removeprefix("sqlite:///"))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(database_url, future=True)

    drop_statements = [
        "DROP TABLE IF EXISTS test_cases",
        "DROP TABLE IF EXISTS weekly_updates",
        "DROP TABLE IF EXISTS evidence",
        "DROP TABLE IF EXISTS findings",
        "DROP TABLE IF EXISTS assessables",
        "DROP TABLE IF EXISTS domains",
        "DROP TABLE IF EXISTS vendors",
        "DROP TABLE IF EXISTS users",
        "DROP TABLE IF EXISTS projects",
    ]

    create_statements = [
        """
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            owner TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_rating TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            team TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            service_type TEXT NOT NULL,
            tier TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            owner_team TEXT NOT NULL,
            severity_focus TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS assessables (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            asset_name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            environment TEXT NOT NULL,
            criticality TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            assessable_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_rating TEXT NOT NULL,
            status TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id),
            FOREIGN KEY(assessable_id) REFERENCES assessables(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS test_cases (
            id INTEGER PRIMARY KEY,
            finding_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            test_name TEXT NOT NULL,
            result TEXT NOT NULL,
            evidence_summary TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS weekly_updates (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL,
            update_week TEXT NOT NULL,
            status_summary TEXT NOT NULL,
            blockers TEXT NOT NULL,
            next_step TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY,
            finding_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,
            storage_ref TEXT NOT NULL,
            summary TEXT NOT NULL,
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        )
        """,
    ]

    seed_rows: dict[str, list[dict[str, object]]] = {
        "projects": [
            {"id": 1, "name": "M-Pesa API Gateway", "owner": "Platform Assurance", "status": "active", "risk_rating": "high", "created_at": "2026-01-08"},
            {"id": 2, "name": "Consumer Mobile App", "owner": "Digital Channels", "status": "active", "risk_rating": "high", "created_at": "2026-01-15"},
            {"id": 3, "name": "Dealer Operations Portal", "owner": "Enterprise IT", "status": "in_review", "risk_rating": "medium", "created_at": "2026-02-02"},
            {"id": 4, "name": "Partner Settlement Service", "owner": "Finance Engineering", "status": "active", "risk_rating": "critical", "created_at": "2026-02-19"},
            {"id": 5, "name": "Identity Verification Flow", "owner": "Trust Services", "status": "planned", "risk_rating": "medium", "created_at": "2026-03-10"},
        ],
        "users": [
            {"id": 1, "full_name": "Amina Njoroge", "email": "amina.njoroge@example.test", "role": "assurance_lead", "team": "platform"},
            {"id": 2, "full_name": "Brian Otieno", "email": "brian.otieno@example.test", "role": "security_analyst", "team": "mobile"},
            {"id": 3, "full_name": "Caroline Wambui", "email": "caroline.wambui@example.test", "role": "qa_engineer", "team": "qa"},
            {"id": 4, "full_name": "David Kiptoo", "email": "david.kiptoo@example.test", "role": "project_manager", "team": "enterprise"},
            {"id": 5, "full_name": "Esther Mwangi", "email": "esther.mwangi@example.test", "role": "vendor_manager", "team": "third_party"},
        ],
        "vendors": [
            {"id": 1, "name": "Savanna Payments Ltd", "service_type": "payments", "tier": "tier_1", "status": "approved"},
            {"id": 2, "name": "Kijani Cloud Services", "service_type": "hosting", "tier": "tier_2", "status": "under_review"},
            {"id": 3, "name": "Twiga Mobile Labs", "service_type": "mobile_testing", "tier": "tier_2", "status": "approved"},
            {"id": 4, "name": "Jua Identity Systems", "service_type": "identity", "tier": "tier_1", "status": "approved"},
            {"id": 5, "name": "Delta Integrations", "service_type": "integration", "tier": "tier_3", "status": "restricted"},
        ],
        "domains": [
            {"id": 1, "name": "API Security", "owner_team": "platform", "severity_focus": "high"},
            {"id": 2, "name": "Authentication", "owner_team": "trust", "severity_focus": "critical"},
            {"id": 3, "name": "Mobile", "owner_team": "digital", "severity_focus": "high"},
            {"id": 4, "name": "Network Segmentation", "owner_team": "enterprise", "severity_focus": "medium"},
            {"id": 5, "name": "Third-Party Risk", "owner_team": "governance", "severity_focus": "high"},
        ],
        "assessables": [
            {"id": 1, "project_id": 1, "asset_name": "gateway-public-api", "asset_type": "api", "environment": "prod-like", "criticality": "critical"},
            {"id": 2, "project_id": 1, "asset_name": "gateway-admin-console", "asset_type": "web", "environment": "staging", "criticality": "high"},
            {"id": 3, "project_id": 2, "asset_name": "consumer-android-app", "asset_type": "mobile", "environment": "uat", "criticality": "high"},
            {"id": 4, "project_id": 2, "asset_name": "consumer-ios-app", "asset_type": "mobile", "environment": "uat", "criticality": "high"},
            {"id": 5, "project_id": 3, "asset_name": "dealer-portal", "asset_type": "web", "environment": "staging", "criticality": "medium"},
            {"id": 6, "project_id": 3, "asset_name": "dealer-reporting-api", "asset_type": "api", "environment": "staging", "criticality": "medium"},
            {"id": 7, "project_id": 4, "asset_name": "settlement-engine", "asset_type": "service", "environment": "prod-like", "criticality": "critical"},
            {"id": 8, "project_id": 4, "asset_name": "partner-sftp-bridge", "asset_type": "integration", "environment": "prod-like", "criticality": "high"},
            {"id": 9, "project_id": 5, "asset_name": "idv-webhook-handler", "asset_type": "api", "environment": "dev", "criticality": "medium"},
            {"id": 10, "project_id": 5, "asset_name": "idv-operator-dashboard", "asset_type": "web", "environment": "dev", "criticality": "medium"},
        ],
        "findings": [
            {"id": 1, "project_id": 1, "assessable_id": 1, "title": "Missing rate limiting on payout endpoint", "description": "Public payout endpoint accepts burst traffic without throttling.", "risk_rating": "high", "status": "open", "recommendation": "Add tenant-aware rate limiting and abuse alerts.", "created_at": "2026-03-01"},
            {"id": 2, "project_id": 1, "assessable_id": 2, "title": "Admin console lacks MFA enforcement", "description": "Privileged logins can still complete with password only.", "risk_rating": "critical", "status": "open", "recommendation": "Enforce MFA for all privileged roles.", "created_at": "2026-03-03"},
            {"id": 3, "project_id": 1, "assessable_id": 1, "title": "Verbose error responses leak stack metadata", "description": "API errors expose framework and handler details.", "risk_rating": "medium", "status": "mitigated", "recommendation": "Return generic errors and centralize exception handling.", "created_at": "2026-03-04"},
            {"id": 4, "project_id": 2, "assessable_id": 3, "title": "Android app stores session token in shared prefs", "description": "Session token persists in plaintext local storage.", "risk_rating": "high", "status": "open", "recommendation": "Move secrets into encrypted storage.", "created_at": "2026-03-10"},
            {"id": 5, "project_id": 2, "assessable_id": 4, "title": "iOS certificate pinning disabled in release build", "description": "Release profile allows fallback trust chain.", "risk_rating": "high", "status": "open", "recommendation": "Enable pinning and block release without it.", "created_at": "2026-03-11"},
            {"id": 6, "project_id": 2, "assessable_id": 3, "title": "Biometric fallback bypasses lockout threshold", "description": "Fallback path does not honor retry counters.", "risk_rating": "medium", "status": "accepted", "recommendation": "Share retry state across biometric and PIN flows.", "created_at": "2026-03-12"},
            {"id": 7, "project_id": 3, "assessable_id": 5, "title": "Dealer portal session cookie missing SameSite", "description": "Browser sends session cookie in cross-site navigation.", "risk_rating": "medium", "status": "open", "recommendation": "Set SameSite=Lax or Strict based on workflow needs.", "created_at": "2026-03-18"},
            {"id": 8, "project_id": 3, "assessable_id": 6, "title": "Reporting API trusts unsigned internal headers", "description": "API accepts role headers from upstream without verification.", "risk_rating": "high", "status": "open", "recommendation": "Derive identity from signed service credentials only.", "created_at": "2026-03-19"},
            {"id": 9, "project_id": 4, "assessable_id": 7, "title": "Settlement service uses hard-coded retry secret", "description": "Legacy retry worker contains embedded shared secret.", "risk_rating": "critical", "status": "open", "recommendation": "Rotate the secret and move it to secret storage.", "created_at": "2026-03-21"},
            {"id": 10, "project_id": 4, "assessable_id": 8, "title": "SFTP bridge accepts weak ciphers", "description": "Bridge still negotiates deprecated transport ciphers.", "risk_rating": "high", "status": "mitigated", "recommendation": "Restrict cipher suite to approved strong algorithms.", "created_at": "2026-03-22"},
            {"id": 11, "project_id": 4, "assessable_id": 7, "title": "Settlement reconciler lacks dual-control approval", "description": "Single operator can rerun settlement batches.", "risk_rating": "high", "status": "open", "recommendation": "Require second approver for manual reruns.", "created_at": "2026-03-23"},
            {"id": 12, "project_id": 5, "assessable_id": 9, "title": "Webhook signature verification not implemented", "description": "Incoming webhook payloads are trusted without HMAC validation.", "risk_rating": "high", "status": "open", "recommendation": "Validate signatures before processing callbacks.", "created_at": "2026-03-28"},
            {"id": 13, "project_id": 5, "assessable_id": 10, "title": "Dashboard audit trail omits failed admin actions", "description": "Failed admin actions are not logged for review.", "risk_rating": "medium", "status": "open", "recommendation": "Log failed actions with actor and reason codes.", "created_at": "2026-03-29"},
            {"id": 14, "project_id": 1, "assessable_id": 2, "title": "Excessive admin role grants in default seed data", "description": "Seed users receive broad roles not needed for onboarding.", "risk_rating": "low", "status": "closed", "recommendation": "Reduce default roles to least privilege.", "created_at": "2026-03-30"},
            {"id": 15, "project_id": 3, "assessable_id": 5, "title": "Portal file upload type validation bypass", "description": "Renamed files bypass MIME validation checks.", "risk_rating": "high", "status": "open", "recommendation": "Validate MIME and file signature server-side.", "created_at": "2026-04-01"},
        ],
        "test_cases": [
            {"id": 1, "finding_id": 1, "domain": "API Security", "test_name": "Burst payout requests", "result": "failed", "evidence_summary": "429 responses never triggered during 500-request burst."},
            {"id": 2, "finding_id": 2, "domain": "Authentication", "test_name": "Privileged login MFA challenge", "result": "failed", "evidence_summary": "Admin login succeeded with password only."},
            {"id": 3, "finding_id": 4, "domain": "Mobile", "test_name": "Android token storage review", "result": "failed", "evidence_summary": "Session token found in shared preferences XML."},
            {"id": 4, "finding_id": 5, "domain": "Mobile", "test_name": "TLS pinning release validation", "result": "failed", "evidence_summary": "Release build accepted proxy certificate."},
            {"id": 5, "finding_id": 7, "domain": "Web", "test_name": "Cookie attribute inspection", "result": "failed", "evidence_summary": "SameSite attribute missing from session cookie."},
            {"id": 6, "finding_id": 8, "domain": "API Security", "test_name": "Internal header spoofing", "result": "failed", "evidence_summary": "Unsigned X-Role header granted elevated access."},
            {"id": 7, "finding_id": 9, "domain": "Secrets Management", "test_name": "Static secret scan", "result": "failed", "evidence_summary": "Retry worker config contained embedded secret string."},
            {"id": 8, "finding_id": 10, "domain": "Network", "test_name": "SSH cipher negotiation", "result": "passed", "evidence_summary": "Weak cipher support removed in remediated build."},
            {"id": 9, "finding_id": 12, "domain": "API Security", "test_name": "Webhook signature replay", "result": "failed", "evidence_summary": "Unsigned webhook accepted and processed."},
            {"id": 10, "finding_id": 15, "domain": "Web", "test_name": "Polyglot upload validation", "result": "failed", "evidence_summary": "Renamed executable bypassed file validation."},
        ],
        "weekly_updates": [
            {"id": 1, "project_id": 1, "update_week": "2026-W13", "status_summary": "Gateway testing expanded to privileged workflows.", "blockers": "Awaiting MFA rollout timeline.", "next_step": "Retest admin console after auth changes."},
            {"id": 2, "project_id": 2, "update_week": "2026-W13", "status_summary": "Mobile findings reproduced on both platforms.", "blockers": "Release branch still open for feature merges.", "next_step": "Validate secure storage patch on candidate build."},
            {"id": 3, "project_id": 3, "update_week": "2026-W13", "status_summary": "Portal and reporting API assessment still active.", "blockers": "Need updated upload service container image.", "next_step": "Retest upload validation and header trust."},
            {"id": 4, "project_id": 4, "update_week": "2026-W13", "status_summary": "Critical secrets issue escalated to finance engineering.", "blockers": "Secret rotation maintenance window pending.", "next_step": "Confirm compensating controls for rerun approvals."},
            {"id": 5, "project_id": 5, "update_week": "2026-W13", "status_summary": "Planning-stage review already surfaced webhook gap.", "blockers": "No signed callback sample payloads yet.", "next_step": "Implement HMAC verification before staging tests."},
        ],
        "evidence": [
            {"id": 1, "finding_id": 1, "evidence_type": "http_capture", "storage_ref": "demo://evidence/finding-1", "summary": "Burst request traces with sustained 200 responses."},
            {"id": 2, "finding_id": 2, "evidence_type": "screen_recording", "storage_ref": "demo://evidence/finding-2", "summary": "Admin console login without MFA prompt."},
            {"id": 3, "finding_id": 4, "evidence_type": "filesystem_extract", "storage_ref": "demo://evidence/finding-4", "summary": "Shared preferences file with session token."},
            {"id": 4, "finding_id": 8, "evidence_type": "request_replay", "storage_ref": "demo://evidence/finding-8", "summary": "Spoofed internal header accepted by reporting API."},
            {"id": 5, "finding_id": 12, "evidence_type": "webhook_trace", "storage_ref": "demo://evidence/finding-12", "summary": "Unsigned callback payload successfully processed."},
        ],
    }

    with engine.begin() as conn:
        if reset:
            for statement in drop_statements:
                conn.execute(text(statement))

        for statement in create_statements:
            conn.execute(text(statement))

        existing = conn.execute(text("SELECT COUNT(*) FROM projects")).scalar_one()
        if existing:
            return database_url

        for table_name, rows in seed_rows.items():
            if rows:
                columns = ", ".join(rows[0].keys())
                placeholders = ", ".join(f":{column}" for column in rows[0].keys())
                conn.execute(
                    text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"),
                    rows,
                )

    return database_url
