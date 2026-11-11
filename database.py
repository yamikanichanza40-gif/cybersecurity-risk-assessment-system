
import sqlite3
from pathlib import Path

# Database file location
DATABASE = Path(__file__).resolve().parent / "risk_assessment.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    # Enable foreign key support
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_db():
    connection = get_db_connection()

    # ASSETS TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            description TEXT,
            importance TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # THREATS TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            threat_name TEXT NOT NULL,
            threat_category TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id)
                REFERENCES assets(id)
                ON DELETE CASCADE
        )
    """)

    # VULNERABILITIES TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            vulnerability_name TEXT NOT NULL,
            vulnerability_category TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id)
                REFERENCES assets(id)
                ON DELETE CASCADE
        )
    """)

    # RISK ASSESSMENTS TABLE
    connection.execute("""
        CREATE TABLE IF NOT EXISTS risk_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            threat_id INTEGER NOT NULL,
            vulnerability_id INTEGER NOT NULL,
            likelihood INTEGER NOT NULL,
            impact INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (asset_id)
                REFERENCES assets(id)
                ON DELETE CASCADE,

            FOREIGN KEY (threat_id)
                REFERENCES threats(id)
                ON DELETE CASCADE,

            FOREIGN KEY (vulnerability_id)
                REFERENCES vulnerabilities(id)
                ON DELETE CASCADE,

            CHECK (likelihood BETWEEN 1 AND 5),
            CHECK (impact BETWEEN 1 AND 5)
        )
    """)

    connection.commit()
    connection.close()


# ==========================================
# GET DASHBOARD DATA FROM DATABASE
# ==========================================

def get_dashboard_data():

    connection = get_db_connection()

    # Get actual summary totals
    summary = {
        "total_assets": connection.execute(
            "SELECT COUNT(*) FROM assets"
        ).fetchone()[0],

        "total_threats": connection.execute(
            "SELECT COUNT(*) FROM threats"
        ).fetchone()[0],

        "assessed_risks": connection.execute(
            "SELECT COUNT(*) FROM risk_assessments"
        ).fetchone()[0],

        "critical_risks": connection.execute("""
            SELECT COUNT(*)
            FROM risk_assessments
            WHERE LOWER(risk_level) = 'critical'
        """).fetchone()[0]
    }

    # Get actual risk distribution
    risk_distribution = {
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    distribution_records = connection.execute("""
        SELECT LOWER(risk_level) AS level, COUNT(*) AS total
        FROM risk_assessments
        GROUP BY LOWER(risk_level)
    """).fetchall()

    for record in distribution_records:
        if record["level"] in risk_distribution:
            risk_distribution[record["level"]] = record["total"]

    # Get the five most recent risk assessments
    recent_risks = connection.execute("""
        SELECT
            assets.name AS asset,
            threats.threat_name AS threat,
            risk_assessments.likelihood,
            risk_assessments.impact,
            risk_assessments.risk_score AS score,
            risk_assessments.risk_level AS level
        FROM risk_assessments

        JOIN assets
            ON risk_assessments.asset_id = assets.id

        JOIN threats
            ON risk_assessments.threat_id = threats.id

        ORDER BY risk_assessments.id DESC
        LIMIT 5
    """).fetchall()

    # Convert database rows into dictionaries
    recent_risks = [dict(risk) for risk in recent_risks]

    connection.close()

    return summary, risk_distribution, recent_risks


# ==========================================
# GET RISK REGISTER RECORDS
# ==========================================

def get_risk_register():

    connection = get_db_connection()

    risks = connection.execute("""
        SELECT
            risk_assessments.id,
            risk_assessments.asset_id,
            risk_assessments.threat_id,
            risk_assessments.vulnerability_id,
            assets.name AS asset_name,
            assets.asset_type,
            threats.threat_name,
            threats.threat_category,
            vulnerabilities.vulnerability_name,
            vulnerabilities.severity,
            risk_assessments.likelihood,
            risk_assessments.impact,
            risk_assessments.risk_score,
            risk_assessments.risk_level,
            risk_assessments.created_at

        FROM risk_assessments

        JOIN assets
            ON risk_assessments.asset_id = assets.id

        JOIN threats
            ON risk_assessments.threat_id = threats.id

        JOIN vulnerabilities
            ON risk_assessments.vulnerability_id = vulnerabilities.id

        ORDER BY risk_assessments.id DESC
    """).fetchall()

    connection.close()

    return risks
