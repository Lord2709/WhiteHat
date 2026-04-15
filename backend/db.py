import json
import os
import sqlite3
from typing import Any, Dict

from config import DATA_DIR, DB_PATH


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_table_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def db_init() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS team_profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT '',
                linkedin_url TEXT NOT NULL DEFAULT '',
                professional_summary TEXT NOT NULL DEFAULT '',
                expertise_json TEXT NOT NULL DEFAULT '[]',
                availability_notes TEXT NOT NULL DEFAULT '',
                current_load INTEGER NOT NULL DEFAULT 0,
                available_hours_per_week INTEGER NOT NULL DEFAULT 40,
                sprint_hours_remaining INTEGER NOT NULL DEFAULT 20,
                work_days_json TEXT NOT NULL DEFAULT '["monday","tuesday","wednesday","thursday","friday"]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                system_name TEXT NOT NULL DEFAULT '',
                counts_json TEXT NOT NULL DEFAULT '{}',
                request_json TEXT NOT NULL DEFAULT '{}',
                result_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_config (
                id TEXT PRIMARY KEY DEFAULT 'default',
                packages_json TEXT NOT NULL DEFAULT '{}',
                va_cve_ids_json TEXT NOT NULL DEFAULT '[]',
                system_info_json TEXT NOT NULL DEFAULT '{}',
                maintenance_windows_json TEXT NOT NULL DEFAULT '[]',
                team_members_json TEXT NOT NULL DEFAULT '[]',
                exploit_language TEXT NOT NULL DEFAULT 'python',
                api_keys_json TEXT NOT NULL DEFAULT '{}',
                nl_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        ensure_table_column(conn, "analysis_config", "vendor_advisories_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_table_column(conn, "analysis_config", "internal_docs_json", "TEXT NOT NULL DEFAULT '[]'")
        ensure_table_column(conn, "analysis_config", "dependency_graph_json", "TEXT NOT NULL DEFAULT '[]'")
        conn.commit()


def json_loads_safe(raw: Any, fallback: Any) -> Any:
    try:
        if raw is None:
            return fallback
        return json.loads(raw)
    except Exception:
        return fallback


def team_profile_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "linkedin_url": row["linkedin_url"],
        "professional_summary": row["professional_summary"],
        "expertise": json_loads_safe(row["expertise_json"], []),
        "availability_notes": row["availability_notes"],
        "current_load": int(row["current_load"] or 0),
        "schedule": {
            "available_hours_per_week": int(row["available_hours_per_week"] or 40),
            "sprint_hours_remaining": int(row["sprint_hours_remaining"] or 20),
            "work_days": json_loads_safe(
                row["work_days_json"],
                ["monday", "tuesday", "wednesday", "thursday", "friday"],
            ),
        },
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def scan_row_to_meta(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "label": row["label"],
        "system_name": row["system_name"],
        "counts": json_loads_safe(row["counts_json"], {}),
        "created_at": row["created_at"],
    }
