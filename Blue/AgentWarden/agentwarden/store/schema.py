"""SQLite DDL and connection pragmas. One statement per table, applied with
`CREATE TABLE IF NOT EXISTS` - there is no migration story yet (v1, single
schema version); see README's Known limitations."""
from __future__ import annotations

import sqlite3

PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
)

DDL = (
    """
    CREATE TABLE IF NOT EXISTS identities (
        identity_id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        source TEXT NOT NULL,
        bound_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tasks (
        task_id TEXT PRIMARY KEY,
        root_session_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        status TEXT NOT NULL,
        opened_at TEXT NOT NULL,
        closed_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        identity_id TEXT NOT NULL,
        transport TEXT NOT NULL,
        task_id TEXT NOT NULL,
        root_session_id TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        parent_session_id TEXT,
        started_at TEXT NOT NULL,
        last_activity_at TEXT NOT NULL,
        ended_at TEXT,
        closed_reason TEXT,
        status TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_task ON sessions(task_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_instance ON sessions(instance_id)",
    """
    CREATE TABLE IF NOT EXISTS session_edges (
        child_session_id TEXT PRIMARY KEY,
        parent_session_id TEXT NOT NULL,
        declared_at TEXT NOT NULL,
        accepted INTEGER NOT NULL,
        rejection_reason TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS grants (
        grant_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        upstream_server_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        scope_json TEXT NOT NULL,
        issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        max_uses INTEGER NOT NULL,
        use_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_grants_task_tool ON grants(task_id, tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_grants_session_tool ON grants(session_id, tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_grants_status ON grants(status)",
    """
    CREATE TABLE IF NOT EXISTS calls (
        call_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        upstream_server_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        arguments_digest TEXT NOT NULL,
        redacted_arguments_json TEXT NOT NULL,
        outcome TEXT NOT NULL,
        matched_rule_id TEXT,
        grant_id TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        latency_ms REAL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_calls_task ON calls(task_id)",
    "CREATE INDEX IF NOT EXISTS idx_calls_session ON calls(session_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        session_id TEXT NOT NULL,
        task_id TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        call_id TEXT,
        grant_id TEXT,
        tool_name TEXT,
        upstream_server_id TEXT,
        detail_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit_events(severity)",
)


def initialize_schema(conn: sqlite3.Connection) -> None:
    for pragma in PRAGMAS:
        conn.execute(pragma)
    for statement in DDL:
        conn.execute(statement)
    conn.commit()
