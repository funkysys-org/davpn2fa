"""Local SQLite audit log for davpn2fa.

Replaces the former Supabase audit_log: no cloud dependency, no RLS, and
— unlike the Supabase variant — it records events in EVERY mode
(including AUTH_DISABLED=1 trusted-network deployments), because the
database lives on the same shared volume as the PKI.

Schema mirrors the former Supabase table so the dashboard template
(action, target_user, admin_email, created_at) keeps working.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DATA_DIR = os.environ.get("OPENVPN_DATA_DIR", "/etc/openvpn/data")
DB_PATH = os.path.join(DATA_DIR, "audit_log.db")

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_email TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    target_user TEXT,
    details     TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_log_created_at_idx
    ON audit_log (created_at DESC);
"""


def _connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _init():
    with _lock:
        conn = _connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def log_event(action, target_user=None, details=None, admin_email="unknown"):
    """Append one audit event. Never raises: an audit failure is logged
    to stderr (visible in container logs) but must not break the admin
    action that produced it."""
    try:
        with _lock:
            conn = _connect()
            try:
                conn.execute(
                    "INSERT INTO audit_log (admin_email, action, target_user, details, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        admin_email,
                        action,
                        target_user,
                        json.dumps(details or {}, default=str),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as exc:  # noqa: BLE001
        import sys

        print(
            f"audit_log insert FAILED for action '{action}' (target={target_user}): {exc}",
            file=sys.stderr,
        )


def recent_events(limit=10):
    """Most recent events, newest first, as dicts shaped for the
    dashboard template."""
    try:
        with _lock:
            conn = _connect()
            try:
                rows = conn.execute(
                    "SELECT admin_email, action, target_user, created_at "
                    "FROM audit_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            finally:
                conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


_init()
