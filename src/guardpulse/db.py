"""SQLite storage: schema, migrations and the app-private data folder."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('block', 'allow')),
    value      TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS apps (
    id         INTEGER PRIMARY KEY,
    package    TEXT NOT NULL UNIQUE,
    label      TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS schedules (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    days       INTEGER NOT NULL CHECK (days BETWEEN 1 AND 127),  -- bit 0 = Monday
    start_min  INTEGER NOT NULL CHECK (start_min BETWEEN 0 AND 1439),
    end_min    INTEGER NOT NULL CHECK (end_min BETWEEN 0 AND 1439),
    packages   TEXT NOT NULL,                                     -- JSON list
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL                                           -- JSON value
);

CREATE TABLE IF NOT EXISTS partner (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    name              TEXT NOT NULL,
    contact           TEXT NOT NULL DEFAULT '',
    pin_hash          TEXT NOT NULL,
    totp_secret       TEXT NOT NULL,
    totp_last_counter INTEGER NOT NULL DEFAULT 0,
    failed_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until      REAL NOT NULL DEFAULT 0,
    created_at        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id            INTEGER PRIMARY KEY,
    at            REAL NOT NULL,
    action        TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    authorised_by TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS ix_audit_at ON audit (at DESC);

CREATE TABLE IF NOT EXISTS outbox (
    id       INTEGER PRIMARY KEY,
    at       REAL NOT NULL,
    event    TEXT NOT NULL,
    payload  TEXT NOT NULL,                                       -- JSON
    attempts INTEGER NOT NULL DEFAULT 0,
    sent_at  REAL
);
CREATE INDEX IF NOT EXISTS ix_outbox_pending ON outbox (sent_at) WHERE sent_at IS NULL;

-- activity from this account's other phones (Phase 6 sync); never re-uploaded
CREATE TABLE IF NOT EXISTS remote_activity (
    key           TEXT PRIMARY KEY,                               -- "<device>:<audit id>"
    device        TEXT NOT NULL,
    at            REAL NOT NULL,
    action        TEXT NOT NULL,
    detail        TEXT NOT NULL DEFAULT '',
    authorised_by TEXT NOT NULL DEFAULT 'none'
);
CREATE INDEX IF NOT EXISTS ix_remote_activity_at ON remote_activity (at DESC);
"""


def data_dir() -> Path:
    """App-private storage: Flet sets FLET_APP_STORAGE_DATA on device builds."""
    root = os.getenv("FLET_APP_STORAGE_DATA") or str(Path.cwd() / "storage")
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    return path


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA secure_delete = ON")
    conn.executescript(SCHEMA)
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
    return conn
