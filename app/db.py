from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./aither.db")

def _sqlite_path() -> str:
    if not DATABASE_URL.startswith("sqlite:///"):
        raise RuntimeError("This foundation currently requires a sqlite DATABASE_URL, e.g. sqlite:///./aither.db")
    path = DATABASE_URL.removeprefix("sqlite:///")
    if path == ":memory:": return path
    p = Path(path)
    if not p.is_absolute(): p = Path.cwd() / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return str(p)

@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(_sqlite_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally: conn.close()

def init_db() -> None:
    with connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,email_verified INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at TEXT NOT NULL,expires_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
        CREATE TABLE IF NOT EXISTS email_verification_tokens (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at TEXT NOT NULL,expires_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_email_verification_user_id ON email_verification_tokens(user_id);
        CREATE TABLE IF NOT EXISTS password_reset_tokens (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at TEXT NOT NULL,expires_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_password_reset_user_id ON password_reset_tokens(user_id);
        CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,event TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
        CREATE TABLE IF NOT EXISTS user_app_data (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,app_id TEXT NOT NULL,data_json TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY (user_id, app_id));
        CREATE INDEX IF NOT EXISTS idx_user_app_data_user_id ON user_app_data(user_id);
        CREATE TABLE IF NOT EXISTS telemetry_events (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT,app_id TEXT NOT NULL,event TEXT NOT NULL,details_json TEXT NOT NULL DEFAULT '{}',created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_telemetry_created_at ON telemetry_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_telemetry_app_id ON telemetry_events(app_id);
        CREATE TABLE IF NOT EXISTS mail_messages (id INTEGER PRIMARY KEY AUTOINCREMENT,owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,sender TEXT NOT NULL,recipients TEXT NOT NULL DEFAULT '',cc TEXT NOT NULL DEFAULT '',subject TEXT NOT NULL DEFAULT '',body TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,is_read INTEGER NOT NULL DEFAULT 0,deleted INTEGER NOT NULL DEFAULT 0,folder TEXT NOT NULL DEFAULT 'inbox');
        CREATE INDEX IF NOT EXISTS idx_mail_owner ON mail_messages(owner_user_id,deleted,id DESC);
        """)
