"""
Vault — bi-directional token mapping backed by SQLite in-memory DB.

When Aegis sanitizes a payload before sending it to an LLM, it replaces
sensitive values with opaque tokens (e.g. "john@acme.com" → "__TK_0001__").
When the LLM response comes back, Vault reconstructs the original values.

This allows the AI response to reference masked entities naturally while
Aegis restores real values for the end user — with zero data leaving your
infrastructure.

Storage: SQLite in-memory (per-session). For multi-process deployments,
swap _get_conn() to use a persistent file or Redis.
"""

import sqlite3
import threading
import uuid
from typing import Optional


_LOCAL = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Thread-local SQLite in-memory connection."""
    if not hasattr(_LOCAL, "conn"):
        _LOCAL.conn = sqlite3.connect(":memory:", check_same_thread=False)
        _LOCAL.conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                token      TEXT PRIMARY KEY,
                original   TEXT NOT NULL,
                label      TEXT NOT NULL,
                created_at REAL DEFAULT (unixepoch('now'))
            )
        """)
        _LOCAL.conn.commit()
    return _LOCAL.conn


class Vault:
    """
    Thread-safe bi-directional token store.
    Each Vault instance shares the thread-local SQLite connection.
    """

    def store(self, original: str, label: str) -> str:
        """
        Store an original value and return its opaque token.
        Idempotent: same original → same token.
        """
        conn = _get_conn()
        # Check if already stored
        row = conn.execute(
            "SELECT token FROM vault WHERE original = ? AND label = ?",
            (original, label),
        ).fetchone()
        if row:
            return row[0]

        token = f"__TK_{uuid.uuid4().hex[:8].upper()}__"
        conn.execute(
            "INSERT INTO vault (token, original, label) VALUES (?, ?, ?)",
            (token, original, label),
        )
        conn.commit()
        return token

    def restore(self, token: str) -> Optional[str]:
        """Look up the original value for a token. Returns None if not found."""
        conn = _get_conn()
        row = conn.execute(
            "SELECT original FROM vault WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def reconstruct(self, text: str) -> str:
        """
        Replace all __TK_XXXXXXXX__ tokens in text with their original values.
        Used to de-anonymize LLM responses before returning to the client.
        """
        import re
        conn = _get_conn()
        rows = conn.execute("SELECT token, original FROM vault").fetchall()
        for token, original in rows:
            text = text.replace(token, original)
        return text

    def clear(self) -> None:
        """Wipe all stored mappings (e.g. end of session)."""
        conn = _get_conn()
        conn.execute("DELETE FROM vault")
        conn.commit()

    def stats(self) -> dict:
        conn = _get_conn()
        count = conn.execute("SELECT COUNT(*) FROM vault").fetchone()[0]
        return {"stored_mappings": count}
