import sqlite3
import uuid
from typing import Optional


class Vault:
    """Request-scoped bi-directional token store using a private in-memory SQLite DB."""

    def __init__(self):
        # Every instance gets its own private, isolated in-memory DB
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE vault (
                token      TEXT PRIMARY KEY,
                original   TEXT NOT NULL,
                label      TEXT NOT NULL,
                created_at REAL DEFAULT (unixepoch('now'))
            )
        """)
        self.conn.commit()

    def store(self, original: str, label: str) -> str:
        row = self.conn.execute(
            "SELECT token FROM vault WHERE original = ? AND label = ?",
            (original, label),
        ).fetchone()
        if row:
            return row[0]

        token = f"__TK_{uuid.uuid4().hex[:8].upper()}__"
        self.conn.execute(
            "INSERT INTO vault (token, original, label) VALUES (?, ?, ?)",
            (token, original, label),
        )
        self.conn.commit()
        return token

    def restore(self, token: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT original FROM vault WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def reconstruct(self, text: str) -> str:
        rows = self.conn.execute("SELECT token, original FROM vault").fetchall()
        for token, original in rows:
            text = text.replace(token, original)
        return text

    def close(self) -> None:
        """Close the connection and drop the in-memory database."""
        self.conn.close()
