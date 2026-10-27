import sqlite3
from typing import Dict, List, Tuple

DB_PATH = "aegis_rules.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tenant_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            pattern TEXT NOT NULL,
            entity_type TEXT NOT NULL DEFAULT 'KEYWORD',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(tenant_id, pattern)
        )
    """)
    conn.commit()
    conn.close()

def fetch_all_tenant_patterns() -> Dict[str, List[Tuple[str, str]]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT tenant_id, pattern, entity_type FROM tenant_rules")
    rows = cursor.fetchall()
    conn.close()

    grouped: Dict[str, List[Tuple[str, str]]] = {}
    for tenant_id, pattern, entity_type in rows:
        if tenant_id not in grouped:
            grouped[tenant_id] = []
        grouped[tenant_id].append((pattern, entity_type))
    return grouped

def save_tenant_patterns(tenant_id: str, patterns: List[Tuple[str, str]]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tenant_rules WHERE tenant_id = ?", (tenant_id,))
    for pattern, entity_type in patterns:
        cursor.execute(
            "INSERT OR REPLACE INTO tenant_rules (tenant_id, pattern, entity_type) VALUES (?, ?, ?)",
            (tenant_id, pattern, entity_type),
        )
    conn.commit()
    conn.close()
