import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "security_logs.db")

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.commit()
        conn.close()

def log_analysis(action_type: str, content: str, status: str, reason: str):
    with get_db() as conn:
        conn.execute(
            '''INSERT INTO security_logs (action_type, content, status, reason) 
               VALUES (?, ?, ?, ?)''',
            (action_type, content, status, reason)
        )

def get_cached_analysis(content: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT status, reason FROM security_logs WHERE content = ? ORDER BY timestamp DESC LIMIT 1''',
            (content,)
        )
        row = cursor.fetchone()
        if row:
            return {"status": row[0], "reason": row[1]}
    return None
