import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "threats.db")

def init_db():
    """Create database and table if not exists"""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            risk_score  REAL NOT NULL,
            risk_level  TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            top_reasons TEXT,
            detected_at TEXT NOT NULL,
            source      TEXT DEFAULT 'chrome_extension'
        )
    """)
    conn.commit()
    conn.close()

def log_threat(url, risk_score, risk_level,
               is_phishing, top_reasons=""):
    """Save a detected threat to database"""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        INSERT INTO threats
        (url, risk_score, risk_level, is_phishing,
         top_reasons, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        url, risk_score, risk_level,
        1 if is_phishing else 0,
        str(top_reasons),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

def get_all_threats():
    """Get all threats as list of dicts"""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        SELECT id, url, risk_score, risk_level,
               is_phishing, top_reasons, detected_at
        FROM threats
        ORDER BY detected_at DESC
    """)
    rows = c.fetchall()
    conn.close()
    return [{
        "id"         : r[0],
        "url"        : r[1],
        "risk_score" : r[2],
        "risk_level" : r[3],
        "is_phishing": r[4],
        "top_reasons": r[5],
        "detected_at": r[6]
    } for r in rows]

def get_stats():
    """Get summary stats for dashboard"""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT COUNT(*) FROM threats")
    total = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE is_phishing=1")
    phishing = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM threats WHERE is_phishing=0")
    safe = c.fetchone()[0]

    c.execute("SELECT AVG(risk_score) FROM threats")
    avg_risk = c.fetchone()[0] or 0

    c.execute("""
        SELECT COUNT(*) FROM threats
        WHERE detected_at >= datetime('now', '-1 day')
    """)
    today = c.fetchone()[0]

    conn.close()
    return {
        "total"   : total,
        "phishing": phishing,
        "safe"    : safe,
        "avg_risk": round(avg_risk, 1),
        "today"   : today
    }

# Initialize DB when this file is imported
init_db()