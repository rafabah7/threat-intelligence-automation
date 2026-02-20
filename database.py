import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "soc.db")

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "data"), exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            link TEXT,
            source TEXT,
            type TEXT,
            severity TEXT,
            summary TEXT,
            cvss_score REAL,
            date TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_alert(entry):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts 
        (title, link, source, type, severity, summary, cvss_score, date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry["title"],
        entry["link"],
        entry["source"],
        entry["type"],
        entry["severity"],
        entry["summary"],
        entry["cvss_score"],
        entry["date"]
    ))

    conn.commit()
    conn.close()
