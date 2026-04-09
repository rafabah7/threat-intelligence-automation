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
            date TEXT,
            cve_id TEXT,
            cwe TEXT,
            affected_products TEXT,
            published_date TEXT,
            vendor TEXT,
            cvss_vector TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_alert(entry):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            title, link, source, type, severity, summary, cvss_score, date,
            cve_id, cwe, affected_products, published_date, vendor, cvss_vector
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry["title"],
        entry["link"],
        entry["source"],
        entry["type"],
        entry["severity"],
        entry["summary"],
        entry["cvss_score"],
        entry["date"],
        entry.get("cve_id"),
        entry.get("cwe"),
        entry.get("affected_products"),
        entry.get("published_date"),
        entry.get("vendor"),
        entry.get("cvss_vector")
    ))

    conn.commit()
    conn.close()
