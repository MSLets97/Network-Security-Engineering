import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("output/jobs.db")


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            company     TEXT    NOT NULL,
            location    TEXT,
            url         TEXT    UNIQUE NOT NULL,
            platform    TEXT    NOT NULL,
            status      TEXT    DEFAULT 'found',
            salary      TEXT,
            job_type    TEXT,
            found_at    TEXT    NOT NULL,
            applied_at  TEXT,
            notes       TEXT
        )
    """)
    conn.commit()
    conn.close()


def job_exists(url: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM jobs WHERE url = ?", (url,))
    exists = c.fetchone() is not None
    conn.close()
    return exists


def save_job(title, company, location, url, platform, salary=None, job_type=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(
            """INSERT OR IGNORE INTO jobs
               (title, company, location, url, platform, salary, job_type, found_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (title, company, location, url, platform, salary, job_type,
             datetime.now().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def mark_applied(url: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE jobs SET status = 'applied', applied_at = ? WHERE url = ?",
        (datetime.now().isoformat(), url),
    )
    conn.commit()
    conn.close()


def mark_failed(url: str, notes: str = ""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE jobs SET status = 'failed', notes = ? WHERE url = ?",
        (notes, url),
    )
    conn.commit()
    conn.close()


def mark_skipped(url: str, reason: str = ""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE jobs SET status = 'skipped', notes = ? WHERE url = ?",
        (reason, url),
    )
    conn.commit()
    conn.close()


def get_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status")
    stats = dict(c.fetchall())
    conn.close()
    return stats


def get_recent_jobs(limit: int = 50) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        "SELECT * FROM jobs ORDER BY found_at DESC LIMIT ?", (limit,)
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows
