"""
Cache — SQLite-backed result storage.

Stores every scan so you can diff runs over time and not re-enumerate
a domain you already scanned.  Automatically creates the DB on first run.
"""

import sqlite3
import json
import datetime
from pathlib import Path
from typing import Optional, Dict, Any

DB_PATH = Path.home() / ".kerb-map" / "results.db"


def _default(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, datetime.timedelta):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


class Cache:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain      TEXT NOT NULL,
                    dc_ip       TEXT NOT NULL,
                    operator    TEXT,
                    timestamp   TEXT NOT NULL,
                    duration_s  REAL,
                    data        TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id     INTEGER NOT NULL,
                    category    TEXT NOT NULL,
                    target      TEXT NOT NULL,
                    attack      TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    priority    INTEGER NOT NULL,
                    reason      TEXT,
                    next_step   TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                );

                CREATE INDEX IF NOT EXISTS idx_domain   ON scans(domain);
                CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
            """)

    def save_scan(
        self,
        domain: str,
        dc_ip: str,
        operator: str,
        data: Dict[str, Any],
        targets: list,
        duration_s: float = 0.0,
    ) -> int:
        ts = datetime.datetime.now().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO scans (domain, dc_ip, operator, timestamp, duration_s, data) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (domain, dc_ip, operator, ts, duration_s,
                 json.dumps(data, default=_default)),
            )
            scan_id = cur.lastrowid
            for t in targets:
                conn.execute(
                    "INSERT INTO findings "
                    "(scan_id, category, target, attack, severity, priority, reason, next_step) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, t.get("category",""), t.get("target",""),
                     t.get("attack",""), t.get("severity",""),
                     t.get("priority",0), t.get("reason",""), t.get("next_step","")),
                )
        return scan_id

    def list_scans(self, domain: Optional[str] = None):
        q    = "SELECT id, domain, dc_ip, operator, timestamp, duration_s FROM scans"
        args = ()
        if domain:
            q   += " WHERE domain = ?"
            args = (domain,)
        q += " ORDER BY timestamp DESC"
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(q, args).fetchall()

    def get_scan(self, scan_id: int) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def get_findings(self, scan_id: int) -> list:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT category, target, attack, severity, priority, reason "
                "FROM findings WHERE scan_id = ? ORDER BY priority DESC",
                (scan_id,),
            ).fetchall()
        return [
            {"category": r[0], "target": r[1], "attack": r[2],
             "severity": r[3], "priority": r[4], "reason": r[5]}
            for r in rows
        ]
