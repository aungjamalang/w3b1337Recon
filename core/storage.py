"""SQLite + JSON storage layer with checkpoint support."""

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


class Storage:
    """Unified storage layer combining SQLite and JSON file storage."""

    def __init__(self, db_path: str = "data/recon.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with required tables."""
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT UNIQUE,
                platform TEXT NOT NULL,
                severity TEXT,
                bounty_amount REAL DEFAULT 0,
                researcher TEXT,
                disclosed_date TEXT,
                created_at TEXT NOT NULL,
                raw_data TEXT
            );

            CREATE TABLE IF NOT EXISTS payloads (
                id TEXT PRIMARY KEY,
                report_id TEXT,
                category TEXT NOT NULL,
                value TEXT NOT NULL,
                payload_type TEXT,
                bypass INTEGER DEFAULT 0,
                tags TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS parameters (
                id TEXT PRIMARY KEY,
                report_id TEXT,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                context TEXT,
                frequency INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY (report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS patterns (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                source_report_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (source_report_id) REFERENCES reports(id)
            );

            CREATE TABLE IF NOT EXISTS checkpoints (
                id TEXT PRIMARY KEY,
                collector_name TEXT NOT NULL,
                last_page INTEGER DEFAULT 0,
                last_id TEXT,
                total_collected INTEGER DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_reports_category ON reports(category);
            CREATE INDEX IF NOT EXISTS idx_reports_platform ON reports(platform);
            CREATE INDEX IF NOT EXISTS idx_reports_severity ON reports(severity);
            CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
            CREATE INDEX IF NOT EXISTS idx_parameters_category ON parameters(category);
            CREATE INDEX IF NOT EXISTS idx_patterns_category ON patterns(category);
        """)
        self._conn.commit()

    # --- Report Operations ---

    def add_report(self, report: Dict[str, Any]) -> str:
        """Add a report to the database."""
        report_id = report.get("id", str(uuid.uuid4()))
        now = datetime.utcnow().isoformat()

        self._conn.execute(
            """INSERT OR REPLACE INTO reports 
            (id, category, title, url, platform, severity, bounty_amount, researcher, disclosed_date, created_at, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report_id,
                report.get("category", "unknown"),
                report.get("title", "Untitled"),
                report.get("url"),
                report.get("platform", "unknown"),
                report.get("severity"),
                report.get("bounty_amount", 0),
                report.get("researcher"),
                report.get("disclosed_date"),
                now,
                json.dumps(report),
            ),
        )
        self._conn.commit()
        return report_id

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a report by ID."""
        row = self._conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row:
            return dict(row)
        return None

    def search_reports(
        self,
        category: Optional[str] = None,
        platform: Optional[str] = None,
        severity: Optional[str] = None,
        keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Search reports with filters."""
        query = "SELECT * FROM reports WHERE 1=1"
        params = []

        if category:
            query += " AND LOWER(category) = LOWER(?)"
            params.append(category)
        if platform:
            query += " AND LOWER(platform) = LOWER(?)"
            params.append(platform)
        if severity:
            query += " AND LOWER(severity) = LOWER(?)"
            params.append(severity)
        if keyword:
            query += " AND (LOWER(title) LIKE LOWER(?) OR LOWER(raw_data) LIKE LOWER(?))"
            params.extend([f"%{keyword}%", f"%{keyword}%"])

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_report_count(self, category: Optional[str] = None) -> int:
        """Get total report count."""
        if category:
            row = self._conn.execute(
                "SELECT COUNT(*) as cnt FROM reports WHERE LOWER(category) = LOWER(?)",
                (category,),
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) as cnt FROM reports").fetchone()
        return row["cnt"] if row else 0

    # --- Payload Operations ---

    def add_payload(self, payload: Dict[str, Any]) -> str:
        """Add a payload to the database."""
        payload_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        tags = json.dumps(payload.get("tags", []))

        self._conn.execute(
            """INSERT INTO payloads (id, report_id, category, value, payload_type, bypass, tags, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                payload_id,
                payload.get("report_id"),
                payload.get("category", "unknown"),
                payload["value"],
                payload.get("type"),
                1 if payload.get("bypass") else 0,
                tags,
                now,
            ),
        )
        self._conn.commit()
        return payload_id

    def get_payloads(self, category: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Get payloads, optionally filtered by category."""
        if category:
            rows = self._conn.execute(
                "SELECT * FROM payloads WHERE LOWER(category) = LOWER(?) LIMIT ?",
                (category, limit),
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM payloads LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    # --- Parameter Operations ---

    def add_parameter(self, param: Dict[str, Any]) -> str:
        """Add a parameter to the database."""
        param_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        self._conn.execute(
            """INSERT INTO parameters (id, report_id, category, name, context, frequency, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                param_id,
                param.get("report_id"),
                param.get("category", "unknown"),
                param["name"],
                param.get("context"),
                param.get("frequency", 1),
                now,
            ),
        )
        self._conn.commit()
        return param_id

    def get_top_parameters(self, category: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Get most frequently attacked parameters."""
        query = """SELECT name, category, SUM(frequency) as total_freq, COUNT(*) as report_count
                   FROM parameters"""
        params = []

        if category:
            query += " WHERE LOWER(category) = LOWER(?)"
            params.append(category)

        query += " GROUP BY name, category ORDER BY total_freq DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # --- Pattern Operations ---

    def add_pattern(self, pattern: Dict[str, Any]) -> str:
        """Add a pattern to the database."""
        pattern_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        self._conn.execute(
            """INSERT INTO patterns (id, category, pattern_type, value, description, source_report_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                pattern_id,
                pattern.get("category", "unknown"),
                pattern.get("pattern_type", "generic"),
                pattern["value"],
                pattern.get("description"),
                pattern.get("source_report_id"),
                now,
            ),
        )
        self._conn.commit()
        return pattern_id

    def get_patterns(self, category: Optional[str] = None, pattern_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get patterns with optional filtering."""
        query = "SELECT * FROM patterns WHERE 1=1"
        params = []

        if category:
            query += " AND LOWER(category) = LOWER(?)"
            params.append(category)
        if pattern_type:
            query += " AND pattern_type = ?"
            params.append(pattern_type)

        rows = self._conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    # --- Checkpoint Operations ---

    def save_checkpoint(self, collector_name: str, page: int, last_id: Optional[str] = None, total: int = 0):
        """Save collection progress checkpoint."""
        now = datetime.utcnow().isoformat()
        self._conn.execute(
            """INSERT OR REPLACE INTO checkpoints (id, collector_name, last_page, last_id, total_collected, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (collector_name, collector_name, page, last_id, total, now),
        )
        self._conn.commit()

    def get_checkpoint(self, collector_name: str) -> Optional[Dict[str, Any]]:
        """Get checkpoint for a collector."""
        row = self._conn.execute(
            "SELECT * FROM checkpoints WHERE collector_name = ?", (collector_name,)
        ).fetchone()
        return dict(row) if row else None

    # --- JSON File Operations ---

    @staticmethod
    def save_json(data: Any, filepath: str):
        """Save data to JSON file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    @staticmethod
    def load_json(filepath: str) -> Any:
        """Load data from JSON file."""
        path = Path(filepath)
        if path.exists():
            with open(path, "r") as f:
                return json.load(f)
        return None

    # --- Statistics ---

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        stats = {}
        stats["total_reports"] = self.get_report_count()
        stats["total_payloads"] = self._conn.execute("SELECT COUNT(*) as cnt FROM payloads").fetchone()["cnt"]
        stats["total_parameters"] = self._conn.execute("SELECT COUNT(*) as cnt FROM parameters").fetchone()["cnt"]
        stats["total_patterns"] = self._conn.execute("SELECT COUNT(*) as cnt FROM patterns").fetchone()["cnt"]

        # Category breakdown
        rows = self._conn.execute(
            "SELECT category, COUNT(*) as cnt FROM reports GROUP BY category ORDER BY cnt DESC"
        ).fetchall()
        stats["reports_by_category"] = {row["category"]: row["cnt"] for row in rows}

        # Platform breakdown
        rows = self._conn.execute(
            "SELECT platform, COUNT(*) as cnt FROM reports GROUP BY platform ORDER BY cnt DESC"
        ).fetchall()
        stats["reports_by_platform"] = {row["platform"]: row["cnt"] for row in rows}

        return stats

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        self.close()
