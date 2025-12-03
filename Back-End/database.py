import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional

class ScanDatabase:
    def __init__(self, db_path: str = "scans.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT UNIQUE NOT NULL,
                    repo_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    total_issues INTEGER DEFAULT 0,
                    security_issues INTEGER DEFAULT 0,
                    quality_issues INTEGER DEFAULT 0,
                    issues TEXT,
                    unit_test_report TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT
                )
            """)
            conn.commit()
    
    def save_scan(self, scan_data: Dict) -> bool:
        """Save or update scan data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scans 
                    (job_id, repo_url, status, total_issues, security_issues, quality_issues, 
                     issues, unit_test_report, created_at, updated_at, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_data['job_id'],
                    scan_data['repo_url'],
                    scan_data['status'],
                    scan_data.get('total_issues', 0),
                    scan_data.get('security_issues', 0),
                    scan_data.get('quality_issues', 0),
                    json.dumps(scan_data.get('issues', [])),
                    json.dumps(scan_data.get('unit_test_report')) if scan_data.get('unit_test_report') else None,
                    scan_data['created_at'],
                    scan_data['updated_at'],
                    scan_data.get('completed_at')
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Database save error: {e}")
            return False
    
    def get_scan(self, job_id: str) -> Optional[Dict]:
        """Get scan by job_id"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("SELECT * FROM scans WHERE job_id = ?", (job_id,))
                row = cursor.fetchone()
                if row:
                    scan = dict(row)
                    scan['issues'] = json.loads(scan['issues']) if scan['issues'] else []
                    scan['unit_test_report'] = json.loads(scan['unit_test_report']) if scan['unit_test_report'] else None
                    return scan
                return None
        except Exception as e:
            print(f"Database get error: {e}")
            return None
    
    def get_all_scans(self, limit: int = 50) -> List[Dict]:
        """Get all scans with limit"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT job_id, repo_url, status, total_issues, security_issues, 
                           quality_issues, created_at, completed_at 
                    FROM scans 
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Database get_all error: {e}")
            return []
    
    def get_scan_history(self, repo_url: str) -> List[Dict]:
        """Get scan history for specific repository"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT job_id, status, total_issues, security_issues, 
                           quality_issues, created_at, completed_at 
                    FROM scans 
                    WHERE repo_url = ? 
                    ORDER BY created_at DESC
                """, (repo_url,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"Database history error: {e}")
            return []
    
    def delete_scan(self, job_id: str) -> bool:
        """Delete scan by job_id"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM scans WHERE job_id = ?", (job_id,))
                conn.commit()
                return True
        except Exception as e:
            print(f"Database delete error: {e}")
            return False