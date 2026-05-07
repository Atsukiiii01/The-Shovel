import sqlite3
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="shovel_recon.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                first_seen DATETIME,
                last_scan DATETIME
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                category TEXT,
                query_text TEXT,
                found_at DATETIME,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
        ''')
        self.conn.commit()

    def upsert_target(self, domain):
        """Adds target or updates last scan time. Returns the target ID."""
        cursor = self.conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
            INSERT INTO targets (domain, first_seen, last_scan)
            VALUES (?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET last_scan = excluded.last_scan
        ''', (domain, now, now))
        self.conn.commit()
        
        cursor.execute('SELECT id FROM targets WHERE domain = ?', (domain,))
        return cursor.fetchone()[0]