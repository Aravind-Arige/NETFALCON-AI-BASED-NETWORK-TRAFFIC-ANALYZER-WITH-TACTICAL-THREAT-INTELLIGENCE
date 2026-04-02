import sqlite3
import os
import time
import threading
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database.db")

class HistoryDatabase:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.init_db()

    def get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def init_db(self):
        with self._lock:
            conn = self.get_conn()
            cursor = conn.cursor()
            
            # Metrics table (sampled every 10-60 secs)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    packet_count INTEGER,
                    bandwidth_in REAL,
                    bandwidth_out REAL,
                    latency REAL,
                    jitter REAL,
                    packet_loss REAL,
                    health_score REAL
                )
            """)
            
            # Threats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    alert TEXT,
                    action_taken TEXT
                )
            """)
            
            # Top talkers table (snapshots)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS top_talkers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    ip TEXT,
                    bytes INTEGER
                )
            """)
            
            conn.commit()
            conn.close()

    def log_metrics(self, data):
        with self._lock:
            try:
                conn = self.get_conn()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO metrics (timestamp, packet_count, bandwidth_in, bandwidth_out, latency, jitter, packet_loss, health_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    time.time(),
                    data.get("packet_count", 0),
                    data.get("bandwidth", 0),
                    data.get("bandwidth", 0) * 0.3, # approximation if not split
                    data.get("latency", 0),
                    data.get("jitter", 0),
                    data.get("packet_loss", 0),
                    data.get("health_score", 100)
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[DB] Error logging metrics: {e}")

    def log_threat(self, threat):
        with self._lock:
            try:
                conn = self.get_conn()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO threats (timestamp, src_ip, dst_ip, protocol, alert, action_taken)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    time.time(),
                    threat.get("src", ""),
                    threat.get("dst", ""),
                    threat.get("protocol", ""),
                    threat.get("alert", ""),
                    "mitigated" if threat.get("mitigated") else "logged"
                ))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[DB] Error logging threat: {e}")

    def log_top_talkers(self, talkers):
        if not talkers: return
        with self._lock:
            try:
                conn = self.get_conn()
                cursor = conn.cursor()
                now = time.time()
                data = [(now, t["ip"], t["bytes"]) for t in talkers]
                cursor.executemany("""
                    INSERT INTO top_talkers (timestamp, ip, bytes)
                    VALUES (?, ?, ?)
                """, data)
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[DB] Error logging talkers: {e}")

    def purge_old_data(self, days=7):
        with self._lock:
            try:
                conn = self.get_conn()
                cursor = conn.cursor()
                cutoff = time.time() - (days * 86400)
                cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))
                cursor.execute("DELETE FROM threats WHERE timestamp < ?", (cutoff,))
                cursor.execute("DELETE FROM top_talkers WHERE timestamp < ?", (cutoff,))
                conn.commit()
                conn.close()
                print(f"[DB] Purged data older than {days} days.")
            except Exception as e:
                print(f"[DB] Purge error: {e}")

    def query_history(self, start_ts, end_ts, target_ip=None):
        with self._lock:
            conn = self.get_conn()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Setup metrics base query
            metrics_query = "SELECT * FROM metrics WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp ASC"
            metrics_params = [start_ts, end_ts]
            
            cursor.execute(metrics_query, metrics_params)
            metrics = [dict(r) for r in cursor.fetchall()]
            
            # Setup threats query
            threats_query = "SELECT * FROM threats WHERE timestamp BETWEEN ? AND ?"
            threats_params = [start_ts, end_ts]
            if target_ip:
                threats_query += " AND (src_ip = ? OR dst_ip = ?)"
                threats_params.extend([target_ip, target_ip])
            threats_query += " ORDER BY timestamp ASC"
            
            cursor.execute(threats_query, threats_params)
            threats = [dict(r) for r in cursor.fetchall()]
            
            conn.close()
            return {"metrics": metrics, "threats": threats}

db = HistoryDatabase()
