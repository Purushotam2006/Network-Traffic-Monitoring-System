"""
=============================================================================
Network Traffic Monitoring System - Database Module (database.py)
-----------------------------------------------------------------------------
Cybersecurity College Project
Handles SQLite persistence for monitoring sessions, packet metadata,
and traffic statistics.
=============================================================================
"""

import sqlite3
import os
import threading
from datetime import datetime

DB_NAME = "network_monitor.db"
DB_LOCK = threading.Lock()


def get_db_path():
    """Returns the absolute path to the SQLite database file."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, DB_NAME)


def get_connection():
    """Returns a SQLite connection with row factory configured."""
    conn = sqlite3.connect(get_db_path(), timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes the SQLite database with required tables and indexes.
    Safe to call multiple times.
    """
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        # 1. Monitoring Sessions Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TEXT NOT NULL,
                end_time TEXT,
                interface TEXT NOT NULL,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                status TEXT DEFAULT 'RUNNING'
            )
        """)

        # 2. Captured Packet Metadata Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT NOT NULL,
                length INTEGER NOT NULL,
                info TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
            )
        """)

        # 3. Traffic Speed Snapshots Table (for historical graphs and reporting)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS traffic_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp TEXT NOT NULL,
                upload_speed REAL DEFAULT 0.0,
                download_speed REAL DEFAULT 0.0,
                bytes_sent INTEGER DEFAULT 0,
                bytes_recv INTEGER DEFAULT 0,
                FOREIGN KEY (session_id) REFERENCES sessions (id) ON DELETE CASCADE
            )
        """)

        # Performance Indexes for fast filtering and analytics
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")

        conn.commit()
        conn.close()


def create_session(interface="Default"):
    """Creates a new monitoring session and returns its ID."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO sessions (start_time, interface, status, total_packets, total_bytes)
            VALUES (?, ?, 'RUNNING', 0, 0)
        """, (now_str, interface))
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id


def end_session(session_id, total_packets=0, total_bytes=0):
    """Marks a monitoring session as completed with final counts."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            UPDATE sessions
            SET end_time = ?, total_packets = ?, total_bytes = ?, status = 'STOPPED'
            WHERE id = ?
        """, (now_str, total_packets, total_bytes, session_id))
        conn.commit()
        conn.close()


def insert_packets_batch(packet_list):
    """
    Inserts a list of packet dicts into the database efficiently using executemany.
    packet_list items should have:
    session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, info
    """
    if not packet_list:
        return

    tuples = []
    for p in packet_list:
        tuples.append((
            p.get("session_id"),
            p.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            p.get("src_ip", "0.0.0.0"),
            p.get("dst_ip", "0.0.0.0"),
            p.get("src_port", 0),
            p.get("dst_port", 0),
            p.get("protocol", "OTHER"),
            p.get("length", 0),
            p.get("info", "")
        ))

    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO packets (
                session_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, info
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, tuples)
        conn.commit()
        conn.close()


def record_traffic_snapshot(session_id, upload_speed, download_speed, bytes_sent, bytes_recv):
    """Records a single bandwidth snapshot for historical charts."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO traffic_snapshots (
                session_id, timestamp, upload_speed, download_speed, bytes_sent, bytes_recv
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (session_id, now_str, upload_speed, download_speed, bytes_sent, bytes_recv))
        conn.commit()
        conn.close()


def get_packets(session_id=None, protocol=None, src_ip=None, dst_ip=None,
                src_port=None, dst_port=None, min_size=None, max_size=None,
                limit=100, offset=0):
    """
    Retrieves filtered packet list from database with pagination.
    Returns list of dicts.
    """
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM packets WHERE 1=1"
        params = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if protocol and protocol.upper() != "ALL":
            query += " AND UPPER(protocol) = ?"
            params.append(protocol.upper())
        if src_ip:
            query += " AND src_ip LIKE ?"
            params.append(f"%{src_ip}%")
        if dst_ip:
            query += " AND dst_ip LIKE ?"
            params.append(f"%{dst_ip}%")
        if src_port:
            query += " AND src_port = ?"
            params.append(int(src_port))
        if dst_port:
            query += " AND dst_port = ?"
            params.append(int(dst_port))
        if min_size:
            query += " AND length >= ?"
            params.append(int(min_size))
        if max_size:
            query += " AND length <= ?"
            params.append(int(max_size))

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        results = [dict(row) for row in rows]
        conn.close()
        return results


def get_packet_count(session_id=None, protocol=None, src_ip=None, dst_ip=None,
                     src_port=None, dst_port=None, min_size=None, max_size=None):
    """Returns total matching packet count for pagination calculation."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        query = "SELECT COUNT(*) as total FROM packets WHERE 1=1"
        params = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if protocol and protocol.upper() != "ALL":
            query += " AND UPPER(protocol) = ?"
            params.append(protocol.upper())
        if src_ip:
            query += " AND src_ip LIKE ?"
            params.append(f"%{src_ip}%")
        if dst_ip:
            query += " AND dst_ip LIKE ?"
            params.append(f"%{dst_ip}%")
        if src_port:
            query += " AND src_port = ?"
            params.append(int(src_port))
        if dst_port:
            query += " AND dst_port = ?"
            params.append(int(dst_port))
        if min_size:
            query += " AND length >= ?"
            params.append(int(min_size))
        if max_size:
            query += " AND length <= ?"
            params.append(int(max_size))

        cursor.execute(query, params)
        row = cursor.fetchone()
        count = row["total"] if row else 0
        conn.close()
        return count


def get_protocol_distribution(session_id=None):
    """
    Returns a dictionary of protocol counts:
    {'TCP': count, 'UDP': count, 'ICMP': count, 'DNS': count, 'HTTP': count, 'HTTPS/TLS': count, 'OTHER': count}
    """
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        query = "SELECT protocol, COUNT(*) as count FROM packets"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " GROUP BY protocol"

        cursor.execute(query, params)
        rows = cursor.fetchall()

        dist = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "HTTP": 0,
            "HTTPS/TLS": 0,
            "OTHER": 0
        }

        for row in rows:
            proto = row["protocol"]
            count = row["count"]
            if proto in dist:
                dist[proto] = count
            else:
                dist["OTHER"] += count

        conn.close()
        return dist


def get_top_ips(session_id=None, limit=5):
    """Returns top source and destination IP addresses."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        # Top Source IPs
        src_query = "SELECT src_ip, COUNT(*) as count, SUM(length) as bytes FROM packets"
        params = []
        if session_id:
            src_query += " WHERE session_id = ?"
            params.append(session_id)
        src_query += " GROUP BY src_ip ORDER BY count DESC LIMIT ?"
        params.append(limit)

        cursor.execute(src_query, params)
        top_src = [dict(row) for row in cursor.fetchall()]

        # Top Destination IPs
        dst_query = "SELECT dst_ip, COUNT(*) as count, SUM(length) as bytes FROM packets"
        params_dst = []
        if session_id:
            dst_query += " WHERE session_id = ?"
            params_dst.append(session_id)
        dst_query += " GROUP BY dst_ip ORDER BY count DESC LIMIT ?"
        params_dst.append(limit)

        cursor.execute(dst_query, params_dst)
        top_dst = [dict(row) for row in cursor.fetchall()]

        conn.close()
        return {"top_sources": top_src, "top_destinations": top_dst}


def get_all_sessions():
    """Returns all recorded monitoring sessions."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM sessions ORDER BY id DESC")
        rows = cursor.fetchall()
        sessions = [dict(r) for r in rows]
        conn.close()
        return sessions


def get_session_summary(session_id):
    """Returns aggregate summary details for a specific session."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = cursor.fetchone()
        if not session:
            conn.close()
            return None

        summary = dict(session)

        # Total packet count and byte count from actual packets
        cursor.execute("""
            SELECT COUNT(*) as pkt_count, COALESCE(SUM(length), 0) as byte_count,
                   AVG(length) as avg_length
            FROM packets WHERE session_id = ?
        """, (session_id,))
        agg = cursor.fetchone()
        summary["actual_packets"] = agg["pkt_count"]
        summary["actual_bytes"] = agg["byte_count"]
        summary["avg_packet_size"] = round(agg["avg_length"] or 0, 2)

        conn.close()
        return summary


def get_recent_traffic_snapshots(session_id=None, limit=30):
    """Retrieves recent bandwidth snapshots for charting."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM traffic_snapshots"
        params = []
        if session_id:
            query += " WHERE session_id = ?"
            params.append(session_id)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        # Return in chronological order
        snapshots = [dict(r) for r in reversed(rows)]
        conn.close()
        return snapshots


def clear_all_data():
    """Clears all packet data, snapshots, and session history."""
    with DB_LOCK:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM traffic_snapshots")
        cursor.execute("DELETE FROM packets")
        cursor.execute("DELETE FROM sessions")
        conn.commit()
        conn.close()
