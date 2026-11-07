"""
=============================================================================
Network Traffic Monitoring System - Flask Web Application (app.py)
-----------------------------------------------------------------------------
Cybersecurity College Project
Main application controller serving dashboard views and REST APIs for
real-time packet monitoring, bandwidth statistics, filtering, and reporting.
=============================================================================
"""

import io
import csv
import time
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for

# Application modules
import database
import network_stats
from packet_monitor import monitor_instance

app = Flask(__name__)
app.config["SECRET_KEY"] = "cybersecurity-network-monitor-key-2026"

# Bandwidth tracker instance for system I/O speed measurement
bandwidth_tracker = network_stats.BandwidthTracker(history_size=30)

# Background worker for periodic bandwidth snapshots and database sync
bg_thread = None
bg_stop_event = threading.Event()


def background_bandwidth_worker():
    """
    Background worker thread that samples system network bandwidth
    every 1 second and saves periodic snapshots to database when monitoring is active.
    """
    while not bg_stop_event.is_set():
        stats = bandwidth_tracker.update()

        status = monitor_instance.get_status()
        if status["is_running"] and status["session_id"]:
            try:
                database.record_traffic_snapshot(
                    session_id=status["session_id"],
                    upload_speed=stats["upload_speed_kbs"],
                    download_speed=stats["download_speed_kbs"],
                    bytes_sent=stats["total_sent_bytes"],
                    bytes_recv=stats["total_recv_bytes"]
                )
            except Exception as e:
                print(f"[!] Error recording traffic snapshot: {e}")

        time.sleep(1.0)


# =============================================================================
# HTML Page Routes
# =============================================================================

@app.route("/")
def index():
    """Root route redirects to dashboard view."""
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/dashboard")
def dashboard():
    """Main real-time cybersecurity overview dashboard."""
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/packets")
def packets_view():
    """Detailed live packet inspection and search/filtering page."""
    return render_template("packets.html", active_page="packets")


@app.route("/reports")
def reports_view():
    """Historical session analytics and summary reports page."""
    return render_template("reports.html", active_page="reports")


# =============================================================================
# REST API Endpoints
# =============================================================================

@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    """Returns detected system network interfaces."""
    interfaces = network_stats.get_network_interfaces()
    return jsonify({
        "success": True,
        "interfaces": interfaces
    })


@app.route("/api/monitor/start", methods=["POST"])
def api_start_monitor():
    """Starts network packet monitoring on the selected interface."""
    data = request.get_json() or {}
    interface_name = data.get("interface", "Default")
    use_simulation = data.get("simulation", False)

    # Reset bandwidth tracker baseline for this session
    bandwidth_tracker.reset()

    success, message = monitor_instance.start(
        interface_name=interface_name,
        use_simulation=use_simulation
    )

    return jsonify({
        "success": success,
        "message": message,
        "status": monitor_instance.get_status()
    })


@app.route("/api/monitor/stop", methods=["POST"])
def api_stop_monitor():
    """Stops the active monitoring session."""
    success, message = monitor_instance.stop()
    return jsonify({
        "success": success,
        "message": message,
        "status": monitor_instance.get_status()
    })


@app.route("/api/monitor/status", methods=["GET"])
def api_monitor_status():
    """Returns current monitor status, total packets, and protocol distribution."""
    status = monitor_instance.get_status()
    return jsonify({
        "success": True,
        "status": status
    })


@app.route("/api/stats/live", methods=["GET"])
def api_live_stats():
    """
    Returns live bandwidth speeds, byte totals, rolling chart points,
    and cumulative protocol counts for dashboard graphs.
    """
    bw_stats = bandwidth_tracker.get_current_stats()
    chart_points = bandwidth_tracker.get_history()
    status = monitor_instance.get_status()

    return jsonify({
        "success": True,
        "bandwidth": bw_stats,
        "chart_history": chart_points,
        "monitoring": status
    })


@app.route("/api/packets/recent", methods=["GET"])
def api_recent_packets():
    """Returns recent packets from the in-memory buffer for real-time table."""
    limit = request.args.get("limit", default=50, type=int)
    limit = max(1, min(limit, 200))
    packets = monitor_instance.get_recent_packets(limit=limit)
    return jsonify({
        "success": True,
        "count": len(packets),
        "packets": packets
    })


@app.route("/api/packets/search", methods=["GET"])
def api_search_packets():
    """
    Searches and filters captured packet metadata from the SQLite database.
    Supports filtering by protocol, source IP, destination IP, ports, size, and pagination.
    """
    session_id = request.args.get("session_id", type=int)
    protocol = request.args.get("protocol", type=str)
    src_ip = request.args.get("src_ip", type=str)
    dst_ip = request.args.get("dst_ip", type=str)
    src_port = request.args.get("src_port", type=str)
    dst_port = request.args.get("dst_port", type=str)
    min_size = request.args.get("min_size", type=str)
    max_size = request.args.get("max_size", type=str)

    page = request.args.get("page", default=1, type=int)
    page_size = request.args.get("page_size", default=25, type=int)
    page_size = max(5, min(page_size, 200))
    offset = (page - 1) * page_size

    total_count = database.get_packet_count(
        session_id=session_id,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        min_size=min_size,
        max_size=max_size
    )

    packets = database.get_packets(
        session_id=session_id,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        min_size=min_size,
        max_size=max_size,
        limit=page_size,
        offset=offset
    )

    total_pages = max(1, (total_count + page_size - 1) // page_size)

    return jsonify({
        "success": True,
        "packets": packets,
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    })


@app.route("/api/traffic/clear", methods=["POST"])
def api_clear_traffic():
    """Clears in-memory buffers and SQLite database history."""
    if monitor_instance.is_running:
        monitor_instance.stop()

    database.clear_all_data()
    bandwidth_tracker.reset()

    # Reset monitor counters
    with monitor_instance.lock:
        monitor_instance.recent_packets.clear()
        monitor_instance.total_packets_captured = 0
        monitor_instance.total_bytes_captured = 0
        for k in monitor_instance.protocol_counts:
            monitor_instance.protocol_counts[k] = 0

    return jsonify({
        "success": True,
        "message": "All network traffic history and database records have been cleared."
    })


@app.route("/api/reports/sessions", methods=["GET"])
def api_reports_sessions():
    """Returns list of past monitoring sessions."""
    sessions = database.get_all_sessions()
    return jsonify({
        "success": True,
        "sessions": sessions
    })


@app.route("/api/reports/session/<int:session_id>", methods=["GET"])
def api_report_session_detail(session_id):
    """Returns detailed analytics report for a specific session."""
    summary = database.get_session_summary(session_id)
    if not summary:
        return jsonify({"success": False, "message": "Session not found."}), 404

    protocol_dist = database.get_protocol_distribution(session_id)
    top_ips = database.get_top_ips(session_id, limit=5)
    snapshots = database.get_recent_traffic_snapshots(session_id, limit=50)

    return jsonify({
        "success": True,
        "session": summary,
        "protocol_distribution": protocol_dist,
        "top_ips": top_ips,
        "snapshots": snapshots
    })


@app.route("/api/export/csv", methods=["GET"])
def api_export_csv():
    """
    Exports captured packet metadata as a downloadable CSV spreadsheet.
    Supports filtering by session_id or protocol.
    """
    session_id = request.args.get("session_id", type=int)
    protocol = request.args.get("protocol", type=str)

    packets = database.get_packets(
        session_id=session_id,
        protocol=protocol,
        limit=5000  # Cap download to 5000 rows to ensure snappy response
    )

    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV Header
    writer.writerow([
        "Packet ID",
        "Session ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Packet Size (Bytes)",
        "Info"
    ])

    for p in packets:
        writer.writerow([
            p.get("id"),
            p.get("session_id"),
            p.get("timestamp"),
            p.get("src_ip"),
            p.get("dst_ip"),
            p.get("src_port"),
            p.get("dst_port"),
            p.get("protocol"),
            p.get("length"),
            p.get("info", "")
        ])

    csv_data = output.getvalue()
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"network_packets_{timestamp_str}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# =============================================================================
# Application Startup and Initialization
# =============================================================================

def start_background_threads():
    """Initializes database and starts background bandwidth sampling thread."""
    database.init_db()
    global bg_thread
    if bg_thread is None or not bg_thread.is_alive():
        bg_thread = threading.Thread(
            target=background_bandwidth_worker,
            daemon=True,
            name="Background-Bandwidth-Worker"
        )
        bg_thread.start()


# Ensure database is created on module import
database.init_db()
start_background_threads()

if __name__ == "__main__":
    print("=" * 70)
    print("  NETWORK TRAFFIC MONITORING SYSTEM")
    print("  Cybersecurity College Project")
    print("  Server running at: http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
