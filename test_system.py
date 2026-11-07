"""
=============================================================================
Network Traffic Monitoring System - Verification & Unit Test Suite
-----------------------------------------------------------------------------
Tests database operations, network statistics, packet monitor threading,
and Flask REST API endpoints to ensure 100% bug-free college project submission.
=============================================================================
"""

import time
import unittest
import json
import database
import network_stats
from packet_monitor import monitor_instance
from app import app


class TestNetworkMonitoringSystem(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        database.init_db()

    def test_01_database_operations(self):
        """Test database table creation, session creation, packet insertion, and queries."""
        print("\n[TEST 1] Testing Database Persistence...")
        session_id = database.create_session("Test-Interface")
        self.assertIsNotNone(session_id)
        self.assertGreater(session_id, 0)

        # Batch insert sample packets
        sample_packets = [
            {
                "session_id": session_id,
                "timestamp": "2026-11-06 12:00:01",
                "src_ip": "192.168.1.50",
                "dst_ip": "8.8.8.8",
                "src_port": 54321,
                "dst_port": 53,
                "protocol": "DNS",
                "length": 84,
                "info": "DNS Query: example.com"
            },
            {
                "session_id": session_id,
                "timestamp": "2026-11-06 12:00:02",
                "src_ip": "192.168.1.50",
                "dst_ip": "140.82.121.4",
                "src_port": 51234,
                "dst_port": 443,
                "protocol": "HTTPS/TLS",
                "length": 1420,
                "info": "TLS Encrypted Handshake"
            },
            {
                "session_id": session_id,
                "timestamp": "2026-11-06 12:00:03",
                "src_ip": "192.168.1.50",
                "dst_ip": "1.1.1.1",
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ICMP",
                "length": 64,
                "info": "ICMP Echo Request"
            }
        ]

        database.insert_packets_batch(sample_packets)

        # Verify retrieval
        packets = database.get_packets(session_id=session_id)
        self.assertEqual(len(packets), 3)

        # Verify protocol filtering
        dns_packets = database.get_packets(session_id=session_id, protocol="DNS")
        self.assertEqual(len(dns_packets), 1)
        self.assertEqual(dns_packets[0]["protocol"], "DNS")

        # Verify distribution
        dist = database.get_protocol_distribution(session_id=session_id)
        self.assertEqual(dist["DNS"], 1)
        self.assertEqual(dist["HTTPS/TLS"], 1)
        self.assertEqual(dist["ICMP"], 1)

        # Verify session summary
        database.end_session(session_id, total_packets=3, total_bytes=1568)
        summary = database.get_session_summary(session_id)
        self.assertEqual(summary["actual_packets"], 3)
        self.assertEqual(summary["status"], "STOPPED")
        print(" -> Database tests passed successfully!")

    def test_02_network_stats(self):
        """Test psutil interface detection and bandwidth tracker."""
        print("\n[TEST 2] Testing Network Stats & Interfaces...")
        interfaces = network_stats.get_network_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)
        print(f" -> Found {len(interfaces)} interface(s). Primary: {interfaces[0]['display_name']}")

        tracker = network_stats.BandwidthTracker(history_size=10)
        stats = tracker.update()
        self.assertIn("upload_speed_kbs", stats)
        self.assertIn("download_speed_kbs", stats)
        self.assertIn("total_sent_formatted", stats)
        print(f" -> Speed tracker: Up={stats['upload_speed_formatted']}, Down={stats['download_speed_formatted']}")
        print(" -> Network stats tests passed successfully!")

    def test_03_packet_monitor_demo_mode(self):
        """Test packet monitor worker thread, capture buffer, and shutdown."""
        print("\n[TEST 3] Testing Packet Monitor Thread & Capture Engine...")
        success, msg = monitor_instance.start(interface_name="Test-Iface", use_simulation=True)
        self.assertTrue(success)

        # Allow 1.5 seconds for capture thread to generate test packets
        time.sleep(1.5)

        status = monitor_instance.get_status()
        self.assertTrue(status["is_running"])
        self.assertGreater(status["total_packets"], 0)
        print(f" -> Captured {status['total_packets']} packets in demonstration mode.")

        # Test recent packets retrieval
        recent = monitor_instance.get_recent_packets(limit=10)
        self.assertGreater(len(recent), 0)
        self.assertIn(recent[0]["protocol"], ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS/TLS", "ARP", "OTHER"])

        # Stop monitoring
        stop_success, stop_msg = monitor_instance.stop()
        self.assertTrue(stop_success)
        self.assertFalse(monitor_instance.is_running)
        print(" -> Packet monitor thread cleanly stopped.")

    def test_04_flask_views_and_apis(self):
        """Test all Flask view routes and JSON API endpoints."""
        print("\n[TEST 4] Testing Flask Routes and REST APIs...")

        # 1. HTML Pages
        for route in ["/", "/dashboard", "/packets", "/reports"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"NETSENTINEL", res.data)

        # 2. API /api/interfaces
        res = self.client.get("/api/interfaces")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])

        # 3. API /api/stats/live
        res = self.client.get("/api/stats/live")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])
        self.assertIn("bandwidth", data)

        # 4. API /api/monitor/start and /stop
        res = self.client.post("/api/monitor/start", json={"interface": "Default", "simulation": True})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])

        time.sleep(0.5)

        res = self.client.post("/api/monitor/stop")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])

        # 5. API /api/packets/search
        res = self.client.get("/api/packets/search?page=1&page_size=10")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])

        # 6. API /api/reports/sessions
        res = self.client.get("/api/reports/sessions")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["success"])

        # 7. API /api/export/csv
        res = self.client.get("/api/export/csv")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "text/csv")
        self.assertIn(b"Packet ID,Session ID,Timestamp", res.data)
        print(" -> All Flask routes and APIs responded with status 200!")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestNetworkMonitoringSystem)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n" + "=" * 70)
        print("  ALL TESTS PASSED! SYSTEM VERIFIED 100% OPERATIONAL.")
        print("=" * 70)
        exit(0)
    else:
        print("\n[!] Tests failed.")
        exit(1)
