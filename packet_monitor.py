"""
=============================================================================
Network Traffic Monitoring System - Packet Monitor Module (packet_monitor.py)
-----------------------------------------------------------------------------
Cybersecurity College Project
Captures and analyzes live network packets using Scapy. Extracts packet
metadata (IPs, Ports, Protocols, Sizes) and safely stores records into SQLite.
Includes graceful Windows Npcap error handling and educational test traffic mode.
=============================================================================
"""

import time
import threading
import collections
import random
from datetime import datetime

# Database module integration
import database

# Optional Scapy imports with error handling
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketMonitor:
    """
    Manages live packet capture threads, protocol classification,
    in-memory recent packet buffers, and database persistence.
    """

    def __init__(self, buffer_size=150):
        self.buffer_size = buffer_size
        self.lock = threading.Lock()

        # Threading controls
        self.is_running = False
        self.stop_event = threading.Event()
        self.capture_thread = None
        self.db_flush_thread = None

        # State tracking
        self.current_session_id = None
        self.active_interface = "Default"
        self.total_packets_captured = 0
        self.total_bytes_captured = 0
        self.error_message = None
        self.is_simulation_mode = False

        # Live in-memory buffer of recent packets for real-time frontend streaming
        self.recent_packets = collections.deque(maxlen=buffer_size)

        # Queue of packets pending insertion into SQLite
        self.pending_db_packets = []
        self.db_queue_lock = threading.Lock()

        # Protocol counts cache for quick dashboard stats
        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "HTTP": 0,
            "HTTPS/TLS": 0,
            "ARP": 0,
            "OTHER": 0
        }

    def get_status(self):
        """Returns the current monitoring status dictionary."""
        with self.lock:
            return {
                "is_running": self.is_running,
                "active_interface": self.active_interface,
                "session_id": self.current_session_id,
                "total_packets": self.total_packets_captured,
                "total_bytes": self.total_bytes_captured,
                "protocol_counts": dict(self.protocol_counts),
                "error_message": self.error_message,
                "is_simulation_mode": self.is_simulation_mode,
                "scapy_available": SCAPY_AVAILABLE
            }

    def start(self, interface_name=None, use_simulation=False):
        """
        Starts the packet monitoring worker thread.
        Prevents multiple simultaneous monitoring threads.
        """
        with self.lock:
            if self.is_running:
                return False, "Monitoring is already running."

            self.error_message = None
            self.stop_event.clear()
            self.active_interface = interface_name or "Default"
            self.total_packets_captured = 0
            self.total_bytes_captured = 0
            self.recent_packets.clear()
            self.is_simulation_mode = use_simulation

            # Reset protocol counts
            for k in self.protocol_counts:
                self.protocol_counts[k] = 0

            # Create a new session in SQLite
            try:
                self.current_session_id = database.create_session(self.active_interface)
            except Exception as e:
                self.error_message = f"Database error: {str(e)}"
                return False, self.error_message

            self.is_running = True

        # Start the background SQLite batch flusher thread
        self.db_flush_thread = threading.Thread(
            target=self._db_flusher_worker,
            daemon=True,
            name="DB-Flusher-Thread"
        )
        self.db_flush_thread.start()

        # Decide whether to run Scapy sniffing or simulation mode
        if use_simulation or not SCAPY_AVAILABLE:
            self.is_simulation_mode = True
            self.capture_thread = threading.Thread(
                target=self._simulation_capture_worker,
                daemon=True,
                name="Simulation-Capture-Thread"
            )
            self.capture_thread.start()
            return True, f"Monitoring started in educational demonstration mode on {self.active_interface}."

        # Real Scapy Capture Worker
        self.capture_thread = threading.Thread(
            target=self._scapy_capture_worker,
            args=(interface_name,),
            daemon=True,
            name="Scapy-Capture-Thread"
        )
        self.capture_thread.start()
        return True, f"Live Scapy packet monitoring started on {self.active_interface}."

    def stop(self):
        """
        Stops the active monitoring session and flushes pending data to database.
        """
        with self.lock:
            if not self.is_running:
                return False, "Monitoring is not currently active."

            self.is_running = False
            self.stop_event.set()

        # Wait for capture thread to wind down gracefully (timeout 2.0s)
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)

        # Flush remaining pending packets into database
        self._flush_pending_packets()

        # Close session in SQLite
        if self.current_session_id:
            try:
                database.end_session(
                    self.current_session_id,
                    self.total_packets_captured,
                    self.total_bytes_captured
                )
            except Exception as e:
                print(f"[!] Error ending session in DB: {e}")

        return True, "Packet monitoring stopped successfully."

    def _scapy_capture_worker(self, interface_name):
        """
        Worker thread executing Scapy's sniff loop.
        Catches Windows Npcap / permission exceptions and handles fallback.
        """
        scapy_iface = None

        # Resolve interface if specified and not Default
        if interface_name and interface_name not in ["Default", "All Interfaces", "Default Interface"]:
            scapy_iface = interface_name

        def packet_handler(pkt):
            if self.stop_event.is_set():
                return
            self._process_scapy_packet(pkt)

        def stop_check(pkt):
            return self.stop_event.is_set()

        try:
            # Execute scapy sniff with stop_filter
            # store=False prevents Scapy from accumulating packets in RAM
            sniff(
                iface=scapy_iface,
                prn=packet_handler,
                stop_filter=stop_check,
                store=False
            )
        except Exception as e:
            err_str = str(e)
            print(f"[!] Scapy capture error: {err_str}")
            with self.lock:
                self.error_message = (
                    f"Scapy capture error: {err_str}. "
                    "On Windows, Npcap must be installed (https://npcap.com) "
                    "and the app should be run with Administrator privileges. "
                    "You can switch to Demonstration Mode to test without Npcap."
                )
                self.is_running = False

    def _process_scapy_packet(self, pkt):
        """
        Extracts packet metadata without inspecting private payloads.
        Classifies protocol, captures IPs, ports, size, and timestamp.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pkt_len = len(pkt)

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        info = ""

        # Check IP layer
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        elif ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            protocol = "ARP"
            op = "Request" if pkt[ARP].op == 1 else "Reply"
            info = f"ARP {op}: Who has {dst_ip}? Tell {src_ip}"

        # Protocol Identification
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].underlayer.sprintf("%TCP.flags%") if hasattr(pkt[TCP], 'underlayer') else ""

            # Check for HTTP (Port 80, 8080 or signature)
            if src_port in [80, 8080] or dst_port in [80, 8080]:
                protocol = "HTTP"
                info = f"HTTP Traffic [{src_port} -> {dst_port}]"
            # Check for HTTPS / TLS (Port 443)
            elif src_port == 443 or dst_port == 443:
                protocol = "HTTPS/TLS"
                info = f"Encrypted TLS Handshake/Traffic [{src_port} -> {dst_port}]"
            elif src_port == 53 or dst_port == 53:
                protocol = "DNS"
                info = f"DNS over TCP [{src_port} -> {dst_port}]"
            else:
                protocol = "TCP"
                info = f"TCP Flags: [{flags}] Seq={pkt[TCP].seq}"

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            # Check for DNS (Port 53)
            if src_port == 53 or dst_port == 53 or DNS in pkt:
                protocol = "DNS"
                if DNS in pkt and pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore') if hasattr(pkt[DNS].qd.qname, 'decode') else str(pkt[DNS].qd.qname)
                    info = f"DNS Query: {qname}"
                else:
                    info = f"DNS Traffic [{src_port} -> {dst_port}]"
            elif src_port == 443 or dst_port == 443:
                protocol = "HTTPS/TLS"
                info = f"QUIC / HTTP3 Traffic [{src_port} -> {dst_port}]"
            else:
                protocol = "UDP"
                info = f"UDP Datagram [{src_port} -> {dst_port}]"

        elif ICMP in pkt:
            protocol = "ICMP"
            icmp_type = pkt[ICMP].type
            type_name = "Echo Request" if icmp_type == 8 else ("Echo Reply" if icmp_type == 0 else f"Type {icmp_type}")
            info = f"ICMP {type_name}"

        # Record packet
        self._record_packet({
            "session_id": self.current_session_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": pkt_len,
            "info": info[:120]  # Safe summary string
        })

    def _record_packet(self, pkt_dict):
        """Updates in-memory buffer, counters, and queues packet for DB insertion."""
        with self.lock:
            self.total_packets_captured += 1
            self.total_bytes_captured += pkt_dict["length"]

            proto = pkt_dict["protocol"]
            if proto in self.protocol_counts:
                self.protocol_counts[proto] += 1
            else:
                self.protocol_counts["OTHER"] += 1

            self.recent_packets.appendleft(pkt_dict)

        with self.db_queue_lock:
            self.pending_db_packets.append(pkt_dict)

    def _db_flusher_worker(self):
        """
        Background worker that flushes accumulated packets to SQLite in batches.
        Prevents SQLite locking and maintains smooth frontend performance.
        """
        while self.is_running or len(self.pending_db_packets) > 0:
            time.sleep(1.0)
            self._flush_pending_packets()

    def _flush_pending_packets(self):
        """Performs batch insert into database."""
        to_insert = []
        with self.db_queue_lock:
            if self.pending_db_packets:
                to_insert = list(self.pending_db_packets)
                self.pending_db_packets.clear()

        if to_insert:
            try:
                database.insert_packets_batch(to_insert)
            except Exception as e:
                print(f"[!] Error inserting packet batch: {e}")

    def get_recent_packets(self, limit=50):
        """Returns the most recent packets captured from memory buffer."""
        with self.lock:
            return list(self.recent_packets)[:limit]

    def _simulation_capture_worker(self):
        """
        Educational demonstration mode:
        Generates realistic local network packet traffic (TCP, UDP, DNS, HTTPS, ICMP)
        without requiring Npcap drivers or Administrator privileges.
        Perfect for college demonstrations and testing on lab computers.
        """
        sample_domains = [
            "google.com", "github.com", "cloudflare.com", "college.edu",
            "microsoft.com", "amazon.com", "python.org", "wikipedia.org"
        ]
        sample_ips = [
            "192.168.1.105", "192.168.1.1", "142.250.190.46", "140.82.121.4",
            "1.1.1.1", "8.8.8.8", "104.16.132.229", "151.101.1.140"
        ]

        while not self.stop_event.is_set():
            # Random delay between simulated packets (20ms - 200ms)
            time.sleep(random.uniform(0.05, 0.25))

            if self.stop_event.is_set():
                break

            choice = random.choices(
                ["HTTPS/TLS", "TCP", "DNS", "UDP", "HTTP", "ICMP", "ARP"],
                weights=[40, 25, 15, 10, 5, 3, 2]
            )[0]

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = random.choice(["192.168.1.105", "192.168.1.42"])
            dst_ip = random.choice(sample_ips)
            pkt_len = random.randint(64, 1500)
            src_port = random.randint(49152, 65535)

            if choice == "HTTPS/TLS":
                dst_port = 443
                info = f"Encrypted TLSv1.3 Application Data [{src_port} -> 443]"
            elif choice == "TCP":
                dst_port = random.choice([80, 443, 8080, 22, 3306])
                flags = random.choice(["ACK", "SYN, ACK", "PSH, ACK"])
                info = f"TCP Flags: [{flags}] Seq={random.randint(10000, 99999)}"
            elif choice == "DNS":
                dst_port = 53
                dst_ip = random.choice(["1.1.1.1", "8.8.8.8"])
                domain = random.choice(sample_domains)
                info = f"DNS Standard Query A: {domain}"
                pkt_len = random.randint(70, 180)
            elif choice == "HTTP":
                dst_port = 80
                info = f"HTTP/1.1 GET /index.html [{src_port} -> 80]"
            elif choice == "ICMP":
                src_port = 0
                dst_port = 0
                info = "ICMP Echo (ping) Request id=0x0001 seq=1"
                pkt_len = 64
            elif choice == "ARP":
                src_port = 0
                dst_port = 0
                info = f"ARP Request: Who has {dst_ip}? Tell {src_ip}"
                pkt_len = 42
            else:
                dst_port = random.randint(1024, 9999)
                info = f"UDP Datagram [{src_port} -> {dst_port}]"

            self._record_packet({
                "session_id": self.current_session_id,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": choice,
                "length": pkt_len,
                "info": info
            })


# Global singleton instance for application lifetime
monitor_instance = PacketMonitor()
