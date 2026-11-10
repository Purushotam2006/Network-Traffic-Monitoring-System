"""
=============================================================================
Network Traffic Monitoring System - Network Statistics Module (network_stats.py)
-----------------------------------------------------------------------------
Cybersecurity College Project
Collects system network interface details, computes upload/download speeds,
and tracks cumulative data sent/received using psutil.
=============================================================================
"""

import time
import socket
import collections
import threading

try:
    import psutil
except ImportError:
    psutil = None


# ---- Application-level HTTP counters (fallback when psutil sees no real NIC) ----
_http_lock = threading.Lock()
_http_bytes_sent = 0
_http_bytes_recv = 0


def add_http_bytes(sent=0, recv=0):
    """Called from Flask hooks to count request/response bytes."""
    global _http_bytes_sent, _http_bytes_recv
    with _http_lock:
        _http_bytes_sent += int(sent)
        _http_bytes_recv += int(recv)


def _read_http_counters():
    with _http_lock:
        return _http_bytes_sent, _http_bytes_recv


def _psutil_unreliable():
    """True on cloud containers (e.g. Render) where psutil sees only loopback/empty counters."""
    if psutil is None:
        return True
    try:
        total = 0
        found_real_nic = False
        for name, c in psutil.net_io_counters(pernic=True).items():
            if name.lower().startswith(("lo", "loopback")):
                continue
            found_real_nic = True
            total += c.bytes_sent + c.bytes_recv
        return (not found_real_nic) or total < 1000000
    except Exception:
        return True


def format_bytes(num_bytes):
    """
    Converts a raw byte count into human-readable representation:
    B, KB, MB, GB, TB
    """
    if num_bytes is None:
        return "0 B"
    num = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num) < 1024.0:
            return f"{num:3.2f} {unit}"
        num /= 1024.0
    return f"{num:.2f} PB"


def format_speed(speed_kbs):
    """
    Converts a speed in KB/s into human-readable representation:
    KB/s, MB/s, GB/s
    """
    if speed_kbs is None or speed_kbs < 0:
        return "0.00 KB/s"
    if speed_kbs >= 1024.0:
        mb_speed = speed_kbs / 1024.0
        return f"{mb_speed:3.2f} MB/s"
    return f"{speed_kbs:3.2f} KB/s"


def get_network_interfaces():
    """
    Detects and returns all available network interfaces on the host machine.
    Returns a list of dicts containing name, IPv4, MAC, status, and description.
    """
    interfaces = []

    if psutil is None:
        # Fallback dummy interface if psutil is not yet installed
        return [{
            "name": "Default Interface",
            "display_name": "Default Network Interface (Auto)",
            "ipv4": "127.0.0.1",
            "mac": "00:00:00:00:00:00",
            "is_up": True,
            "speed": 0
        }]

    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            ipv4_addr = None
            mac_addr = None
            netmask = None

            for addr in addr_list:
                # AF_INET is IPv4
                if addr.family == socket.AF_INET:
                    ipv4_addr = addr.address
                    netmask = addr.netmask
                # AF_LINK on Unix or -1 on Windows is MAC
                elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                    mac_addr = addr.address
                elif addr.family == -1 or (hasattr(socket, "AF_PACKET") and addr.family == socket.AF_PACKET):
                    mac_addr = addr.address

            stat = stats.get(name)
            is_up = stat.isup if stat else False
            speed_mb = stat.speed if stat else 0

            # Friendly label
            ip_display = ipv4_addr if ipv4_addr else "No IPv4"
            status_display = "Active" if is_up else "Inactive"
            display_name = f"{name} ({ip_display}) - [{status_display}]"

            interfaces.append({
                "name": name,
                "display_name": display_name,
                "ipv4": ipv4_addr or "N/A",
                "netmask": netmask or "N/A",
                "mac": mac_addr or "N/A",
                "is_up": is_up,
                "speed": speed_mb
            })

    except Exception as e:
        print(f"[!] Error detecting network interfaces: {e}")

    # If no interfaces detected, add a default fallback
    if not interfaces:
        interfaces.append({
            "name": "All Interfaces",
            "display_name": "All Interfaces (Default)",
            "ipv4": "127.0.0.1",
            "mac": "N/A",
            "is_up": True,
            "speed": 0
        })

    # Sort so active interfaces with IPv4 appear first
    interfaces.sort(key=lambda x: (x["is_up"], x["ipv4"] != "N/A"), reverse=True)
    return interfaces


class BandwidthTracker:
    """
    Tracks network bandwidth in real-time.
    Calculates upload speed, download speed, and cumulative data transferred.
    Maintains a rolling window of recent speed points for Chart.js graphing.
    """

    def __init__(self, history_size=40):
        self.history_size = history_size
        self.lock = threading.Lock()

        self.last_check_time = time.time()
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0

        self.upload_speed_kbs = 0.0
        self.download_speed_kbs = 0.0
        self.total_sent = 0
        self.total_recv = 0

        # Rolling history of data points for live line charts:
        # [{ 'time': '12:05:01', 'upload': 15.2, 'download': 42.1 }, ...]
        self.history = collections.deque(maxlen=history_size)

        self.source = "psutil"

        # Baseline initialization
        self._initialize_counters()

    def _initialize_counters(self):
        """Captures initial baseline byte counters."""
        self.source = "http" if _psutil_unreliable() else "psutil"
        try:
            sent, recv = self._read_counters()
            self.last_bytes_sent = sent
            self.last_bytes_recv = recv
            self.total_sent = sent
            self.total_recv = recv
        except Exception:
            pass
        self.last_check_time = time.time()

    def _read_counters(self, per_nic_name=None):
        """Returns (bytes_sent, bytes_recv) from the active source."""
        if self.source == "http":
            return _read_http_counters()
        if per_nic_name and per_nic_name in psutil.net_io_counters(pernic=True):
            io = psutil.net_io_counters(pernic=True)[per_nic_name]
        else:
            io = psutil.net_io_counters(pernic=False)
        return io.bytes_sent, io.bytes_recv

    def update(self, per_nic_name=None):
        """
        Calculates instantaneous speeds since the last update call.
        Returns a dictionary of current statistics.
        """
        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_check_time

            # Ensure minimum interval of 0.2 seconds to avoid division by near-zero
            if elapsed < 0.2:
                return self.get_current_stats()

            curr_sent = self.last_bytes_sent
            curr_recv = self.last_bytes_recv

            try:
                curr_sent, curr_recv = self._read_counters(per_nic_name)
            except Exception:
                pass

            delta_sent = max(0, curr_sent - self.last_bytes_sent)
            delta_recv = max(0, curr_recv - self.last_bytes_recv)

            # Speed in Kilobytes per second (KB/s)
            self.upload_speed_kbs = round((delta_sent / 1024.0) / elapsed, 2)
            self.download_speed_kbs = round((delta_recv / 1024.0) / elapsed, 2)

            self.total_sent = curr_sent
            self.total_recv = curr_recv

            self.last_bytes_sent = curr_sent
            self.last_bytes_recv = curr_recv
            self.last_check_time = current_time

            # Append to rolling history
            time_label = time.strftime("%H:%M:%S", time.localtime(current_time))
            self.history.append({
                "time": time_label,
                "upload": self.upload_speed_kbs,
                "download": self.download_speed_kbs
            })

            return self.get_current_stats()

    def get_current_stats(self):
        """Returns the current network snapshot formatted for frontend consumption."""
        return {
            "upload_speed_kbs": self.upload_speed_kbs,
            "download_speed_kbs": self.download_speed_kbs,
            "upload_speed_formatted": format_speed(self.upload_speed_kbs),
            "download_speed_formatted": format_speed(self.download_speed_kbs),
            "total_sent_bytes": self.total_sent,
            "total_recv_bytes": self.total_recv,
            "total_sent_formatted": format_bytes(self.total_sent),
            "total_recv_formatted": format_bytes(self.total_recv)
        }

    def get_history(self):
        """Returns the rolling history of upload and download points."""
        with self.lock:
            return list(self.history)

    def reset(self):
        """Resets the rolling history and counter baseline."""
        with self.lock:
            self.history.clear()
            self._initialize_counters()
            self.upload_speed_kbs = 0.0
            self.download_speed_kbs = 0.0
