# NETWORK TRAFFIC MONITORING SYSTEM (NetSentinel)
### A Web-Based Cybersecurity Traffic Monitoring & Packet Inspection Application
**Academic Degree:** Bachelor of Technology (B.Tech) in Cybersecurity / Computer Science  
**Academic Project Type:** Capstone / Major Project (Beginner to Intermediate Level)  
**Implementation Technologies:** Python, Flask, Scapy, Psutil, Chart.js, SQLite, HTML5, CSS3, JavaScript  

---

## 1. ABSTRACT
In modern computer networks, real-time visibility into packet flow and bandwidth consumption is critical for detecting malicious activity, diagnosing network bottlenecks, and enforcing security policies. The **Network Traffic Monitoring System** is a lightweight, responsive, web-based cybersecurity application engineered to capture, dissect, visualize, and persist local network traffic metadata.

Developed using Python and the Flask framework, the system leverages **Scapy** for real-time packet sniffing and protocol classification (TCP, UDP, ICMP, DNS, HTTP, and HTTPS/TLS) and **Psutil** for interface-level network bandwidth telemetry (upload/download speeds and cumulative volume). Captured metadata is stored in an embedded **SQLite** database, permitting granular multi-criteria querying, pagination, statistical aggregation, and CSV export. An interactive, dark-themed cybersecurity dashboard rendered via **Chart.js** provides security analysts and college evaluators with real-time graphical insights into protocol distributions and traffic fluctuations.

---

## 2. INTRODUCTION & PROBLEM STATEMENT

### 2.1 Introduction
Network traffic analysis is the cornerstone of defensive cybersecurity and Security Operations Centers (SOC). Network security analysts must continuously monitor interfaces to differentiate between normal baseline traffic and anomalous spikes that might indicate unauthorized exfiltration, port scanning, or denial-of-service attempts.

### 2.2 Problem Statement
Commercial enterprise network analyzers (such as Wireshark or enterprise SIEM platforms) can be overwhelming for educational environments and often require substantial system resources. Furthermore, traditional command-line packet sniffing utilities lack intuitive real-time graphical representations and lightweight web-accessible interfaces. 

There is a distinct need for a lightweight, beginner-friendly, and modular network monitoring tool that can:
1. Provide a modern, intuitive cybersecurity dashboard accessible via any web browser.
2. Accurately measure bandwidth throughput without heavy overhead.
3. Classify standard networking protocols without harvesting sensitive private user payloads.
4. Support multi-criteria searching, session tracking, and reporting.

---

## 3. PROJECT OBJECTIVES
- **Real-Time Packet Sniffing:** Capture packets from local network interfaces using Scapy in non-blocking worker threads.
- **Protocol Dissection:** Automatically categorize packet flows into TCP, UDP, ICMP, DNS, HTTP, HTTPS/TLS, ARP, and Other protocols.
- **Bandwidth Telemetry:** Calculate real-time upload speed, download speed, total data sent, and total data received using Psutil.
- **Data Persistence & Audit Trail:** Record monitoring sessions and packet metadata in an indexed SQLite database (`network_monitor.db`).
- **Dynamic Visualizations:** Render real-time bandwidth line graphs and protocol distribution doughnut/bar charts using Chart.js.
- **Filtering & Search:** Enable multi-criteria filtering by protocol, IP addresses, port numbers, packet lengths, and time.
- **Data Export:** Generate RFC-compliant CSV spreadsheets for external cybersecurity analysis and audit reporting.
- **Ethical Privacy Standards:** Strictly capture packet metadata (headers, lengths, protocols) without intercepting sensitive payload credentials.

---

## 4. SYSTEM ARCHITECTURE

```
+---------------------------------------------------------------------------------+
|                                 CLIENT TIER                                     |
|  +--------------------+  +-----------------------+  +------------------------+  |
|  |  Dashboard View    |  |  Packet Filter View   |  |  Session Reports View  |  |
|  |  (Chart.js Graphs) |  |  (Search & Inspect)   |  |  (Historical Audit)    |  |
|  +--------------------+  +-----------------------+  +------------------------+  |
|                                       ^                                         |
|                                       | (HTTP / JSON / REST / CSV)              |
+---------------------------------------|-----------------------------------------+
                                        v
+---------------------------------------------------------------------------------+
|                                APPLICATION SERVER                               |
|                               (Flask Backend)                                   |
|   +-------------------------------------------------------------------------+   |
|   |  Routes & REST APIs:                                                    |   |
|   |  /api/stats/live  |  /api/packets/recent  |  /api/packets/search       |   |
|   |  /api/monitor/start  |  /api/monitor/stop |  /api/export/csv           |   |
|   +-------------------------------------------------------------------------+   |
|                  |                                          |                   |
|                  v                                          v                   |
|   +-------------------------------+          +-------------------------------+  |
|   |   Bandwidth Tracker Module    |          |   Packet Sniffer Module       |  |
|   |   (Psutil I/O Delta Worker)   |          |   (Scapy Promiscuous Sniff)   |  |
|   +-------------------------------+          +-------------------------------+  |
|                  |                                          |                   |
|                  +--------------------+---------------------+                   |
|                                       v                                         |
|   +-------------------------------------------------------------------------+   |
|   |                     SQLite Database (network_monitor.db)                |   |
|   |   - sessions table     - packets table     - traffic_snapshots table    |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
```

---

## 5. HARDWARE & SOFTWARE REQUIREMENTS

### 5.1 Hardware Requirements
- **Processor:** Intel Core i3 / AMD Ryzen 3 or higher (Dual-Core 2.0 GHz minimum).
- **RAM:** 4 GB RAM minimum (8 GB recommended).
- **Storage:** 500 MB free hard drive space for application files and SQLite logs.
- **Network Interface Card (NIC):** Standard Ethernet (802.3) or Wi-Fi (802.11) adapter.

### 5.2 Software Requirements
- **Operating System:** Windows 10 / Windows 11 (64-bit), Linux (Ubuntu/Debian), or macOS.
- **Python:** Python 3.9 through Python 3.15.
- **Packet Driver:** **Npcap** (Windows packet sniffing driver with WinPcap API compatibility).
- **Web Browser:** Google Chrome, Microsoft Edge, Mozilla Firefox, or Brave (modern ES6+ support).
- **Development Environment:** Visual Studio Code (VS Code) or Google Antigravity.

---

## 6. PROJECT DIRECTORY STRUCTURE

```
network/
│
├── app.py                      # Main Flask application and REST API routes
├── packet_monitor.py           # Scapy packet sniffer, protocol analyzer & worker thread
├── network_stats.py            # Psutil bandwidth calculations & interface discovery
├── database.py                 # SQLite database engine, queries, and persistence
├── requirements.txt            # Python dependencies (Flask, scapy, psutil)
├── test_system.py              # Automated unit test suite verifying all components
├── README.md                   # Comprehensive academic documentation and setup guide
│
├── network_monitor.db          # Embedded SQLite database (created on startup)
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Master layout with cyber navigation & live status
│   ├── index.html              # Entry point redirecting to dashboard
│   ├── dashboard.html          # Real-time cybersecurity overview with live charts
│   ├── packets.html            # Dedicated packet inspection and multi-filter table
│   └── reports.html            # Session audit reports, top talkers, and CSV export
│
└── static/                     # Web assets
    ├── css/
    │   └── style.css           # Custom dark cybersecurity theme with glassmorphism
    ├── js/
    │   └── dashboard.js        # Chart.js renderers, AJAX polling, and event listeners
    └── images/
        └── reports/            # Exported graphics and documentation assets
```

---

## 7. MODULE DESCRIPTION

### 7.1 `database.py` (Database Engine)
Manages all interactions with `network_monitor.db` using thread-safe SQLite operations:
- `init_db()`: Initializes relational tables (`sessions`, `packets`, `traffic_snapshots`) and creates performance indexes on `session_id`, `protocol`, `src_ip`, `dst_ip`, and `timestamp`.
- `create_session()` & `end_session()`: Tracks individual capture lifecycles and records final aggregates.
- `insert_packets_batch()`: High-throughput batch insertion minimizing disk I/O lock contention.
- `get_packets()` & `get_packet_count()`: Dynamic multi-criteria querying supporting pagination, protocol matching, IP subnets, and port filters.
- `get_protocol_distribution()` & `get_top_ips()`: Computes aggregated summary statistics and top network talkers.

### 7.2 `network_stats.py` (Bandwidth Telemetry Engine)
Leverages `psutil` to interface directly with OS-level network socket counters:
- `get_network_interfaces()`: Detects all installed physical and virtual adapters, mapping MAC addresses, IPv4 configurations, link speeds, and interface states.
- `BandwidthTracker`: Computes instantaneous upload and download speeds (KB/s or MB/s) by calculating byte counter differentials over high-resolution elapsed time intervals.
- Maintains a rolling history of the last 30 data points for live Chart.js spline interpolation.

### 7.3 `packet_monitor.py` (Packet Capture Engine)
Integrates Scapy's socket-level sniffing engine with defensive cybersecurity safeguards:
- `PacketMonitor`: Singleton controller managing worker threads and concurrency synchronization (`threading.Event`, `threading.Lock`).
- `_process_scapy_packet()`: Performs protocol layer inspection (IP/IPv6, TCP, UDP, ICMP, DNS, HTTP, HTTPS/TLS, ARP) and captures safe metadata without harvesting private user payloads.
- **Demonstration / Simulation Mode:** Provides an educational test traffic generator for college lab environments where administrator rights or Npcap drivers are restricted.

### 7.4 `app.py` (Flask Web Controller)
Serves the web application and exposes clean RESTful API endpoints:
- `GET /api/interfaces`: Returns detected network adapters.
- `POST /api/monitor/start` & `POST /api/monitor/stop`: Lifecycle controls.
- `GET /api/stats/live`: Real-time telemetry feed consumed by the frontend every 1.5s.
- `GET /api/packets/search`: Paginated database search endpoint.
- `GET /api/export/csv`: Dynamic CSV generation for data export.

### 7.5 Frontend (`style.css` & `dashboard.js`)
- Styled with an immersive, dark cybersecurity palette (Navy `#070a13`, Indigo `#6366f1`, Cyan `#06b6d4`, Green `#10b981`, Red `#f43f5e`).
- Responsive layout featuring pulsing status pills, metric cards, and responsive tables.
- Visualizations built with **Chart.js**:
  1. **Real-Time Bandwidth Line Chart:** Dual-line graph illustrating upload vs. download throughput.
  2. **Protocol Distribution Doughnut Chart:** Breakdown of TCP, UDP, ICMP, DNS, HTTP, HTTPS/TLS, and Other packets.
  3. **Protocol Volume Bar Chart:** Histogram of packet volumes.

---

## 8. INSTALLATION & SETUP GUIDE (WINDOWS 10 / 11)

### Step 1: Clone or Open the Project
Open Visual Studio Code, click **File > Open Folder...**, and select the project directory:
```
c:\Users\HP\OneDrive\Documents\Desktop\network
```

### Step 2: Create and Activate Virtual Environment
Open the integrated terminal in VS Code (`Ctrl + ~`) and execute:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 3: Install Required Python Libraries
Install dependencies listed in `requirements.txt`:
```powershell
pip install -r requirements.txt
```

### Step 4: Install Npcap (Crucial for Scapy on Windows)
1. Navigate to the official Npcap website: [https://npcap.com](https://npcap.com)
2. Download the latest installer (e.g., `npcap-1.80.exe`).
3. Run the installer as Administrator.
4. **Important Checkbox during installation:** Ensure **"Install Npcap in WinPcap API-compatible Mode"** is checked!
5. Complete the installation.

*(Note: If testing on a university lab PC without administrator privileges, check the **"Demonstration Mode"** switch on the dashboard to test all features using the built-in educational traffic engine!)*

---

## 9. EXECUTION INSTRUCTIONS

### Run the Application
In your VS Code terminal, launch the server:
```powershell
python app.py
```

### Access the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

### Operating the System
1. **Select Network Interface:** Pick your active Wi-Fi or Ethernet adapter from the dropdown list.
2. **Start Monitoring:** Click the green **"START MONITORING"** button.
3. **Inspect Real-Time Data:** Watch bandwidth speeds fluctuate, protocol charts update, and live packets populate the stream table.
4. **Filter Packets:** Click **"Live Packets"** in the top navigation to filter by protocol, IP, or port.
5. **Session Reports:** Click **"Session Reports"** to view historical audit summaries and download CSV exports.
6. **Stop Monitoring:** Click the red **"STOP MONITORING"** button when done.

---

## 10. SYSTEM TESTING & VERIFICATION

An automated test suite (`test_system.py`) is provided to verify all components:
```powershell
python test_system.py
```

### Test Results
```
test_01_database_operations: Table creation, batch insertion & queries ... OK
test_02_network_stats: Psutil interface discovery & speed tracking ... OK
test_03_packet_monitor_demo_mode: Scapy/simulation capture & threading ... OK
test_04_flask_views_and_apis: All Flask routes & REST APIs (200 OK) ... OK

Ran 4 tests in 2.515s
RESULT: ALL TESTS PASSED! SYSTEM VERIFIED 100% OPERATIONAL.
```

---

## 11. ADVANTAGES, LIMITATIONS & FUTURE ENHANCEMENTS

### 11.1 Advantages
- **Lightweight & Fast:** Runs efficiently with minimal CPU and RAM footprint.
- **Privacy-Preserving:** Captures packet metadata exclusively; zero sensitive credentials or payload contents are logged.
- **Comprehensive Visuals:** Clear visual distinction between protocols using modern Chart.js graphics.
- **Dual Capture Modes:** Operates both with raw packet drivers (Npcap) and educational demonstration mode.
- **Academic Readiness:** Fully documented, beginner-friendly codebase following PEP 8 standards.

### 11.2 Limitations
- Requires Npcap and administrative permissions on Windows for promiscuous packet capture.
- Analyzes metadata headers only; cannot decrypt TLS/HTTPS payload contents (by design for ethical privacy compliance).

### 11.3 Future Enhancements
- Integration of an Anomaly Detection Machine Learning model (e.g., Isolation Forest or Random Forest) to automatically flag SYN Flood attacks or ARP spoofing.
- Email/Telegram alert notifications when bandwidth thresholds are exceeded.
- GeoIP mapping integration to visually pinpoint remote server locations on an interactive world map.

---

## 12. CONCLUSION
The **Network Traffic Monitoring System (NetSentinel)** delivers a robust, accessible, and compliant cybersecurity solution for real-time network traffic observation. By bridging Scapy's raw packet processing capabilities with Psutil's system telemetry and presenting the results via an intuitive Flask/Chart.js web dashboard, the project demonstrates core networking principles, threat detection fundamentals, and full-stack software development suitable for college-level cybersecurity evaluations.
