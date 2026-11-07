/**
 * ==============================================================================
 * Network Traffic Monitoring System - Frontend JavaScript Engine (dashboard.js)
 * ------------------------------------------------------------------------------
 * Cybersecurity College Project
 * Handles AJAX polling, Chart.js updates, packet rendering, search/filtering,
 * session reports, and interactive control events.
 * ==============================================================================
 */

// Global State
let pollingInterval = null;
let trafficLineChart = null;
let protocolDoughnutChart = null;
let protocolBarChart = null;

let reportProtocolChart = null;
let reportBandwidthChart = null;

let isMonitoringActive = false;
let previousPacketCount = 0;
let lastStatsCheckTime = Date.now();

// Protocol color definitions matching dark cyber theme
const PROTO_COLORS = {
    "TCP": "#3b82f6",
    "UDP": "#f59e0b",
    "ICMP": "#ec4899",
    "DNS": "#06b6d4",
    "HTTP": "#eab308",
    "HTTPS/TLS": "#8b5cf6",
    "ARP": "#10b981",
    "OTHER": "#94a3b8"
};

// ==============================================================================
// DOM Initialization & Setup
// ==============================================================================

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    loadNetworkInterfaces();
    bindDashboardControls();

    // Check if we are on the dashboard page
    if (document.getElementById("trafficLineChart")) {
        initDashboardCharts();
        startStatsPolling();
    }
});

// Update cyber clock display
function initClock() {
    const clockEl = document.getElementById("cyberClock");
    if (!clockEl) return;
    const updateTime = () => {
        const now = new Date();
        clockEl.textContent = now.toTimeString().split(" ")[0];
    };
    updateTime();
    setInterval(updateTime, 1000);
}

// Show UI Toast Notifications
function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `cyber-toast toast-${type}`;

    let icon = "fa-circle-info";
    if (type === "success") icon = "fa-circle-check";
    if (type === "error") icon = "fa-triangle-exclamation";

    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ==============================================================================
// Network Interfaces Detection
// ==============================================================================

async function loadNetworkInterfaces() {
    const select = document.getElementById("interfaceSelect");
    if (!select) return;

    try {
        const res = await fetch("/api/interfaces");
        const data = await res.json();

        if (data.success && data.interfaces.length > 0) {
            select.innerHTML = "";
            data.interfaces.forEach((iface, idx) => {
                const opt = document.createElement("option");
                opt.value = iface.name;
                opt.textContent = iface.display_name;
                if (idx === 0) opt.selected = true;
                select.appendChild(opt);
            });
        } else {
            select.innerHTML = '<option value="Default">Default System Interface</option>';
        }
    } catch (err) {
        console.error("Failed to fetch interfaces:", err);
        select.innerHTML = '<option value="Default">Default System Interface</option>';
    }
}

// ==============================================================================
// Control Panel Actions (Start / Stop / Clear)
// ==============================================================================

function bindDashboardControls() {
    const btnStart = document.getElementById("btnStart");
    const btnStop = document.getElementById("btnStop");
    const btnClear = document.getElementById("btnClear");
    const simToggle = document.getElementById("simulationModeToggle");

    if (btnStart) {
        btnStart.addEventListener("click", async () => {
            const iface = document.getElementById("interfaceSelect")?.value || "Default";
            const simulation = simToggle?.checked || false;

            btnStart.disabled = true;

            try {
                const res = await fetch("/api/monitor/start", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ interface: iface, simulation: simulation })
                });
                const data = await res.json();

                if (data.success) {
                    showToast(data.message, "success");
                    updateStatusUI(true, simulation);
                } else {
                    showToast(data.message || "Could not start packet capture.", "error");
                    btnStart.disabled = false;
                }
            } catch (err) {
                showToast("Server connection error when starting capture.", "error");
                btnStart.disabled = false;
            }
        });
    }

    if (btnStop) {
        btnStop.addEventListener("click", async () => {
            btnStop.disabled = true;
            try {
                const res = await fetch("/api/monitor/stop", { method: "POST" });
                const data = await res.json();

                if (data.success) {
                    showToast(data.message, "info");
                    updateStatusUI(false);
                } else {
                    showToast(data.message || "Failed to stop capture.", "error");
                    btnStop.disabled = false;
                }
            } catch (err) {
                showToast("Server connection error when stopping capture.", "error");
                btnStop.disabled = false;
            }
        });
    }

    if (btnClear) {
        btnClear.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to clear all packet history and reset charts?")) {
                return;
            }
            try {
                const res = await fetch("/api/traffic/clear", { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, "success");
                    resetDashboardStats();
                    updateStatusUI(false);
                }
            } catch (err) {
                showToast("Failed to clear history.", "error");
            }
        });
    }
}

function updateStatusUI(isRunning, isSimMode = false) {
    isMonitoringActive = isRunning;
    const pill = document.getElementById("statusIndicator");
    const statusText = document.getElementById("statusText");
    const btnStart = document.getElementById("btnStart");
    const btnStop = document.getElementById("btnStop");

    if (pill && statusText) {
        if (isRunning) {
            pill.className = "status-pill status-active";
            statusText.textContent = isSimMode ? "MONITORING (DEMO MODE)" : "MONITORING ACTIVE";
            if (btnStart) btnStart.disabled = true;
            if (btnStop) btnStop.disabled = false;
        } else {
            pill.className = "status-pill status-stopped";
            statusText.textContent = "MONITORING IDLE";
            if (btnStart) btnStart.disabled = false;
            if (btnStop) btnStop.disabled = true;
        }
    }
}

function resetDashboardStats() {
    const elIds = [
        "statTotalPackets", "statTcpPackets", "statUdpPackets", "statIcmpPackets",
        "statUploadSpeed", "statDownloadSpeed", "statTotalSent", "statTotalRecv",
        "livePacketCount", "statPacketRate", "statTcpPercent", "statUdpPercent"
    ];
    elIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = id.includes("Speed") ? "0.00 KB/s" : (id.includes("Sent") || id.includes("Recv") ? "0 B" : "0");
    });

    const tbody = document.getElementById("livePacketsBody");
    if (tbody) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="8">
                    <div class="no-data">
                        <i class="fa-solid fa-radar fa-spin-pulse"></i>
                        <p>Packet history cleared. Click "START MONITORING" to resume capture.</p>
                    </div>
                </td>
            </tr>`;
    }

    if (trafficLineChart) {
        trafficLineChart.data.labels = [];
        trafficLineChart.data.datasets[0].data = [];
        trafficLineChart.data.datasets[1].data = [];
        trafficLineChart.update();
    }

    if (protocolDoughnutChart) {
        protocolDoughnutChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0, 0, 0];
        protocolDoughnutChart.update();
    }

    if (protocolBarChart) {
        protocolBarChart.data.datasets[0].data = [0, 0, 0, 0, 0, 0, 0, 0];
        protocolBarChart.update();
    }
}

// ==============================================================================
// Chart.js Visualizations Setup
// ==============================================================================

function initDashboardCharts() {
    // 1. Live Bandwidth Line Chart
    const lineCtx = document.getElementById("trafficLineChart")?.getContext("2d");
    if (lineCtx) {
        trafficLineChart = new Chart(lineCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Upload (KB/s)",
                        data: [],
                        borderColor: "#06b6d4",
                        backgroundColor: "rgba(6, 182, 212, 0.12)",
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true,
                        pointRadius: 2,
                        pointHoverRadius: 5
                    },
                    {
                        label: "Download (KB/s)",
                        data: [],
                        borderColor: "#10b981",
                        backgroundColor: "rgba(16, 185, 129, 0.12)",
                        borderWidth: 2,
                        tension: 0.35,
                        fill: true,
                        pointRadius: 2,
                        pointHoverRadius: 5
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 10 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: {
                            color: "#94a3b8",
                            font: { family: "JetBrains Mono", size: 10 },
                            callback: val => val + " KB/s"
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: "#f8fafc", font: { family: "Inter", size: 12 } }
                    }
                }
            }
        });
    }

    // 2. Protocol Distribution Doughnut Chart
    const doughnutCtx = document.getElementById("protocolDoughnutChart")?.getContext("2d");
    if (doughnutCtx) {
        protocolDoughnutChart = new Chart(doughnutCtx, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS/TLS", "ARP", "Other"],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        PROTO_COLORS["TCP"],
                        PROTO_COLORS["UDP"],
                        PROTO_COLORS["ICMP"],
                        PROTO_COLORS["DNS"],
                        PROTO_COLORS["HTTP"],
                        PROTO_COLORS["HTTPS/TLS"],
                        PROTO_COLORS["ARP"],
                        PROTO_COLORS["OTHER"]
                    ],
                    borderColor: "#131c31",
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "right",
                        labels: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 11 }, boxWidth: 12 }
                    }
                },
                cutout: "68%"
            }
        });
    }

    // 3. Protocol Activity Bar Chart
    const barCtx = document.getElementById("protocolBarChart")?.getContext("2d");
    if (barCtx) {
        protocolBarChart = new Chart(barCtx, {
            type: "bar",
            data: {
                labels: ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS/TLS", "ARP", "Other"],
                datasets: [{
                    label: "Packets Captured",
                    data: [0, 0, 0, 0, 0, 0, 0, 0],
                    backgroundColor: [
                        PROTO_COLORS["TCP"],
                        PROTO_COLORS["UDP"],
                        PROTO_COLORS["ICMP"],
                        PROTO_COLORS["DNS"],
                        PROTO_COLORS["HTTP"],
                        PROTO_COLORS["HTTPS/TLS"],
                        PROTO_COLORS["ARP"],
                        PROTO_COLORS["OTHER"]
                    ],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: "#94a3b8", font: { family: "Inter", size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#94a3b8", font: { family: "JetBrains Mono", size: 10 } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }
}

// ==============================================================================
// Real-Time Stats & Packet Polling
// ==============================================================================

function startStatsPolling() {
    if (pollingInterval) clearInterval(pollingInterval);

    // Initial check
    fetchDashboardData();

    // Poll every 1.5 seconds for snappy real-time updates
    pollingInterval = setInterval(fetchDashboardData, 1500);
}

async function fetchDashboardData() {
    try {
        const [statsRes, pktsRes] = await Promise.all([
            fetch("/api/stats/live"),
            fetch("/api/packets/recent?limit=50")
        ]);

        const statsData = await statsRes.json();
        const pktsData = await pktsRes.json();

        if (statsData.success) {
            updateDashboardMetrics(statsData);
        }

        if (pktsData.success) {
            renderLivePackets(pktsData.packets);
        }
    } catch (err) {
        console.warn("Polling fetch error:", err);
    }
}

function updateDashboardMetrics(data) {
    const bw = data.bandwidth;
    const mon = data.monitoring;

    // Check status notice if error
    const noticeEl = document.getElementById("systemNotice");
    const noticeText = document.getElementById("systemNoticeText");
    if (noticeEl && noticeText) {
        if (mon.error_message) {
            noticeText.textContent = mon.error_message;
            noticeEl.classList.remove("hidden");
        } else {
            noticeEl.classList.add("hidden");
        }
    }

    // Keep UI sync with monitoring state
    if (mon.is_running !== isMonitoringActive) {
        updateStatusUI(mon.is_running, mon.is_simulation_mode);
    }

    // Metric text updates
    setElementText("statTotalPackets", (mon.total_packets || 0).toLocaleString());
    setElementText("statUploadSpeed", bw.upload_speed_formatted);
    setElementText("statDownloadSpeed", bw.download_speed_formatted);
    setElementText("statTotalSent", "Sent: " + bw.total_sent_formatted);
    setElementText("statTotalRecv", "Recv: " + bw.total_recv_formatted);

    // Packet rate calculation
    const now = Date.now();
    const elapsedSec = Math.max(1, (now - lastStatsCheckTime) / 1000);
    const deltaPackets = Math.max(0, (mon.total_packets || 0) - previousPacketCount);
    const rate = Math.round(deltaPackets / elapsedSec);
    setElementText("statPacketRate", `${rate} pkts/sec`);
    previousPacketCount = mon.total_packets || 0;
    lastStatsCheckTime = now;

    // Protocol Counts
    const counts = mon.protocol_counts || {};
    const total = mon.total_packets || 0;

    const tcp = counts["TCP"] || 0;
    const udp = counts["UDP"] || 0;
    const icmp = counts["ICMP"] || 0;

    setElementText("statTcpPackets", tcp.toLocaleString());
    setElementText("statUdpPackets", udp.toLocaleString());
    setElementText("statIcmpPackets", icmp.toLocaleString());

    if (total > 0) {
        setElementText("statTcpPercent", `${Math.round((tcp / total) * 100)}% of total`);
        setElementText("statUdpPercent", `${Math.round((udp / total) * 100)}% of total`);
    }

    // Update Line Chart with Bandwidth Points
    if (trafficLineChart && data.chart_history) {
        const history = data.chart_history;
        trafficLineChart.data.labels = history.map(h => h.time);
        trafficLineChart.data.datasets[0].data = history.map(h => h.upload);
        trafficLineChart.data.datasets[1].data = history.map(h => h.download);
        trafficLineChart.update();
    }

    // Update Doughnut & Bar Charts with Protocol Counts
    const protoData = [
        counts["TCP"] || 0,
        counts["UDP"] || 0,
        counts["ICMP"] || 0,
        counts["DNS"] || 0,
        counts["HTTP"] || 0,
        counts["HTTPS/TLS"] || 0,
        counts["ARP"] || 0,
        counts["OTHER"] || 0
    ];

    if (protocolDoughnutChart) {
        protocolDoughnutChart.data.datasets[0].data = protoData;
        protocolDoughnutChart.update();
    }

    if (protocolBarChart) {
        protocolBarChart.data.datasets[0].data = protoData;
        protocolBarChart.update();
    }
}

function setElementText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

// ==============================================================================
// Live Recent Packets Stream Rendering
// ==============================================================================

function renderLivePackets(packets) {
    const tbody = document.getElementById("livePacketsBody");
    const countBadge = document.getElementById("livePacketCount");
    if (!tbody) return;

    if (!packets || packets.length === 0) {
        return;
    }

    if (countBadge) {
        countBadge.textContent = `${packets.length} Packets`;
    }

    // Build HTML rows
    const rows = packets.map(p => {
        const protoClass = getBadgeClassForProto(p.protocol);
        const timeShort = p.timestamp ? p.timestamp.split(" ")[1] || p.timestamp : "--";

        return `
            <tr>
                <td>${escapeHtml(timeShort)}</td>
                <td><span class="ip-tag">${escapeHtml(p.src_ip)}</span></td>
                <td><span class="ip-tag">${escapeHtml(p.dst_ip)}</span></td>
                <td>${p.src_port || "-"}</td>
                <td>${p.dst_port || "-"}</td>
                <td><span class="badge-proto ${protoClass}">${escapeHtml(p.protocol)}</span></td>
                <td>${p.length} B</td>
                <td title="${escapeHtml(p.info || '')}">${escapeHtml(truncate(p.info, 45))}</td>
            </tr>
        `;
    }).join("");

    tbody.innerHTML = rows;

    // Auto-scroll handler
    const autoScroll = document.getElementById("autoScrollToggle");
    const container = document.getElementById("tableContainer");
    if (autoScroll && autoScroll.checked && container) {
        // Keeps user at top of newest packets
        container.scrollTop = 0;
    }
}

function getBadgeClassForProto(proto) {
    if (!proto) return "badge-other";
    const upper = proto.toUpperCase();
    if (upper.includes("HTTPS") || upper.includes("TLS")) return "badge-https";
    if (upper === "TCP") return "badge-tcp";
    if (upper === "UDP") return "badge-udp";
    if (upper === "ICMP") return "badge-icmp";
    if (upper === "DNS") return "badge-dns";
    if (upper === "HTTP") return "badge-http";
    if (upper === "ARP") return "badge-arp";
    return "badge-other";
}

function truncate(str, len) {
    if (!str) return "";
    return str.length > len ? str.substring(0, len) + "..." : str;
}

// ==============================================================================
// Dedicated Packet Inspection & Search Filtering (packets.html)
// ==============================================================================

let currentPacketsPage = 1;
let totalPacketsPages = 1;

function initPacketsPage() {
    const form = document.getElementById("packetFilterForm");
    const btnReset = document.getElementById("btnResetFilters");
    const btnPrev = document.getElementById("btnPrevPage");
    const btnNext = document.getElementById("btnNextPage");
    const btnExport = document.getElementById("btnExportFilteredCsv");

    if (form) {
        form.addEventListener("submit", (e) => {
            e.preventDefault();
            currentPacketsPage = 1;
            loadFilteredPackets();
        });
    }

    if (btnReset) {
        btnReset.addEventListener("click", () => {
            if (form) form.reset();
            currentPacketsPage = 1;
            loadFilteredPackets();
        });
    }

    if (btnPrev) {
        btnPrev.addEventListener("click", () => {
            if (currentPacketsPage > 1) {
                currentPacketsPage--;
                loadFilteredPackets();
            }
        });
    }

    if (btnNext) {
        btnNext.addEventListener("click", () => {
            if (currentPacketsPage < totalPacketsPages) {
                currentPacketsPage++;
                loadFilteredPackets();
            }
        });
    }

    if (btnExport) {
        btnExport.addEventListener("click", () => {
            const proto = document.getElementById("filterProtocol")?.value || "ALL";
            let exportUrl = `/api/export/csv?protocol=${encodeURIComponent(proto)}`;
            window.location.href = exportUrl;
        });
    }

    // Initial load
    loadFilteredPackets();
}

async function loadFilteredPackets() {
    const tbody = document.getElementById("filteredPacketsBody");
    const summary = document.getElementById("resultsSummary");
    const pageBadge = document.getElementById("currentPageBadge");
    const pageInfo = document.getElementById("paginationInfo");
    const btnPrev = document.getElementById("btnPrevPage");
    const btnNext = document.getElementById("btnNextPage");

    const proto = document.getElementById("filterProtocol")?.value || "";
    const srcIp = document.getElementById("filterSrcIp")?.value || "";
    const dstIp = document.getElementById("filterDstIp")?.value || "";
    const srcPort = document.getElementById("filterSrcPort")?.value || "";
    const dstPort = document.getElementById("filterDstPort")?.value || "";
    const minSize = document.getElementById("filterMinSize")?.value || "";
    const maxSize = document.getElementById("filterMaxSize")?.value || "";
    const pageSize = document.getElementById("filterPageSize")?.value || "25";

    const params = new URLSearchParams({
        protocol: proto,
        src_ip: srcIp,
        dst_ip: dstIp,
        src_port: srcPort,
        dst_port: dstPort,
        min_size: minSize,
        max_size: maxSize,
        page: currentPacketsPage,
        page_size: pageSize
    });

    try {
        const res = await fetch(`/api/packets/search?${params.toString()}`);
        const data = await res.json();

        if (data.success) {
            totalPacketsPages = data.total_pages;

            if (summary) summary.textContent = `Found ${data.total.toLocaleString()} matching packets`;
            if (pageBadge) pageBadge.textContent = data.page;
            if (pageInfo) pageInfo.textContent = `Page ${data.page} of ${data.total_pages}`;

            if (btnPrev) btnPrev.disabled = data.page <= 1;
            if (btnNext) btnNext.disabled = data.page >= data.total_pages;

            if (!data.packets || data.packets.length === 0) {
                tbody.innerHTML = `
                    <tr class="empty-row">
                        <td colspan="9">
                            <div class="no-data">
                                <i class="fa-solid fa-magnifying-glass"></i>
                                <p>No packets found matching current criteria.</p>
                            </div>
                        </td>
                    </tr>`;
                return;
            }

            tbody.innerHTML = data.packets.map(p => {
                const protoClass = getBadgeClassForProto(p.protocol);
                return `
                    <tr>
                        <td>#${p.id}</td>
                        <td>${escapeHtml(p.timestamp)}</td>
                        <td>${escapeHtml(p.src_ip)}</td>
                        <td>${escapeHtml(p.dst_ip)}</td>
                        <td>${p.src_port || "-"}</td>
                        <td>${p.dst_port || "-"}</td>
                        <td><span class="badge-proto ${protoClass}">${escapeHtml(p.protocol)}</span></td>
                        <td>${p.length} B</td>
                        <td title="${escapeHtml(p.info || '')}">${escapeHtml(truncate(p.info, 50))}</td>
                    </tr>
                `;
            }).join("");
        }
    } catch (err) {
        console.error("Error loading filtered packets:", err);
    }
}

// ==============================================================================
// Session Reports & Historical Analytics (reports.html)
// ==============================================================================

async function initReportsPage() {
    const sessionSelect = document.getElementById("sessionSelect");
    const btnLoad = document.getElementById("btnLoadReport");
    const btnDownload = document.getElementById("btnDownloadSessionCsv");

    try {
        const res = await fetch("/api/reports/sessions");
        const data = await res.json();

        if (data.success && data.sessions.length > 0) {
            sessionSelect.innerHTML = data.sessions.map(s => `
                <option value="${s.id}">
                    Session #${s.id} - ${s.start_time} (${s.interface}) - [${s.total_packets} pkts]
                </option>
            `).join("");
        } else {
            sessionSelect.innerHTML = '<option value="">No recorded monitoring sessions found.</option>';
        }
    } catch (err) {
        console.error("Error loading sessions:", err);
    }

    if (btnLoad) {
        btnLoad.addEventListener("click", () => {
            const sid = sessionSelect?.value;
            if (sid) loadSessionReport(sid);
            else showToast("Please select a session first.", "error");
        });
    }

    if (btnDownload) {
        btnDownload.addEventListener("click", () => {
            const sid = sessionSelect?.value;
            if (sid) {
                window.location.href = `/api/export/csv?session_id=${sid}`;
            } else {
                showToast("Please select a session first.", "error");
            }
        });
    }
}

async function loadSessionReport(sessionId) {
    try {
        const res = await fetch(`/api/reports/session/${sessionId}`);
        const data = await res.json();

        if (!data.success) {
            showToast(data.message || "Could not load report.", "error");
            return;
        }

        // Show details area, hide empty state
        document.getElementById("reportDetailsArea")?.classList.remove("hidden");
        document.getElementById("noSessionSelected")?.classList.add("hidden");

        const s = data.session;
        setElementText("repSessionId", `#${s.id}`);
        setElementText("repStatus", s.status);
        setElementText("repTotalPackets", (s.actual_packets || s.total_packets || 0).toLocaleString());
        setElementText("repAvgPacketSize", `Avg Size: ${s.avg_packet_size || 0} B`);
        setElementText("repStartTime", s.start_time || "--");
        setElementText("repInterface", `Interface: ${s.interface}`);
        setElementText("repEndTime", s.end_time || "Running / Interrupted");
        setElementText("repTotalBytes", `Data: ${formatBytesJs(s.actual_bytes || s.total_bytes || 0)}`);

        // Render Protocol Chart for this session
        renderSessionProtocolChart(data.protocol_distribution);

        // Render Bandwidth History Chart for this session
        renderSessionBandwidthChart(data.snapshots);

        // Render Top Source and Destination IPs
        renderTopIpsTable("topSourceIpsBody", data.top_ips.top_sources);
        renderTopIpsTable("topDestIpsBody", data.top_ips.top_destinations);

        showToast(`Loaded analytics for Session #${sessionId}`, "success");
    } catch (err) {
        console.error("Error loading session report:", err);
        showToast("Error retrieving session report.", "error");
    }
}

function renderSessionProtocolChart(dist) {
    const ctx = document.getElementById("reportProtocolChart")?.getContext("2d");
    if (!ctx) return;

    if (reportProtocolChart) {
        reportProtocolChart.destroy();
    }

    const labels = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS/TLS", "OTHER"];
    const values = labels.map(l => dist[l] || 0);

    reportProtocolChart = new Chart(ctx, {
        type: "pie",
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: labels.map(l => PROTO_COLORS[l] || "#94a3b8"),
                borderColor: "#131c31",
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "right", labels: { color: "#94a3b8", font: { family: "JetBrains Mono" } } }
            }
        }
    });
}

function renderSessionBandwidthChart(snapshots) {
    const ctx = document.getElementById("reportBandwidthChart")?.getContext("2d");
    if (!ctx) return;

    if (reportBandwidthChart) {
        reportBandwidthChart.destroy();
    }

    const labels = (snapshots || []).map(s => s.timestamp ? s.timestamp.split(" ")[1] || s.timestamp : "");
    const uploadSpeeds = (snapshots || []).map(s => s.upload_speed || 0);
    const downloadSpeeds = (snapshots || []).map(s => s.download_speed || 0);

    reportBandwidthChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [
                {
                    label: "Upload Speed (KB/s)",
                    data: uploadSpeeds,
                    borderColor: "#06b6d4",
                    backgroundColor: "rgba(6, 182, 212, 0.1)",
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: "Download Speed (KB/s)",
                    data: downloadSpeeds,
                    borderColor: "#10b981",
                    backgroundColor: "rgba(16, 185, 129, 0.1)",
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: "#94a3b8", font: { size: 10 } } },
                y: { beginAtZero: true, ticks: { color: "#94a3b8" } }
            },
            plugins: {
                legend: { labels: { color: "#f8fafc" } }
            }
        }
    });
}

function renderTopIpsTable(tbodyId, list) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;

    if (!list || list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No records found.</td></tr>';
        return;
    }

    tbody.innerHTML = list.map(item => `
        <tr>
            <td><strong>${escapeHtml(item.src_ip || item.dst_ip)}</strong></td>
            <td>${item.count.toLocaleString()} pkts</td>
            <td>${formatBytesJs(item.bytes || 0)}</td>
        </tr>
    `).join("");
}

function formatBytesJs(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}
