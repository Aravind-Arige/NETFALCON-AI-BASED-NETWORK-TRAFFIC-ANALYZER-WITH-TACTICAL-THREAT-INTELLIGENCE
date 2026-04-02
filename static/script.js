const socket = io();
let packetChart, bandwidthChart;

// background animation removed as requested



document.addEventListener("DOMContentLoaded", () => {
    loadInterfaces();
    initChart();
    initHealthGauge();
    checkRunningOnLoad();
});


function initChart() {
    const isLight = () => document.body.classList.contains('light-mode');

    const config = (label, color) => ({
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: label,
                data: [],
                borderColor: color,
                backgroundColor: color.replace('1)', '0.1)'),
                borderWidth: 2,
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { intersect: false },
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: isLight() ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: isLight() ? '#666' : '#8b949e' }
                }
            },
            plugins: {
                legend: { labels: { color: isLight() ? '#333' : '#fff' } }
            }
        }
    });

    packetChart = new Chart(document.getElementById('trafficChart'), config('Packets / sec', '#00e5ff'));
    bandwidthChart = new Chart(document.getElementById('bandwidthChart'), config('Bandwidth (KB/s)', '#7c4dff'));

    // Re-initialize charts when theme changes
    window.addEventListener('themeChanged', () => {
        const light = isLight();
        [packetChart, bandwidthChart].forEach(chart => {
            chart.options.scales.y.grid.color = light ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.05)';
            chart.options.scales.y.ticks.color = light ? '#666' : '#8b949e';
            chart.options.plugins.legend.labels.color = light ? '#333' : '#fff';
            chart.update();
        });
        // Re-render gauge with updated theme colors
        const lastScore = window._lastHealthScore !== undefined ? window._lastHealthScore : 100;
        updateHealthGauge(lastScore);
    });
}

// ---- Network Health Gauge ----
function getHealthLabel(score) {
    if (score > 70) return { text: 'Healthy', color: '#00e5ff' };
    if (score > 40) return { text: 'Degraded', color: '#ffb703' };
    return { text: 'Critical', color: '#ff5252' };
}

function initHealthGauge() {
    const gaugeDiv = document.getElementById('healthGauge');
    if (!gaugeDiv) return;
    updateHealthGauge(100);
}

function updateHealthGauge(score) {
    const gaugeDiv = document.getElementById('healthGauge');
    if (!gaugeDiv) return;

    window._lastHealthScore = score;
    const isLight = document.body.classList.contains('light-mode');
    const label = getHealthLabel(score);
    const barColor = score > 70 ? '#00e5ff' : score > 40 ? '#ffb703' : '#ff5252';
    const paperBg = isLight ? 'rgba(255,255,255,0)' : 'rgba(0,0,0,0)';
    const fontColor = isLight ? '#1a1c22' : '#eff2f5';

    const traceData = [{
        type: 'indicator',
        mode: 'gauge+number+delta',
        value: score,
        number: {
            suffix: '%',
            font: { size: 36, color: barColor, family: 'Inter, sans-serif' }
        },
        delta: {
            reference: 100,
            decreasing: { color: '#ff5252' },
            increasing: { color: '#00e5ff' },
            font: { size: 13 }
        },
        title: {
            text: `Network Health<br><span style="font-size:0.85em; color:${label.color}; font-weight:700;">${label.text}</span>`,
            font: { size: 14, color: fontColor, family: 'Inter, sans-serif' }
        },
        gauge: {
            axis: {
                range: [0, 100],
                tickwidth: 1,
                tickcolor: isLight ? 'rgba(0,0,0,0.2)' : 'rgba(255,255,255,0.2)',
                tickfont: { color: fontColor, size: 10 }
            },
            bar: { color: barColor, thickness: 0.25 },
            bgcolor: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)',
            borderwidth: 1,
            bordercolor: isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)',
            steps: [
                { range: [0, 40], color: isLight ? 'rgba(255,82,82,0.12)' : 'rgba(255,82,82,0.18)' },
                { range: [40, 70], color: isLight ? 'rgba(255,183,3,0.12)' : 'rgba(255,183,3,0.18)' },
                { range: [70, 100], color: isLight ? 'rgba(0,229,255,0.10)' : 'rgba(0,229,255,0.14)' }
            ],
            threshold: {
                line: { color: barColor, width: 3 },
                thickness: 0.75,
                value: score
            }
        }
    }];

    const layout = {
        margin: { t: 60, b: 20, l: 30, r: 30 },
        paper_bgcolor: paperBg,
        plot_bgcolor: paperBg,
        font: { color: fontColor, family: 'Inter, sans-serif' },
        height: 230
    };

    Plotly.react(gaugeDiv, traceData, layout, { displayModeBar: false, responsive: true });
}

function updateChart(stats) {
    if (!packetChart || !bandwidthChart) return;

    const now = new Date().toLocaleTimeString();

    // Update Packet Chart
    packetChart.data.labels.push(now);
    packetChart.data.datasets[0].data.push(stats.packet_rate || 0);

    // Update Bandwidth Chart
    bandwidthChart.data.labels.push(now);
    bandwidthChart.data.datasets[0].data.push(stats.bandwidth || 0);

    // Keep last 60 points
    if (packetChart.data.labels.length > 60) {
        packetChart.data.labels.shift();
        packetChart.data.datasets[0].data.shift();
        bandwidthChart.data.labels.shift();
        bandwidthChart.data.datasets[0].data.shift();
    }

    packetChart.update();
    bandwidthChart.update();
}


function loadInterfaces() {
    const refreshBtn = document.querySelector(".refresh-btn");
    if (refreshBtn) refreshBtn.classList.add("spinning");

    fetch('/interfaces')
        .then(r => r.json())
        .then(list => {
            const select = document.getElementById("interfaceSelect");
            if (!select) return;

            // Sort: Recommended first, then activity
            list.sort((a, b) => {
                if (a.is_recommended) return -1;
                if (b.is_recommended) return 1;
                return b.flow - a.flow;
            });

            const currentValue = select.value;
            select.innerHTML = '<option value="auto">Auto-detect Interface</option>';

            const modalGrid = document.getElementById("modalInterfaceGrid");
            if (modalGrid) modalGrid.innerHTML = "";

            list.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface.name;

                let statusInfo = iface.is_connected ? "✅ Connected" : "❌ Disconnected";
                let label = iface.name;

                if (iface.is_recommended) {
                    label = `⭐ ${label} (Recommended - ${statusInfo})`;
                } else {
                    label = `${label} (${statusInfo})`;
                }

                opt.text = label;
                if (iface.is_recommended && currentValue === "auto") opt.selected = true;
                select.appendChild(opt);

                // Populate Modal Grid
                if (modalGrid) {
                    const card = document.createElement("div");
                    card.className = `interface-card ${iface.is_recommended ? 'active' : ''}`;
                    if (iface.is_recommended) card.classList.add('recommended');

                    card.onclick = () => selectInterface(iface.name);

                    card.innerHTML = `
                        <div class="header-row">
                            <h4 class="name" style="margin:0;">${iface.name}</h4>
                            ${iface.is_recommended ? '<span class="badge">Recommended</span>' : ''}
                        </div>
                        <span class="desc" style="font-size:0.8rem; margin: 8px 0; display:block;">${iface.description}</span>
                        <div class="status-row">
                            <span class="activity-label" style="font-size: 0.75rem; color: var(--text-dim);">${iface.is_connected ? '🟢 Connected' : '⚪ Disconnected'}</span>
                            <div class="wave-container" style="${iface.is_connected ? 'visibility:visible' : 'visibility:hidden'}">
                                <div class="wave"></div>
                                <div class="wave"></div>
                                <div class="wave"></div>
                            </div>
                        </div>
                    `;
                    modalGrid.appendChild(card);
                }
            });

            // Restore selection if it still exists
            if (currentValue !== "auto") select.value = currentValue;
        })
        .catch(err => console.error("Error loading interfaces:", err))
        .finally(() => {
            if (refreshBtn) {
                setTimeout(() => refreshBtn.classList.remove("spinning"), 600);
            }
        });
}

function selectInterface(name) {
    const select = document.getElementById("interfaceSelect");
    if (select) {
        select.value = name;
        toggleInterfaceModal();
        // Optional: Start analyzer automatically if user wants?
        // But better to just set it.
    }
}

function toggleThreatModal() {
    const modal = document.getElementById("threatModal");
    if (modal) modal.style.display = modal.style.display === "none" ? "flex" : "none";
}

function toggleInterfaceModal() {
    const modal = document.getElementById("interfaceModal");
    if (modal) {
        modal.style.display = modal.style.display === "none" ? "flex" : "none";
        if (modal.style.display === "flex") {
            // Reset to "all" mode when opening normally
            modal.setAttribute("data-mode", "all");
            const interfaceSection = document.getElementById("interfaceSelectionSection");
            const modalTitle = document.getElementById("modalTitle");
            if (interfaceSection) interfaceSection.style.display = "block";
            if (modalTitle) modalTitle.innerText = "🌐 Network Interfaces & Active Flows";
        }
    }
}

function toggleFlowsOnlyModal() {
    const modal = document.getElementById("interfaceModal");
    if (modal) {
        modal.style.display = modal.style.display === "none" ? "flex" : "none";
        if (modal.style.display === "flex") {
            // Set to "flows-only" mode
            modal.setAttribute("data-mode", "flows-only");
            const interfaceSection = document.getElementById("interfaceSelectionSection");
            const connectedInterfaceInfo = document.getElementById("connectedInterfaceInfo");
            const modalTitle = document.getElementById("modalTitle");
            const connectedInterfaceName = document.getElementById("connectedInterfaceName");

            if (interfaceSection) interfaceSection.style.display = "none";
            if (connectedInterfaceInfo) connectedInterfaceInfo.style.display = "block";
            if (modalTitle) modalTitle.innerText = "📊 Active Flows - Connected Interface";

            // Update with current interface
            if (connectedInterfaceName && window.currentStats && window.currentStats.current_interface) {
                connectedInterfaceName.innerText = window.currentStats.current_interface || "Not connected";
            }
        }
    }
}

function viewThreatDetails(index) {
    const threat = window.currentThreats[index];
    if (!threat || !threat.metadata) return;

    const m = threat.metadata;
    document.getElementById("modalThreatTitle").innerText = (threat.mitigated ? "✅ " : "⚠️ ") + (m.title || threat.alert);
    document.getElementById("modalThreatType").innerText = m.type || "Unknown";
    document.getElementById("modalThreatOrigin").innerText = threat.src;
    document.getElementById("modalThreatTarget").innerText = threat.dst;
    document.getElementById("modalThreatTime").innerText = threat.timestamp + (threat.mitigated ? " [MITIGATED]" : " [ACTIVE]");

    document.getElementById("modalThreatCause").innerText = m.cause || "No cause specified.";
    document.getElementById("modalThreatRisk").innerText = m.risk || "General network compromise.";

    // Handle mitigation - can be string or object with summary and steps
    const mitigationSummaryEl = document.getElementById("modalThreatMitigationSummary");
    const mitigationStepsEl = document.getElementById("modalThreatMitigationSteps");
    if (typeof m.mitigation === 'object' && m.mitigation.summary) {
        mitigationSummaryEl.innerText = m.mitigation.summary;
        if (m.mitigation.steps && m.mitigation.steps.length > 0) {
            mitigationStepsEl.innerHTML = m.mitigation.steps.map(step => `<li>${step}</li>`).join('');
            mitigationStepsEl.style.display = 'block';
        } else {
            mitigationStepsEl.style.display = 'none';
        }
    } else {
        // Fallback for string mitigation
        mitigationSummaryEl.innerText = m.mitigation || "Investigate source device traffic.";
        mitigationStepsEl.style.display = 'none';
    }

    // Add mitigation status indicator
    const existingStatusPanel = document.getElementById("mitigationStatusPanel");
    if (existingStatusPanel) existingStatusPanel.remove();

    const statusPanel = document.createElement("div");
    statusPanel.id = "mitigationStatusPanel";
    statusPanel.className = "threat-info-block";
    if (threat.mitigated) {
        statusPanel.style.border = "1px solid rgba(0, 229, 0, 0.4)";
        statusPanel.style.background = "rgba(0, 229, 0, 0.07)";
        statusPanel.innerHTML = `<div style="color: #0f0; font-weight: bold;">✅ Threat Mitigated</div>
            <p style="font-size: 0.9em; margin: 8px 0 0 0;">This threat was automatically blocked by the firewall.</p>`;
    } else {
        statusPanel.style.border = "1px solid rgba(255, 82, 82, 0.4)";
        statusPanel.style.background = "rgba(255, 82, 82, 0.07)";
        statusPanel.innerHTML = `<div style="color: #ff5252; font-weight: bold;">🔴 Threat Active</div>
            <p style="font-size: 0.9em; margin: 8px 0 0 0;">This threat is currently being monitored.</p>`;
    }

    // Insert before the direct mitigation panel
    const modal = document.querySelector(".threat-detail-content");
    if (modal) {
        const mitigationSection = modal.querySelector(".threat-info-block.success-block");
        if (mitigationSection && mitigationSection.parentNode) {
            mitigationSection.parentNode.insertBefore(statusPanel, mitigationSection);
        } else {
            modal.appendChild(statusPanel);
        }
    }

    // Add direct mitigation if available and not already mitigated
    const existingMitigationPanel = document.getElementById("directMitigationPanel");
    if (existingMitigationPanel) existingMitigationPanel.remove();

    if (m.direct_action && !threat.mitigated) {
        const mitigationPanel = document.createElement("div");
        mitigationPanel.id = "directMitigationPanel";
        mitigationPanel.className = "threat-info-block";
        mitigationPanel.style.border = "1px solid rgba(0, 229, 255, 0.4)";
        mitigationPanel.style.background = "rgba(0, 229, 255, 0.07)";
        mitigationPanel.style.borderRadius = "12px";
        mitigationPanel.style.padding = "16px";
        mitigationPanel.style.marginTop = "16px";

        const button = document.createElement("button");
        button.innerText = "Mitigate Threat";
        button.className = "btn-primary";
        button.style.width = "100%";
        button.onclick = () => mitigateThreat(index);
        mitigationPanel.appendChild(button);

        const statusDiv = document.createElement("div");
        statusDiv.id = "mitigationStatus";
        statusDiv.style.marginTop = "10px";
        mitigationPanel.appendChild(statusDiv);

        document.querySelector("#threatModal .modal-body").appendChild(mitigationPanel);
    } else if (threat.mitigated) {
        // Remove any previously injected mitigated message to avoid duplicates
        const existingMitigatedMsg = document.querySelector("#threatModal .modal-body .mitigated-status-msg");
        if (existingMitigatedMsg) existingMitigatedMsg.remove();

        const statusDiv = document.createElement("div");
        statusDiv.className = "threat-info-block success-block mitigated-status-msg";
        statusDiv.innerText = "✅ This threat has been mitigated.";
        document.querySelector("#threatModal .modal-body").appendChild(statusDiv);
    }

    // Keep the old block panel for compatibility, but hide if direct action is available
    const blockPanel = document.getElementById("blockIpPanel");
    if (m.direct_action) {
        blockPanel.style.display = "none";
    } else {
        // Old logic
        const mitigationText = (typeof m.mitigation === 'object' ? m.mitigation.summary : m.mitigation) || "";
        const blockKeywords = ["block", "block the source", "block source ip", "block ip", "blacklist", "firewall rule"];
        const shouldShowBlock = blockKeywords.some(k => mitigationText.toLowerCase().includes(k));

        const blockIpTarget = document.getElementById("blockIpTarget");
        const blockIpBtn = document.getElementById("blockIpBtn");
        const unblockIpBtn = document.getElementById("unblockIpBtn");
        const blockIpStatus = document.getElementById("blockIpStatus");

        if (shouldShowBlock && threat.src && threat.src !== "SYSTEM") {
            blockPanel.style.display = "block";
            blockIpTarget.innerText = threat.src;
            window._currentBlockIp = threat.src;

            fetch('/blocked_ips').then(r => r.json()).then(data => {
                const isBlocked = data.blocked.includes(threat.src);
                blockIpBtn.style.display = isBlocked ? "none" : "inline-block";
                unblockIpBtn.style.display = isBlocked ? "inline-block" : "none";
                blockIpStatus.innerText = isBlocked ? "⛔ IP is currently blocked" : "";
                refreshBlockedIpsList(data.blocked);
            });
        } else {
            blockPanel.style.display = "none";
            window._currentBlockIp = null;
        }
    }

    toggleThreatModal();
}

function blockThreatIp() {
    const ip = window._currentBlockIp;
    if (!ip) return;

    const btn = document.getElementById("blockIpBtn");
    const status = document.getElementById("blockIpStatus");
    btn.disabled = true;
    btn.innerText = "Blocking...";
    status.innerText = "";

    fetch('/block_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                status.innerText = `❌ Error: ${data.error}`;
                btn.disabled = false;
                btn.innerText = "🚫 Block IP";
            } else {
                document.getElementById("blockIpBtn").style.display = "none";
                document.getElementById("unblockIpBtn").style.display = "inline-block";
                status.innerText = data.status === "blocked"
                    ? "⛔ Firewall rule applied — IP blocked!"
                    : `⚠️ ${data.note || "Tracked in session"}`;
                fetch('/blocked_ips').then(r => r.json()).then(d => refreshBlockedIpsList(d.blocked));
            }
        })
        .catch(() => { status.innerText = "❌ Failed to contact server"; btn.disabled = false; btn.innerText = "🚫 Block IP"; });
}

function unblockThreatIp() {
    const ip = window._currentBlockIp;
    if (!ip) return;

    const btn = document.getElementById("unblockIpBtn");
    const status = document.getElementById("blockIpStatus");
    btn.disabled = true;
    btn.innerText = "Unblocking...";

    fetch('/unblock_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    })
        .then(r => r.json())
        .then(() => {
            document.getElementById("unblockIpBtn").style.display = "none";
            document.getElementById("blockIpBtn").style.display = "inline-block";
            document.getElementById("blockIpBtn").disabled = false;
            document.getElementById("blockIpBtn").innerText = "🚫 Block IP";
            status.innerText = "✅ IP unblocked";
            fetch('/blocked_ips').then(r => r.json()).then(d => refreshBlockedIpsList(d.blocked));
        })
        .catch(() => { status.innerText = "❌ Failed"; btn.disabled = false; btn.innerText = "✅ Unblock IP"; });
}

function mitigateThreat(index) {
    const button = document.querySelector("#directMitigationPanel button");
    const statusDiv = document.getElementById("mitigationStatus");
    button.disabled = true;
    button.innerText = "Mitigating...";
    statusDiv.innerText = "";

    fetch('/mitigate_threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index })
    })
        .then(r => r.json())
        .then(data => {
            if (data.status === "mitigated" || data.status === "already_blocked" || data.status === "tracked") {
                statusDiv.innerText = "✅ Threat Mitigated";
                statusDiv.style.color = "#00e676";
                button.innerText = "Mitigated";
                button.disabled = true;
                // Update the threat
                window.currentThreats[index].mitigated = true;
                // Refresh blocked IPs
                fetch('/blocked_ips').then(r => r.json()).then(d => refreshBlockedIpsList(d.blocked));
            } else {
                statusDiv.innerText = data.error || "Failed to mitigate";
                statusDiv.style.color = "#ff5252";
                button.disabled = false;
                button.innerText = "Mitigate Threat";
            }
        })
        .catch(() => {
            statusDiv.innerText = "❌ Error mitigating threat";
            statusDiv.style.color = "#ff5252";
            button.disabled = false;
            button.innerText = "Mitigate Threat";
        });
}

function refreshBlockedIpsList(blocked) {
    const summary = document.getElementById("blockedIpsSummary");
    const list = document.getElementById("blockedIpsList");
    if (!blocked || blocked.length === 0) {
        summary.style.display = "none";
        return;
    }
    summary.style.display = "block";
    list.innerHTML = "";
    blocked.forEach(ip => {
        const chip = document.createElement("span");
        chip.style.cssText = "background: rgba(255,82,82,0.15); border: 1px solid rgba(255,82,82,0.4); color: #ff7b72; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-family: monospace; display:inline-flex; align-items:center; gap:6px;";
        chip.innerHTML = `⛔ ${ip} <span style="cursor:pointer; opacity:0.7;" onclick="quickUnblock('${ip}')">✕</span>`;
        list.appendChild(chip);
    });
}

function quickUnblock(ip) {
    fetch('/unblock_ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    }).then(() => fetch('/blocked_ips').then(r => r.json()).then(d => refreshBlockedIpsList(d.blocked)));
}

function showSection(section) {
    console.log("Showing section:", section);
    // Add logic here if more sections are added
}

function startAnalyzer() {
    const iface = document.getElementById("interfaceSelect").value;
    fetch('/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: iface })
    }).catch(err => console.error(err));
}

// when the dashboard loads and a capture is already running, prompt user to restart
function checkRunningOnLoad() {
    fetch('/status')
        .then(r => r.json())
        .then(s => {
            if (s.running) {
                const msg = "A capture session is already in progress. Do you want to restart fresh?";
                if (confirm(msg)) {
                    // stop current session then start again once stopped
                    fetch('/stop', { method: 'POST' })
                        .finally(() => {
                            // small delay to give server time to reset
                            setTimeout(startAnalyzer, 200);
                        });
                }
            }
            // if not running, just reload page with fresh metrics (no auto-start)
        })
        .catch(err => console.error('status check failed', err));
}

function stopAnalyzer() {
    fetch('/stop', { method: 'POST' }).catch(err => console.error(err));
}

function runDosTest() {
    const statusBadge = document.getElementById("statusBadge");
    if (statusBadge && statusBadge.innerText.includes("STOPPED")) {
        alert("Please START the analyzer first to see the simulation results!");
        return;
    }

    const btn = document.getElementById("dosBtn");
    const stopBtn = document.getElementById("stopDosBtn");

    btn.style.display = "none";
    stopBtn.style.display = "flex";

    fetch('/run_dos_test', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            console.log("Simulation started:", data);
        })
        .catch(err => {
            console.error(err);
            btn.style.display = "flex";
            stopBtn.style.display = "none";
        });
}

function stopDosTest() {
    const btn = document.getElementById("dosBtn");
    const stopBtn = document.getElementById("stopDosBtn");

    fetch('/stop_dos_test', { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            console.log("Stop signal sent:", data);
            btn.style.display = "flex";
            stopBtn.style.display = "none";
        })
        .catch(err => console.error(err));
}

function downloadReport() {
    toggleDownloadModal();
}

function toggleDownloadModal() {
    const modal = document.getElementById('downloadModal');
    modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
}

function downloadReportAs(format) {
    window.location.href = `/download_report/${format}`;
    toggleDownloadModal();
}


function uploadPcap() {
    const input = document.getElementById('pcapInput');
    if (!input.files || input.files.length === 0) return;

    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);

    const btn = document.getElementById('uploadBtn');
    const originalText = btn.innerText;
    btn.disabled = true;
    btn.innerText = "⏳ Stopping capture...";

    // 1. stop live capture first
    fetch('/stop', { method: 'POST' })
        .then(() => {
            btn.innerText = "⏳ Analyzing...";
            // 2. small delay for server to reset
            return new Promise(resolve => setTimeout(resolve, 300));
        })
        .then(() => {
            // 3. now upload and analyze pcap
            return fetch('/upload_pcap', {
                method: 'POST',
                body: formData
            });
        })
        .then(async r => {
            const data = await r.json();
            if (!r.ok) throw new Error(data.error || "Server error");
            return data;
        })
        .then(data => {
            alert("PCAP Analysis Complete!");
            btn.disabled = false;
            btn.innerText = originalText;
            input.value = ""; // Clear input
        })
        .catch(err => {
            console.error("Upload failed:", err);
            alert("Upload failed: " + err.message);
            btn.disabled = false;
            btn.innerText = originalText;
        });
}

// 🔑 WebSocket Event Listener
socket.on('status_update', (stats) => {
    if (window.isPlaybackMode) return; // Prevent live updates overriding the time-travel replay

    // 0. Update Chart (only if running)
    if (stats.running) {
        updateChart(stats);
    }

    // 1. Update Status Badge & View Visibility
    // 1. Update Status Badge
    const statusBadge = document.getElementById("statusBadge");

    if (stats.running) {
        if (stats.capturing) {
            statusBadge.innerText = "● CAPTURING";
            statusBadge.className = "status-badge running";
        } else {
            statusBadge.innerText = "● WAITING";
            statusBadge.className = "status-badge warning";
        }
    } else {
        statusBadge.innerText = "● STOPPED";
        statusBadge.className = "status-badge stopped";
    }

    // 2. Update Metrics
    document.getElementById("networkSpeed").innerText = stats.speed_text || "0 bps";
    document.getElementById("packetRate").innerText = stats.packet_rate || 0;
    document.getElementById("bandwidth").innerText = stats.bandwidth || 0;
    document.getElementById("latency").innerText = stats.latency || 0;
    document.getElementById("jitter").innerText = stats.jitter || 0;
    document.getElementById("flows").innerText = stats.flow_count || 0;
    document.getElementById("errorRate").innerText = stats.error_rate || 0;
    document.getElementById("errorPercentage").innerText = (stats.error_percentage || 0) + "%";
    document.getElementById("packetLoss").innerText = stats.packet_loss || 0;
    document.getElementById("threats").innerText = stats.threats || 0;

    // 2.7 Update Top Talkers
    const talkersList = document.getElementById("topTalkersList");
    if (stats.top_talkers && stats.top_talkers.length > 0) {
        talkersList.innerHTML = "";
        stats.top_talkers.forEach(t => {
            const tr = document.createElement("tr");
            const vol = t.bytes > 1024 * 1024
                ? (t.bytes / (1024 * 1024)).toFixed(2) + " MB"
                : (t.bytes / 1024).toFixed(2) + " KB";
            tr.innerHTML = `<td><strong>${t.ip}</strong></td><td>${vol}</td>`;
            talkersList.appendChild(tr);
        });
    } else {
        talkersList.innerHTML = "<tr><td colspan='2' style='text-align:center; opacity:0.5'>Capturing data...</td></tr>";
    }

    // 2.8 Update Suspicious IPs
    const sipList = document.getElementById("suspiciousIpsList");
    if (stats.suspicious_ips && Array.isArray(stats.suspicious_ips) && stats.suspicious_ips.length > 0) {
        sipList.innerHTML = "";
        stats.suspicious_ips.forEach(ipData => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="color: #ff5252; font-weight: bold;">${ipData.ip}</td>
                <td style="text-align: center;">${ipData.threats || 0}</td>
                <td style="font-size: 0.9em;">${ipData.latest_type || 'Unknown'}</td>
            `;
            sipList.appendChild(tr);
        });
    } else {
        sipList.innerHTML = `<tr><td colspan="3" style="text-align:center; opacity:0.5;">No suspicious IPs detected</td></tr>`;
    }

    // 2.9 Update Network Health Gauge
    if (typeof stats.health_score !== 'undefined') {
        updateHealthGauge(stats.health_score);
    }

    // 3. Update Threat List
    const threatList = document.getElementById("threatList");
    if (stats.threat_list && stats.threat_list.length > 0) {
        threatList.innerHTML = "";
        // Store last threat list for modal access
        window.currentThreats = stats.threat_list;

        stats.threat_list.slice().reverse().forEach((t, index) => {
            const realIndex = stats.threat_list.length - 1 - index;
            const li = document.createElement("li");
            const mitigatedIcon = t.mitigated ? " ✅" : "";
            li.innerHTML = `
                <div class="threat-content">
                    <strong>${t.timestamp}</strong> [${t.protocol}] ${t.alert}${mitigatedIcon}<br>
                    <span style='font-size:0.8em; opacity:0.7'>${t.src} &rarr; ${t.dst}</span>
                </div>
                <button class="btn-analyze" onclick="viewThreatDetails(${realIndex})">🔍 Analyze</button>
            `;
            threatList.appendChild(li);
        });

    } else {
        threatList.innerHTML = "<li>No threats detected</li>";
    }

    // 4. Update Active Flows Modal
    const flowList = document.getElementById("activeFlowsList");

    // Store current stats globally for modal filtering
    window.currentStats = stats;

    // Get modal mode to determine filtering
    const modal = document.getElementById("interfaceModal");
    const isFlowsOnlyMode = modal && modal.getAttribute("data-mode") === "flows-only";

    // If flows-only mode, filter flows to show only from connected interface
    let flowsToDisplay = stats.active_flows || [];
    if (isFlowsOnlyMode && stats.current_interface) {
        const connectedIface = stats.current_interface;
        // Display info about connected interface
        const flowsTitle = document.getElementById("flowsTitle");
        if (flowsTitle) {
            flowsTitle.innerText = `📊 Active Flows on ${connectedIface}`;
        }
    }

    if (flowsToDisplay && flowsToDisplay.length > 0) {
        flowList.innerHTML = "";

        // Build a Set of ATTACKER IPs only (source of threats, not the victim/destination)
        const threatIps = new Set();
        const ignoredIps = new Set(["SYSTEM", "NETWORK", "0.0.0.0", "127.0.0.1"]);
        if (stats.threat_list) {
            stats.threat_list.forEach(t => {
                // Only flag the SOURCE of the threat (the attacker), not the destination (our device)
                if (t.src && !ignoredIps.has(t.src)) {
                    threatIps.add(t.src);
                }
            });
        }

        flowsToDisplay.forEach(flow => {
            // Flow format: "src_ip->dst_ip:dport/proto"
            const parts = flow.split('/');
            const conn = parts[0];
            const proto = parts[1] || "UNK";

            // Extract src and dst IPs for threat matching
            const [srcPart, dstPart] = conn.split('->');
            const srcIp = (srcPart || "").trim();
            const dstIp = ((dstPart || "").split(':')[0]).trim();

            const isThreat = threatIps.has(srcIp) || threatIps.has(dstIp);

            const tr = document.createElement("tr");

            if (isThreat) {
                tr.style.cssText = `
                    background: rgba(255, 82, 82, 0.12);
                    border-left: 3px solid #ff5252;
                    color: #ff7b72;
                    font-weight: 600;
                `;
                tr.innerHTML = `
                    <td>⚠️ ${conn}</td>
                    <td style="color:#ff5252;">${proto}</td>
                `;
            } else {
                tr.innerHTML = `<td>${conn}</td><td>${proto}</td>`;
            }

            flowList.appendChild(tr);
        });
    } else {
        flowList.innerHTML = "<tr><td colspan='2' style='text-align:center; opacity:0.5'>No active flows</td></tr>";
    }

    // 5. Update AI Anomaly Panel
    if (stats.anomaly) {
        updateAnomaly(stats.anomaly);
    }


});

// ══════════════════════════════════════════════════════════════════
//  AI ANOMALY ENGINE UI
// ══════════════════════════════════════════════════════════════════

let anomalyTimelineChart = null;
const ANOMALY_TIMELINE_MAX = 60;

const SCORE_COLORS = {
    learning: '#a78bfa',
    normal:   '#00e5ff',
    low:      '#fbbf24',
    medium:   '#fb923c',
    high:     '#f87171',
    critical: '#c084fc'
};

function initAnomalyTimeline() {
    const canvas = document.getElementById('anomalyTimelineChart');
    if (!canvas || anomalyTimelineChart) return;

    anomalyTimelineChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Anomaly Score',
                    data: [],
                    borderColor: '#a78bfa',
                    backgroundColor: 'rgba(167,139,250,0.1)',
                    borderWidth: 2,
                    tension: 0.4,
                    fill: true,
                    pointRadius: 0,
                },
                {
                    label: 'Med (65)',
                    data: [],
                    borderColor: 'rgba(251,146,60,0.5)',
                    borderWidth: 1,
                    borderDash: [4, 3],
                    pointRadius: 0,
                    fill: false,
                },
                {
                    label: 'High (80)',
                    data: [],
                    borderColor: 'rgba(239,68,68,0.5)',
                    borderWidth: 1,
                    borderDash: [4, 3],
                    pointRadius: 0,
                    fill: false,
                },
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            interaction: { intersect: false },
            scales: {
                x: { display: false },
                y: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { color: '#8b949e', font: { size: 9 } }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function updateAnomaly(anomaly) {
    // Lazy-init timeline chart
    if (!anomalyTimelineChart) initAnomalyTimeline();

    const label     = anomaly.label || 'learning';
    const score     = anomaly.score || 0;
    const progress  = anomaly.learning_progress || 0;
    const isLearning = label === 'learning';
    const color      = SCORE_COLORS[label] || '#a78bfa';

    // ── Panel border class ─────────────────────────────────────
    const panel = document.getElementById('anomalyPanel');
    if (panel) {
        panel.className = 'anomaly-panel';
        if (!isLearning) panel.classList.add(`anomaly-${label}`);
    }

    // ── Score ring ─────────────────────────────────────────────
    const scoreEl = document.getElementById('anomalyScore');
    if (scoreEl) scoreEl.textContent = isLearning ? '--' : Math.round(score);

    // SVG ring: circumference = 2π×50 ≈ 314
    const ringFill = document.getElementById('ringFill');
    if (ringFill) {
        const offset = isLearning ? 314 : 314 - (score / 100) * 314;
        ringFill.style.strokeDashoffset = offset;
        ringFill.style.stroke = color;
    }

    // ── Severity badge ─────────────────────────────────────────
    const badge = document.getElementById('anomalySeverityBadge');
    if (badge) {
        badge.className = `anomaly-severity ${label}`;
        badge.textContent = label.toUpperCase();
    }

    // ── Confidence ─────────────────────────────────────────────
    const confEl = document.getElementById('anomalyConfidence');
    if (confEl) {
        const pct = isLearning ? 0 : Math.round((anomaly.confidence || 0) * 100);
        confEl.textContent = `${pct}%`;
    }

    // ── Learning progress bar ──────────────────────────────────
    const learningBlock = document.getElementById('anomalyLearningBlock');
    const normalBlock   = document.getElementById('anomalyNormalBlock');
    const expBlock      = document.getElementById('anomalyExplanationBlock');
    const actBlock      = document.getElementById('anomalyActionsBlock');

    if (isLearning) {
        if (learningBlock) learningBlock.style.display = 'block';
        if (normalBlock)   normalBlock.style.display   = 'none';
        if (expBlock)      expBlock.style.display      = 'none';
        if (actBlock)      actBlock.style.display      = 'none';

        const pctEl = document.getElementById('anomalyProgressPct');
        const bar   = document.getElementById('anomalyProgressBar');
        if (pctEl) pctEl.textContent = `${Math.round(progress)}%`;
        if (bar)   bar.style.width   = `${progress}%`;
        return;
    }

    // Not learning — hide progress bar
    if (learningBlock) learningBlock.style.display = 'none';

    // ── Explanation list ───────────────────────────────────────
    const exps = anomaly.explanations || [];
    if (exps.length > 0 && label !== 'normal') {
        if (expBlock) expBlock.style.display = 'block';
        if (normalBlock) normalBlock.style.display = 'none';

        const list = document.getElementById('anomalyExplanationList');
        if (list) {
            list.innerHTML = exps.slice(0, 5).map(e => `
                <li>
                    <span>${e.description}</span>
                    <span class="exp-deviation">+${e.percent_diff}%</span>
                </li>
            `).join('');
        }
    } else {
        if (expBlock)    expBlock.style.display    = 'none';
        if (normalBlock) normalBlock.style.display = 'flex';
    }

    // ── Suggested actions ──────────────────────────────────────
    const actions = anomaly.suggested_actions || [];
    if (actions.length > 0 && label !== 'normal') {
        if (actBlock) actBlock.style.display = 'block';
        const actList = document.getElementById('anomalyActionsList');
        if (actList) {
            actList.innerHTML = actions.map(a => `<li>${a}</li>`).join('');
        }
    } else {
        if (actBlock) actBlock.style.display = 'none';
    }

    // ── Timeline chart update ──────────────────────────────────
    if (anomalyTimelineChart) {
        const ts  = new Date().toLocaleTimeString();
        const ds  = anomalyTimelineChart.data;

        ds.labels.push(ts);
        ds.datasets[0].data.push(score);
        ds.datasets[1].data.push(65);
        ds.datasets[2].data.push(80);

        // Colour the score line based on current severity
        ds.datasets[0].borderColor       = color;
        ds.datasets[0].backgroundColor   = color.replace(')', ',0.1)').replace('rgb', 'rgba');

        if (ds.labels.length > ANOMALY_TIMELINE_MAX) {
            ds.labels.shift();
            ds.datasets.forEach(d => d.data.shift());
        }

        anomalyTimelineChart.update();
    }
}

// ── Control buttons ─────────────────────────────────────────────

function retrainAnomalyModel() {
    const btn = document.getElementById('retrainBtn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Retraining...'; }

    fetch('/api/anomaly/retrain', { method: 'POST' })
        .then(r => r.json())
        .then(() => {
            if (btn) { btn.disabled = false; btn.textContent = '🔄 Retrain AI Model'; }
            alert('AI model reset — it will now rebuild its baseline from live traffic.');
        })
        .catch(() => {
            if (btn) { btn.disabled = false; btn.textContent = '🔄 Retrain AI Model'; }
        });
}

function saveAnomalyModel() {
    fetch('/api/anomaly/save', { method: 'POST' })
        .then(r => r.json())
        .then(d => alert(d.status === 'model_saved'
            ? '✅ AI model saved — it will load automatically on next startup.'
            : 'Save response: ' + JSON.stringify(d)))
        .catch(err => alert('Save failed: ' + err));
}



// ══════════════════════════════════════════════════════════════════
//  HISTORICAL TIME-TRAVEL & PLAYBACK
// ══════════════════════════════════════════════════════════════════
window.isPlaybackMode = false;
let playbackInterval = null;
let historyMetricsData = [];
let historyThreatsData = [];

function toggleHistoryModal() {
    const modal = document.getElementById("historyModal");
    if (modal.style.display === "none" || modal.style.display === "") {
        modal.style.display = "flex";
        
        // Auto-fill time to last hour if empty
        const now = new Date();
        const start = new Date(now.getTime() - 60*60*1000);
        
        // Setup local ISO strings required by datetime-local input
        const toLocalISO = dt => new Date(dt.getTime() - (dt.getTimezoneOffset() * 60000)).toISOString().slice(0, 16);
        
        if (!document.getElementById("histStartTime").value) {
            document.getElementById("histStartTime").value = toLocalISO(start);
        }
        if (!document.getElementById("histEndTime").value) {
            document.getElementById("histEndTime").value = toLocalISO(now);
        }
    } else {
        modal.style.display = "none";
    }
}

function queryHistoryData() {
    const stEl = document.getElementById("histStartTime").value;
    const edEl = document.getElementById("histEndTime").value;
    const ipFilt = document.getElementById("histIpFilter").value.trim();
    
    if (!stEl || !edEl) { alert("Please select start and end times"); return; }
    
    // Convert local inputs to backend timestamps (seconds epoch)
    const stTs = new Date(stEl).getTime() / 1000;
    const edTs = new Date(edEl).getTime() / 1000;
    
    document.getElementById("histQuerySpinner").innerText = "⏳ ";
    const btn = document.querySelector("#historyModal .secondary-btn");
    btn.disabled = true;

    fetch("/api/history/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            start_time: stTs,
            end_time: edTs,
            ip_filter: ipFilt || null
        })
    })
    .then(r => r.json())
    .then(data => {
        btn.disabled = false;
        document.getElementById("histQuerySpinner").innerText = "";
        
        const resArea = document.getElementById("historyResultsArea");
        resArea.style.display = "block";
        
        historyMetricsData = data.metrics || [];
        historyThreatsData = data.threats || [];
        
        document.getElementById("histMetricsCount").innerText = historyMetricsData.length;
        document.getElementById("histThreatsCount").innerText = historyThreatsData.length;
        
        const playBtn = document.getElementById("histPlayBtn");
        if (historyMetricsData.length > 0) {
            document.getElementById("histWarning").style.display = "none";
            playBtn.disabled = false;
        } else {
            document.getElementById("histWarning").style.display = "block";
            playBtn.disabled = true;
        }
    })
    .catch(err => {
        btn.disabled = false;
        document.getElementById("histQuerySpinner").innerText = "";
        alert("Query error: " + err);
    });
}

function startHistoryPlayback() {
    if (historyMetricsData.length === 0) {
        alert("⏳ No historical data yet.\n\nThe database needs at least ~30 seconds of active packet capture to record metrics.\n\nMake sure:\n1. An interface is selected and capturing\n2. At least 30 seconds have passed\n3. Re-run the query in the History modal\n\nTip: Try widening your time range (e.g., last 1 hour).");
        return;
    }
    
    toggleHistoryModal();
    window.isPlaybackMode = true;
    
    // UI Transitions
    document.getElementById("playbackBanner").style.display = "flex";
    document.getElementById("statusBadge").innerText = "● TIME TRAVEL";
    document.getElementById("statusBadge").className = "status-badge anomaly";
    
    // Clear live charts for replay
    if (packetChart) {
        packetChart.data.labels = [];
        packetChart.data.datasets[0].data = [];
        packetChart.update();
    }
    if (bandwidthChart) {
        bandwidthChart.data.labels = [];
        bandwidthChart.data.datasets[0].data = [];
        bandwidthChart.update();
    }
    document.getElementById("threatList").innerHTML = "<li>Replaying Threats...</li>";
    
    let playCursor = 0;
    const playSpeedMs = 100; // 10x speed of the original 1s intervals
    
    if (playbackInterval) clearInterval(playbackInterval);
    
    // Disconnect socket UI from native connection checks to avoid flapping
    document.getElementById("startBtn").disabled = true;
    document.getElementById("stopBtn").disabled = true;
    
    playbackInterval = setInterval(() => {
        if (playCursor >= historyMetricsData.length) {
            // Replay finished
            clearInterval(playbackInterval);
            document.getElementById("playbackTimeText").innerText = "REPLAY ENDED";
            document.getElementById("statusBadge").innerText = "● REPLAY PAUSED";
            document.getElementById("statusBadge").className = "status-badge warning";
            return;
        }
        
        const row = historyMetricsData[playCursor];
        const rowTime = new Date(row.timestamp * 1000);
        document.getElementById("playbackTimeText").innerText = rowTime.toLocaleTimeString();
        
        // Render Metric Values (Simulating native stats object)
        document.getElementById("packetRate").innerText = row.packet_count || 0;
        document.getElementById("bandwidth").innerText = (row.bandwidth_in || 0).toFixed(1);
        document.getElementById("latency").innerText = row.latency || 0;
        document.getElementById("jitter").innerText = row.jitter || 0;
        document.getElementById("packetLoss").innerText = row.packet_loss || 0;
        
        if (typeof row.health_score !== 'undefined') updateHealthGauge(row.health_score);
        
        // Update Chart ticks (Using same logic just bypassing full `updateChart`)
        const tsLabel = rowTime.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
        
        if (packetChart) {
            packetChart.data.labels.push(tsLabel);
            packetChart.data.datasets[0].data.push(row.packet_count || 0);
            if (packetChart.data.labels.length > 50) { packetChart.data.labels.shift(); packetChart.data.datasets[0].data.shift(); }
            packetChart.update('none');
        }
        if (bandwidthChart) {
            bandwidthChart.data.labels.push(tsLabel);
            bandwidthChart.data.datasets[0].data.push(row.bandwidth_in || 0);
            if (bandwidthChart.data.labels.length > 50) { bandwidthChart.data.labels.shift(); bandwidthChart.data.datasets[0].data.shift(); }
            bandwidthChart.update('none');
        }
        
        // Check for threats that occurred on/near this exact timestamp slice
        // Easiest approach given DB rows: find all threats between row N and N+1 
        const nextTime = (playCursor < historyMetricsData.length - 1) 
            ? historyMetricsData[playCursor+1].timestamp 
            : row.timestamp + 10;
            
        const sliceThreats = historyThreatsData.filter(t => t.timestamp >= row.timestamp && t.timestamp < nextTime);
        
        if (sliceThreats.length > 0) {
            const threatList = document.getElementById("threatList");
            if (threatList.innerText.includes("Replaying")) threatList.innerHTML = "";
            
            sliceThreats.forEach(t => {
                const li = document.createElement("li");
                const tsDate = new Date(t.timestamp * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'});
                li.innerHTML = `
                    <div class="threat-content">
                        <strong>${tsDate}</strong> [${t.protocol}] ${t.alert}<br>
                        <span style='font-size:0.8em; opacity:0.7'>${t.src_ip} &rarr; ${t.dst_ip}</span>
                    </div>
                `;
                threatList.prepend(li);
                if (threatList.children.length > 20) threatList.removeChild(threatList.lastChild);
            });
        }

        playCursor++;
    }, playSpeedMs);
}

function exitPlaybackMode() {
    window.isPlaybackMode = false;
    if (playbackInterval) clearInterval(playbackInterval);
    
    document.getElementById("playbackBanner").style.display = "none";
    document.getElementById("startBtn").disabled = false;
    document.getElementById("stopBtn").disabled = false;
    
    // Wipe replay charts to prep for live data
    if (packetChart) { packetChart.data.labels = []; packetChart.data.datasets[0].data = []; packetChart.update(); }
    if (bandwidthChart) { bandwidthChart.data.labels = []; bandwidthChart.data.datasets[0].data = []; bandwidthChart.update(); }
    document.getElementById("threatList").innerHTML = "<li>Waiting for live data...</li>";
    
    alert("Exited Playback Mode. Live interface will resume capturing smoothly.");
}

// ══════════════════════════════════════════════════════════════════
//  KILL CHAIN MAPPER
// ══════════════════════════════════════════════════════════════════
let currentKillchainData = null;

function toggleKillchainModal() {
    const modal = document.getElementById("killchainModal");
    if (modal.style.display === "none" || modal.style.display === "") {
        modal.style.display = "flex";
        loadKillchainData();
    } else {
        modal.style.display = "none";
    }
}

function loadKillchainData() {
    const container = document.getElementById("killchainContainer");
    container.innerHTML = `<div style="text-align:center; padding: 40px; color: var(--text-dim);">⏳ Analyzing Threat Stream for MITRE ATT&CK patterns...</div>`;
    
    fetch('/api/killchain')
        .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
        .then(data => {
            currentKillchainData = data.campaigns || [];
            if (data.error) {
                container.innerHTML = `<div style="color:#fb923c;text-align:center;padding:20px;">⚠️ Backend error: ${data.error}</div>`;
                return;
            }
            if (currentKillchainData.length === 0) {
                container.innerHTML = `
                    <div style="text-align:center; padding:40px;">
                        <div style="font-size:3rem;margin-bottom:12px;">✅</div>
                        <div style="color:var(--text-dim);margin-bottom:8px;font-weight:600;">No active threat campaigns detected.</div>
                        <small style="color:var(--text-dim);opacity:0.7;">Campaigns appear here once the analyzer detects threats.<br>Try using the 🔥 Threat Simulator to generate test events.</small>
                    </div>`;
                return;
            }
            
            let html = "";
            currentKillchainData.forEach(camp => {
                const threatLvlColor = camp.max_stage >= 4 ? '#ef4444' : camp.max_stage >= 2 ? '#f59e0b' : '#3b82f6';
                
                html += `
                <div class="campaign-card">
                    <div class="campaign-header">
                        <div>
                            <h3 style="margin:0; color:${threatLvlColor}">🚨 Campaign: ${camp.attacker_ip}</h3>
                            <small style="color:var(--text-dim)">First seen: ${camp.events[0].timestamp} • Events: ${camp.events.length} • Targets: ${camp.target_ips.length}</small>
                        </div>
                        <div style="text-align:right">
                            <span style="display:inline-block; padding: 4px 8px; border-radius: 4px; background: rgba(255,255,255,0.05); font-size: 0.8rem;">
                                Max Stage: <strong>${camp.max_stage}/5</strong>
                            </span>
                        </div>
                    </div>
                    
                    <div class="killchain-timeline">`;
                
                camp.events.forEach(ev => {
                    const mitIcon = ev.mitigated ? '🛡️ [Blocked]' : '⚠️ [Active]';
                    html += `
                        <div class="timeline-event">
                            <div class="timeline-dot" style="background: ${ev.color}; box-shadow: 0 0 8px ${ev.color}"></div>
                            <div class="timeline-content" style="border-left: 2px solid ${ev.color}">
                                <div style="display:flex; justify-content: space-between;">
                                    <strong>${ev.timestamp}</strong>
                                    <span style="color:var(--text-dim); font-size: 0.8rem;">${mitIcon} ${ev.protocol}</span>
                                </div>
                                <div style="margin-top: 5px;">${ev.alert}</div>
                                <div class="mitre-badge" style="background: ${ev.color}40; border: 1px solid ${ev.color}; color: var(--text-color);">
                                    ${ev.tactic} (${ev.technique_id})
                                </div>
                            </div>
                        </div>`;
                });
                
                html += `
                    </div>
                </div>`;
            });
            
            container.innerHTML = html;
        })
        .catch(err => {
            container.innerHTML = `<div style="color:red; text-align:center; padding: 20px;">Error generating kill chain: ${err}</div>`;
        });
}

function exportKillchainReport() {
    if (!currentKillchainData || currentKillchainData.length === 0) {
        alert("No campaigns to export.");
        return;
    }
    
    // Create detailed text report
    let rep = "=================================================\n";
    rep += "   NETFALCON INCIDENT REPORT: MITRE ATT&CK       \n";
    rep += "=================================================\n\n";
    
    currentKillchainData.forEach(c => {
        rep += `CAMPAIGN: ${c.attacker_ip}\n`;
        rep += `First Seen: ${c.events[0].timestamp}\n`;
        rep += `Last Seen : ${c.last_seen}\n`;
        rep += `Max Stage : ${c.max_stage}/5\n`;
        rep += `Targets   : ${c.target_ips.join(', ')}\n`;
        rep += `-------------------------------------------------\n`;
        
        c.events.forEach(e => {
            const status = e.mitigated ? "MITIGATED" : "ACTIVE";
            rep += `[${e.timestamp}] ${status}\n`;
            rep += `  Alert : ${e.alert}\n`;
            rep += `  MITRE : ${e.tactic} (${e.technique_id})\n`;
            rep += `  Proto : ${e.protocol}\n\n`;
        });
        rep += "\n";
    });
    
    const blob = new Blob([rep], { type: "text/plain" });
    const u = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = u;
    a.download = `netfalcon-killchain-${new Date().getTime()}.txt`;
    a.click();
    URL.revokeObjectURL(u);
}

// ══════════════════════════════════════════════════════════════════
//  THREAT SIMULATOR
// ══════════════════════════════════════════════════════════════════
let currentSimType = "port_scan";

function toggleSimulatorModal() {
    const modal = document.getElementById("simulatorModal");
    if (modal.style.display === "none" || modal.style.display === "") {
        modal.style.display = "flex";
        // Setup slider listener
        const intensitySlider = document.getElementById("simIntensity");
        const intensityVal = document.getElementById("simIntensityVal");
        if (intensitySlider && intensityVal) {
            intensitySlider.oninput = function() { intensityVal.innerText = this.value; };
        }
        // Start polling status while modal is open
        _simStatusInterval = setInterval(_pollSimStatus, 2000);
        _pollSimStatus(); // immediate first check
    } else {
        modal.style.display = "none";
        clearInterval(_simStatusInterval);
    }
}

let _simStatusInterval = null;
function _pollSimStatus() {
    fetch('/api/simulate/report')
        .then(r => r.json())
        .then(data => {
            const running = data.status && Object.keys(data.status).length > 0;
            const bar     = document.getElementById("simStatusBar");
            const dot     = document.getElementById("simStatusDot");
            const text    = document.getElementById("simStatusText");
            const sub     = document.getElementById("simStatusSub");
            const counter = document.getElementById("simPacketCounter");
            const pkts    = document.getElementById("simPacketNum");
            if (!bar) return;

            if (running) {
                const simEntry = Object.values(data.status)[0];
                const simType  = (simEntry?.type || "simulation").replace(/_/g,' ').toUpperCase();
                const packets  = simEntry?.packets || 0;

                // Bar → green
                bar.style.background = "rgba(34,197,94,0.12)";
                bar.style.borderColor = "rgba(34,197,94,0.5)";
                dot.style.background  = "#22c55e";
                dot.style.boxShadow   = "0 0 8px #22c55e";
                text.style.color      = "#22c55e";
                text.innerText        = `⬤ SIMULATING — ${simType}`;
                sub.innerText         = "Attack packets are being generated. Monitor the Threat Intelligence panel for live detections.";
                counter.style.display = "block";
                pkts.innerText        = packets;

                // UI buttons
                document.getElementById("simStartBtn").style.display = "none";
                document.getElementById("simStopBtn").style.display  = "block";

            } else {
                // Bar → idle (gray)
                bar.style.background  = "rgba(107,114,128,0.12)";
                bar.style.borderColor = "rgba(107,114,128,0.35)";
                dot.style.background  = "#6b7280";
                dot.style.boxShadow   = "none";
                text.style.color      = "";
                text.innerText        = "⬤ IDLE — No simulation running";
                sub.innerText         = "Select an attack type below and click Launch to begin.";
                counter.style.display = "none";

                // Only restore launch btn if stop btn was visible (just stopped)
                if (document.getElementById("simStopBtn").style.display === "block") {
                    document.getElementById("simStartBtn").style.display = "block";
                    document.getElementById("simStopBtn").style.display  = "none";
                }
            }
        }).catch(() => {});
}

function setSimSelect(type, btnElement) {
    currentSimType = type;
    const btns = document.querySelectorAll(".sim-opt-btn");
    btns.forEach(b => {
        b.style.borderColor = "var(--card-border)";
        b.style.background = "var(--pane-bg)";
    });
    btnElement.style.borderColor = "#a78bfa";
    btnElement.style.background = "rgba(167, 139, 250, 0.1)";
}

function startAdvancedSimulation() {
    const intensity = document.getElementById("simIntensity").value;
    const safeMode  = document.getElementById("simSafeMode").checked;

    const payload = {
        sim_id: "default",
        type: currentSimType,
        intensity: parseInt(intensity),
        safe_mode: safeMode
    };

    fetch('/api/simulate/start', {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload)
    }).then(r => r.json()).then(data => {
        if (data.status === "started") {
            document.getElementById("simReportArea").style.display = "none";
            _pollSimStatus();
        } else {
            // Auto-recover: force reset and retry once
            console.warn("Sim start failed, auto-resetting...", data.error);
            fetch('/api/simulate/reset', { method: "POST" })
                .then(() => fetch('/api/simulate/start', {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify(payload)
                }))
                .then(r => r.json())
                .then(data2 => {
                    if (data2.status === "started") {
                        document.getElementById("simReportArea").style.display = "none";
                        _pollSimStatus();
                    } else {
                        alert("Could not start simulation. Try clicking ⟳ Force Reset and try again.");
                    }
                });
        }
    }).catch(e => console.error("Sim Start Error:", e));
}

function forceResetSimulator() {
    fetch('/api/simulate/reset', { method: "POST" })
        .then(r => r.json())
        .then(() => {
            document.getElementById("simStartBtn").style.display = "block";
            document.getElementById("simStopBtn").style.display  = "none";
            _pollSimStatus();
        })
        .catch(e => console.error("Force reset error:", e));
}

function stopAdvancedSimulation() {
    fetch('/api/simulate/stop', {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({sim_id: "default"})
    }).then(r => r.json()).then(() => {
        setTimeout(() => { _pollSimStatus(); fetchSimReport(); }, 400);
    }).catch(e => console.error("Sim Stop Error:", e));
}

function fetchSimReport() {
    fetch('/api/simulate/report')
        .then(r => r.json())
        .then(data => {
            document.getElementById("simReportArea").style.display = "block";
            document.getElementById("simReportText").innerHTML = `
                Simulation halted. <strong>AI Engine intercepted ${data.report.total_threats_logged} events</strong> during the drill.<br>
                <i style="color:var(--text-muted)">Open ⛓️ Kill Chain Mapper to see the full MITRE ATT&amp;CK tactical breakdown.</i>
            `;
        });
}
