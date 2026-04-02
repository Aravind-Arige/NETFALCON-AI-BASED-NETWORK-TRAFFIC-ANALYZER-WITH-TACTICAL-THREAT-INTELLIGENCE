**NETFALCON** is a comprehensive, AI-powered network traffic analysis platform that addresses the critical gaps in traditional network monitoring tools. Unlike passive capture utilities such as Wireshark or signature-dependent IDS platforms like Snort, NETFALCON combines:

- **Deep Packet Inspection** via Scapy
- **Unsupervised Machine Learning** (Isolation Forest) for zero-day anomaly detection
- **MITRE ATT&CK** kill chain correlation for campaign-level threat intelligence
- **Automated system-level threat mitigation** via Windows Firewall
- **Real-time web dashboard** via Flask + Socket.IO
## ✨ Key Features

| Feature | Description |
|---|---|
| 📡 **Live Traffic Capture** | Multi-threaded packet sniffing across WiFi, LAN, and Ethernet interfaces |
| 📊 **Real-time Metrics** | Network speed, avg bandwidth, latency, jitter, active flows, PPS, error rate, packet loss |
| 📈 **Live Graphs** | Real-time packet rate and bandwidth time-series graphs |
| 🔍 **Top IP Talkers** | Dynamic leaderboard of most active source/destination IP pairs |
| 🤖 **AI Anomaly Detection** | Isolation Forest (unsupervised ML) with real-time confidence scoring |
| 🚨 **Threat Detection** | Detects SYN Flood, Port Scan, ARP Poisoning, DNS Amplification, SSH Brute Force, C2 Beaconing |
| 🛡️ **Auto Mitigation** | Automatically blocks attacker IPs via Windows Firewall (`netsh`) rules |
| ⚔️ **Kill Chain Mapper** | Groups correlated alerts into MITRE ATT&CK attack campaigns |
| 📧 **Smart Alert Dispatcher** | SMTP email alerts to administrators on threat detection |
| 🎭 **Adversary Simulator** | Safely simulate SYN Flood, Port Scan, ARP Poisoning, DNS Amplification, SSH Brute Force, C2 Beaconing |
| ⏳ **Time Travel History** | Replay historical network snapshots from SQLite database |
| 🏥 **Network Health Meter** | Composite visual gauge of overall network health (0–100%) |
| 🕵️ **Suspicious IP Dashboard** | Live table of flagged IPs with associated threat types |
| 📁 **PCAP File Analysis** | Upload and analyze offline `.pcap` files |
| 📄 **Report Download** | Export analysis reports directly from the dashboard |
| 🌗 **Dark / Light Theme** | One-click theme toggle for the web interface |
| 🔌 **Auto Interface Detection** | Automatically detects available network interfaces or allows manual selection |
## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          NETFALCON                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  [Network Interface]  ──►  [Traffic Capture Engine]            │
│                                  │                              │
│              ┌───────────────────┤                              │
│              ▼                   ▼                              │
│     [Metrics Engine]    [Threat Detection Engine]               │
│     Feature Vectors ──►  [Anomaly Detection Module]            │
│              │                   │                              │
│              └────────►  [Kill Chain Mapper]                    │
│                                  │                              │
│              ┌───────────────────┤                              │
│              ▼                   ▼                              │
│     [Mitigation Engine]  [Alert Dispatcher]  (SMTP Email)      │
│              │                                                   │
│              ▼                                                   │
│     [Time Travel Module] ◄──► [SQLite Database]                │
│              │                                                   │
│              ▼                                                   │
│     [Flask Web Server + SocketIO] ──► [Dashboard (Browser)]    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
## 📁 Project Structure

```
NETFALCON/
│
├── app.py                      # Flask application entry point
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
├── .gitignore
│
├── modules/
│   ├── capture.py              # Traffic Capture Engine (Scapy sniffer)
│   ├── metrics.py              # Metrics Computation Module
│   ├── threat_detection.py     # Threat Detection Engine
│   ├── anomaly.py              # Isolation Forest Anomaly Detection
│   ├── kill_chain.py           # MITRE ATT&CK Kill Chain Mapper
│   ├── mitigation.py           # Windows Firewall Mitigation Engine
│   ├── alert_dispatcher.py     # SMTP Smart Alert Dispatcher
│   ├── simulator.py            # Adversary Threat Simulator
│   └── time_travel.py          # SQLite Time Travel History Module
│
├── templates/
│   ├── index.html              # Main dashboard template
│   ├── history.html            # Time travel panel template
│   
│
├── static/
│   ├── css/
│   │   ├── style.css           # Dashboard styling (dark/light theme)
│   ├── js/
│   │   ├── dashboard.js        # Real-time SocketIO event handlers
│   │   ├── graphs.js           # Chart.js graph rendering
│   │   └── theme.js            # Theme toggle logic
│
├── database/
│   └── netfalcon.db            # SQLite database (auto-created on first run)
│
└── screenshots/                # Dashboard screenshots for README
```
## 🛠️ Tech Stack

### Backend
| Library / Module | Role |
|---|---|
| `scapy.all` | Core packet capture, dissection, and crafting |
| `scapy.layers.dns` | DNS layer parsing for amplification detection |
| `scapy.layers.inet` | IP, TCP, UDP layer parsing |
| `scapy.layers.l2` | ARP, Ethernet layer parsing |
| `scapy.arch.windows` | Windows-specific interface and socket handling |
| `flask` | Web server and route handling |
| `flask_socketio` | Real-time WebSocket event push to browser |
| `sklearn.ensemble.IsolationForest` | Unsupervised ML anomaly detection |
| `smtplib` | SMTP email alert dispatch |
| `sqlite3` | Time-travel history database |
| `threading` | Multi-threaded capture and processing |
| `collections.defaultdict` | Efficient counters for flow and IP tracking |
| `psutil` | System resource and interface monitoring |
| `requests` | External threat intelligence queries |

### Frontend
| Technology | Role |
|---|---|
| HTML5 + CSS3 | Dashboard structure and theming |
| JavaScript + Chart.js | Real-time graphs and DOM updates |
| Socket.IO (client) | Live event subscription from Flask server |
| Jinja2 | Server-side HTML template rendering |

## ⚙️ Installation

### Prerequisites

- Windows 10/11 (64-bit)
- Python 3.9 or higher
- [Npcap](https://npcap.com/) installed (required for Scapy packet capture on Windows)
- An SMTP-enabled email account (e.g., Gmail with App Password) for alert dispatching

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/NETFALCON.git
cd NETFALCON
```

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**`requirements.txt`:**
```
scapy>=2.5.0
flask>=2.0.0
flask-socketio>=5.0.0
scikit-learn>=1.0.0
psutil>=5.9.0
requests>=2.28.0
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=465
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_app_password
ADMIN_EMAIL=admin@yourdomain.com
```

> ⚠️ Never commit your `.env` file to version control. It is listed in `.gitignore`.

### 5. Run NETFALCON

```bash
python app.py
```

Open your browser and navigate to:
```
http://localhost:5000
```


## 🚀 Usage

### Starting Analysis
1. Open the dashboard at `http://localhost:5000`
2. Select a network interface from the dropdown (or use **Auto-detect Interface**)
3. Click **▶ Start** to begin live capture
4. The status indicator changes from `● STOPPED` → `● CAPTURING`

### Stopping Analysis
- Click **■ Stop** at any time to halt capture

### Uploading a PCAP File
- Click **Upload PCAP** in the sidebar
- Select your `.pcap` file for offline analysis

### Simulating Attacks (Testing)
- Click **Threat Simulator** in the sidebar
- Select an attack type and intensity level
- Enable **Safe-Mode Sandboxing** to restrict simulation to `127.0.0.1`
- Click **Launch Attack Simulation**

### Time Travel History
- Click **Time Travel & History** in the sidebar
- Set a **Start Time** and **End Time**
- Click **Query Database** to retrieve snapshots
- Click **Start 10x Playback** to replay historical network state

### Switching Theme
- Click **Switch Theme** in the sidebar to toggle between dark and light modes

### Downloading Report
- Click **Download Report** in the sidebar to export the current analysis session

 
## 🧩 Modules

### 1. Traffic Capture Engine
Multi-threaded Scapy sniffer supporting live interface capture (`sniff()`) and offline PCAP analysis (`rdpcap()`). Uses `psutil.net_if_stats()` for interface enumeration, filtering for interfaces in UP state.

### 2. Metrics Computation Module
Computes sliding-window network performance metrics:
- **Bandwidth**: `bytes_per_second × 8 / 1,000,000` → Mbps
- **Latency / Jitter**: TCP SYN–SYNACK timing analysis; jitter = mean absolute deviation
- **Active Flows**: Unique 5-tuples `(src_ip, dst_ip, src_port, dst_port, proto)`
- **PPS**: Rolling packet count normalized per second
- **Error Rate**: TCP RST + ICMP unreachable percentage
- **Packet Loss**: TCP retransmission and ICMP echo reply loss detection

### 3. Threat Detection Engine
Behavioral rule engine for known attack patterns (see [Threat Detection](#-threat-detection)).

### 4. AI Anomaly Detection Module
Isolation Forest model trained continuously on live traffic feature vectors (see [AI Anomaly Detection](#-ai-anomaly-detection)).

### 5. Kill Chain Mapper
Correlates related threat alerts from the same source IP into coordinated attack campaigns mapped to MITRE ATT&CK stages (see [Kill Chain Mapping](#-kill-chain-mapping)).

### 6. Threat Mitigation Engine
Interfaces with Windows Firewall via `netsh` to block attacker IPs automatically upon threat confirmation.

```bash
# Example firewall rule added by NETFALCON:
netsh advfirewall firewall add rule name="NETFALCON_BLOCK_<IP>" dir=in action=block remoteip=<attacker_ip>
```

### 7. Smart Alert Dispatcher
Sends formatted HTML email alerts via SMTP (SSL/TLS port 465 or STARTTLS port 587) including: threat type, source IP, target IP, timestamp, ATT&CK stage, and recommended mitigation.

### 8. Adversary Threat Simulator
Uses Scapy's packet crafting to safely simulate six attack types against the monitored interface, bounded by duration and packet count limits with a safety interlock preventing external IP targeting.

### 9. Time Travel History Module
Snapshots network state to SQLite every 60 seconds. Supports historical range queries and 10x-speed dashboard replay for forensic investigation.

### 10. Web Dashboard
Flask + Jinja2 templates with Socket.IO real-time events: `metrics_update`, `threat_alert`, `anomaly_score`, `campaign_update`, `health_update`. Chart.js renders live packet rate and bandwidth graphs.
**⭐ If you found NETFALCON useful, please star this repository!**


Made with ❤️ by Aravind_Arige - NETFALCON, Hyderabad
