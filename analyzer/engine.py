# analyzer/engine.py

from typing import Any
import time
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, ARP, Raw, get_if_addr, conf
from analyzer.metrics import Metrics
from analyzer.threat_intel import analyze_threat, set_calculating_device_ip, CALCULATING_DEVICE_IPS, reset_calculating_device_ips, reset_threat_trackers, is_internal
import threading
from analyzer.firewall import block_ip_firewall
from analyzer.mitre import map_to_mitre
from analyzer.dpi import inspect_packet_l7

metrics = Metrics()
threats: list[dict[str, Any]] = []
protocols = {"TCP": 0, "UDP": 0, "IP": 0,"ICMP": 0, "Other": 0}

_running = False
_capture_thread = None
current_interface = None

last_packet_time = None

# New Globals
active_flows: set[str] = set()
src_ip_counts: dict[str, int] = {}
ip_download_bytes = {} # {ip: total_bytes_downloaded} 
ip_traffic = {} # {ip: total_bytes} - for Top Talkers
last_dos_check = 0
packet_rate = 0

# Suspicious IP tracking (simple heuristics)
suspicious_ips: dict[str, dict[str, Any]] = {}
_sip_lock = threading.Lock()

# Bandwidth Alert Configuration
BANDWIDTH_LIMIT_KBPS = 50000 # 50 Mbps as default capacity for easier testing
THREAT_THRESHOLD_MASSIVE_DOWNLOAD = 50 * 1024 * 1024 # 50MB threshold for "Massive" in a window

# Scan & Brute Force Tracking
# {src_ip: {dst_port1, dst_port2, ...}}
scan_tracker = {} 
# {src_ip: count} for Auth ports
auth_tracker = {}
last_scan_check = 0
last_bandwidth_alert = 0

# Mitigation Tracking - {threat_signature: mitigated_status}
mitigated_threats = {}

def process_packet(pkt, timestamp=None):
    global last_packet_time, last_dos_check, packet_rate, last_bandwidth_alert
    
    is_live = timestamp is None
    if is_live:
        last_packet_time = time.time()
        now = time.time()
    else:
        last_packet_time = float(timestamp)
        now = float(timestamp)

    # 0. Global Bandwidth Spike Check (Live only)
    curr_bw = metrics.bandwidth()
    if is_live and curr_bw > (0.9 * BANDWIDTH_LIMIT_KBPS) and (now - last_bandwidth_alert > 10):
        threats.append({
            "timestamp": time.strftime("%H:%M:%S", time.localtime(now)),
            "src": "SYSTEM",
            "dst": "NETWORK",
            "protocol": "ALERT",
            "alert": f"CRITICAL: Bandwidth Usage Exceeded 90% ({curr_bw} KB/s)"
        })
        last_bandwidth_alert = now

    # Standard IP Processing
    if IP in pkt:
        pkt_len = len(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        packet_info = {
            "src_ip": src_ip,  
            "dst_ip": dst_ip,
            "length": pkt_len
        }

        traffic_type = "Other"
        dport = 0
        
        if TCP in pkt:
            dport = pkt[TCP].dport
            packet_info["dst_port"] = dport
            protocols["TCP"] += 1
            if dport == 80: traffic_type = "HTTP"
            elif dport == 443: traffic_type = "HTTPS"
            elif dport == 22: traffic_type = "SSH"
            elif dport == 21: traffic_type = "FTP"
            elif dport == 3389: traffic_type = "RDP"
            else: traffic_type = "TCP"
        elif UDP in pkt:
            dport = pkt[UDP].dport
            packet_info["dst_port"] = dport
            protocols["UDP"] += 1
            if dport == 53: traffic_type = "DNS"
            else: traffic_type = "UDP"
        elif ICMP in pkt:
            protocols["ICMP"] += 1
            traffic_type = "ICMP"
        else:
            protocols["Other"] += 1
            traffic_type = "Other"

        # 1. Flow Tracking
        flow_key = f"{src_ip}->{dst_ip}:{dport}/{traffic_type}"
        active_flows.add(flow_key)

        detected_alert = None
        
        # Check if this is a simulation test packet
        is_sim_traffic = False
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if b"NETFALCON_FLOOD" in payload or b"DOS_TEST_PACKET" in payload:
                is_sim_traffic = True

        # 2. DoS / Massive Download Detection
        current_second = int(now)
        if current_second != last_dos_check:
            src_ip_counts.clear()
            # We don't clear ip_download_bytes every second, maybe every 60 seconds?
            # For simplicity, let's keep it cumulative for the session or clear if too large
            if len(ip_download_bytes) > 1000: ip_download_bytes.clear()
            
            scan_tracker.clear()
            auth_tracker.clear()
            last_dos_check = current_second
            packet_rate = 0 
        
        src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
        packet_rate += 1

        # Top Talkers Tracking
        ip_traffic[src_ip] = ip_traffic.get(src_ip, 0) + pkt_len
        ip_traffic[dst_ip] = ip_traffic.get(dst_ip, 0) + pkt_len

        # Suspicious IP detection using lightweight heuristics
        syn_flag = 1 if (TCP in pkt and pkt[TCP].flags == 0x02) else 0
        suspicion_type = None
        if src_ip_counts[src_ip] > 100:
            suspicion_type = "High Packet Rate"
        elif dport > 1024 and src_ip_counts[src_ip] > 50:
            suspicion_type = "Unusual Port Traffic"
        elif syn_flag and src_ip_counts[src_ip] > 20:
            suspicion_type = "SYN Flood Pattern"

        if suspicion_type:
            with _sip_lock:
                if src_ip not in suspicious_ips:
                    suspicious_ips[src_ip] = {
                        "ip": src_ip,
                        "threats": 0,
                        "latest_type": suspicion_type,
                        "first_seen": time.strftime("%H:%M:%S")
                    }
                suspicious_ips[src_ip]["threats"] += 1
                suspicious_ips[src_ip]["latest_type"] = suspicion_type

        # Massive Download Detection
        ip_download_bytes[src_ip] = ip_download_bytes.get(src_ip, 0) + pkt_len
        if src_ip not in CALCULATING_DEVICE_IPS and ip_download_bytes[src_ip] > THREAT_THRESHOLD_MASSIVE_DOWNLOAD:
            detected_alert = {
                "title": "Massive Data Transfer",
                "type": "Data Exfiltration / Hoarding",
                "cause": f"{src_ip} transferred more than 50MB in a short period.",
                "risk": "Potential sensitive data leak or unauthorized backup.",
                "mitigation": "Investigate the files being transferred and apply egress bandwidth limits."
            }
            ip_download_bytes[src_ip] = 0

        # Check DoS
        threshold = 40 if is_sim_traffic else 150
        if src_ip_counts[src_ip] == threshold + 1: 
            # Allow simulation test from anywhere (even local) but filter real DoS if from local
            if is_sim_traffic or (src_ip not in CALCULATING_DEVICE_IPS):
                if is_sim_traffic:
                    detected_alert = {
                        "title": "Performance Simulation Test",
                        "type": "Developer Test",
                        "cause": "High packet rate with developer simulation marker detected.",
                        "risk": "None - this is a controlled test for system capacity.",
                        "mitigation": "No action needed. You can stop the test via the sidebar."
                    }
                else:
                    detected_alert = {
                        "title": "Potential DoS / Packet Flood",
                        "type": "Denial of Service",
                        "cause": f"Extreme packet frequency (>150 pkt/s) from source {src_ip}.",
                        "risk": "Network congestion, local machine resource exhaustion, or service crash.",
                        "mitigation": "Immediately block the source IP and verify if it's a legitimate traffic spike."
                    }

        # Check Port Scan
        if src_ip not in scan_tracker: scan_tracker[src_ip] = set()
        scan_tracker[src_ip].add(dport)
        
        if src_ip not in CALCULATING_DEVICE_IPS and len(scan_tracker[src_ip]) > 15:
            if is_internal(src_ip) and is_internal(dst_ip):
                detected_alert = {
                    "title": "Intranet Lateral Movement",
                    "type": "Internal Reconnaissance",
                    "cause": f"Local device {src_ip} scanning more than 15 ports on {dst_ip}.",
                    "risk": "A compromised internal device is looking for other vulnerable systems.",
                    "mitigation": "Isolate the source device from the network and perform a malware scan."
                }
            else:
                detected_alert = {
                    "title": "External Cyber Attack: Port Scan",
                    "type": "External Reconnaissance",
                    "cause": f"External host {src_ip} scanning for open vulnerabilities.",
                    "risk": "Identifying exploitable services to gain unauthorized access.",
                    "mitigation": "Ensure your firewall is dropping unsolicited traffic and hide service banners."
                }

        # Check Brute Force
        if dport in [22, 21, 3389]:
            auth_tracker[src_ip] = auth_tracker.get(src_ip, 0) + 1
            if src_ip not in CALCULATING_DEVICE_IPS and auth_tracker[src_ip] > 20: 
                detected_alert = {
                    "title": "Brute Force Attack Attempt",
                    "type": "Access Violation",
                    "cause": f"Multiple login attempts to administrative ports (22/21/3389) from {src_ip}.",
                    "risk": "Account compromise, unauthorized system access, data theft.",
                    "mitigation": "Implement account lockout policies, use SSH keys only, and enable MFA."
                }

        metrics.update(pkt_len, traffic_type, is_error=(
            (TCP in pkt and pkt[TCP].flags & 0x04) or 
            (ICMP in pkt and pkt[ICMP].type == 3)
        ))

        # Standard Threat Intel
        intel_alerts = analyze_threat(pkt, packet_info)
        
        # Deep Packet Inspection (DPI) & L7 Decoders
        dpi_alerts = inspect_packet_l7(pkt, packet_info)
        
        all_alerts = []
        if detected_alert: all_alerts.append(detected_alert)
        all_alerts.extend(intel_alerts)
        all_alerts.extend(dpi_alerts)

        for alert_obj in all_alerts:
            # Improved dedup logic - check last 60 seconds
            is_dup = False
            event_time_str = time.strftime("%H:%M:%S", time.localtime(now))
            
            # Create threat signature for deduplication
            threat_signature = f"{src_ip}:{alert_obj['title']}"
            
            # Check if this exact threat (same source + alert) was logged in the last 60 seconds
            recent_threats = threats[-50:]  # type: ignore
            for old in recent_threats:
                if old.get("src") == src_ip and old.get("alert") == alert_obj["title"]:
                    # Check if within 60 seconds
                    try:
                        old_time = time.strptime(old["timestamp"], "%H:%M:%S")
                        curr_time = time.strptime(event_time_str, "%H:%M:%S")
                        time_diff = abs((curr_time.tm_hour * 3600 + curr_time.tm_min * 60 + curr_time.tm_sec) - 
                                       (old_time.tm_hour * 3600 + old_time.tm_min * 60 + old_time.tm_sec))
                        if time_diff < 60:  # Within 60 seconds
                            is_dup = True
                            break
                    except ValueError:
                        # If time parsing fails, do exact match check
                        if old["timestamp"] == event_time_str:
                            is_dup = True
                            break

            if not is_dup:
                # Check if this threat has already been mitigated
                threat_signature = f"{src_ip}:{alert_obj['title']}"
                already_mitigated = mitigated_threats.get(threat_signature, False)
                
                # Auto Mitigation (only if not already mitigated)
                mitigated = already_mitigated
                if not already_mitigated and src_ip and src_ip not in CALCULATING_DEVICE_IPS and not is_sim_traffic:
                    mitigated = block_ip_firewall(src_ip)
                    if mitigated:
                        print(f"[AUTO-MITIGATION] IP {src_ip} blocked directly by Firewall.")
                        mitigated_threats[threat_signature] = True  # Mark as mitigated
                
                threats.append({
                    "timestamp": event_time_str,
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocol": traffic_type,
                    "alert": alert_obj["title"],
                    "metadata": alert_obj, # Store full object for UI
                    "mitigated": mitigated,
                    "mitre": map_to_mitre(alert_obj["title"], alert_obj.get("type", ""))
                })
    
    elif ARP in pkt:
        # Pass ARP for spoofing detection
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        
        intel_alerts = analyze_threat(pkt)
        for alert_obj in intel_alerts:
            event_time_str = time.strftime("%H:%M:%S", time.localtime(now))
            threats.append({
                "timestamp": event_time_str,
                "src": src_ip,
                "dst": dst_ip,
                "protocol": "ARP",
                "alert": alert_obj["title"],
                "metadata": alert_obj,
                "mitigated": False,
                "mitre": map_to_mitre(alert_obj["title"], alert_obj.get("type", ""))
            })
    else:
        # Handle non-IP/ARP traffic (Ethernet, etc.)
        protocols["Other"] += 1
        metrics.update(len(pkt), "Other")


def _capture_loop(interface=None):
    global _running

    while _running:
        sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            timeout=2  # 🔑 NON-BLOCKING
        )




def start_live_capture(interface=None):
    global _running, _capture_thread

    if _running:
        return

    reset_calculating_device_ips()

    # 🔑 AUTO-DETECT INTERFACE (Enhanced)
    if interface is None:
        try:
            # 1. Try to find the interface that routes to Google DNS (active internet connection)
            route = conf.route.route("8.8.8.8")
            interface = route[0]
            local_ip = route[2]
            set_calculating_device_ip(local_ip)
            print(f"[DEBUG] Main route interface: {interface}, Local IP: {local_ip}")
        except Exception as e:
            print(f"[DEBUG] Route detection failed: {e}")
            interface = None

        if not interface:
             print("[WARN] Route detection failed. Using Scapy default.")
             interface = conf.iface
             try:
                 local_ip = get_if_addr(interface)
                 set_calculating_device_ip(local_ip)
             except Exception:
                 pass
    else:
        # User provided a specific interface
        try:
            local_ip = get_if_addr(interface)
            set_calculating_device_ip(local_ip)
            print(f"[DEBUG] User interface: {interface}, Local IP: {local_ip}")
        except Exception:
            pass

        # 🔑 RESOLVE FRIENDLY NAME TO DEVICE NAME (Windows Fix)
        try:
            from scapy.arch.windows import get_windows_if_list
            win_list = get_windows_if_list()
            # Try to match the incoming 'interface' string (which is likely a friendly name like "Wi-Fi")
            # to the actual Scapy device name/GUID.
            for x in win_list:
                if x.get('name') == interface or x.get('description') == interface:
                    print(f"[DEBUG] Resolved '{interface}' to '{x.get('name')}' (GUID: {x.get('guid')})")
                    # Use the 'name' from the list which is what Scapy expects (often the GUID-like name or proper ID)
                    # Actually, for get_windows_if_list, 'name' is often the Friendly Name (e.g., 'Wi-Fi') in recent Scapy,
                    # but 'guid' or 'win_index' might be safer?
                    # Let's try to use the raw object or the best identifier. 
                    # Usually passing the dict 'x' works if supported, but let's pass x['name'] and hope Scapy resolves it.
                    # Wait, if x['name'] IS 'Wi-Fi', and we passed 'Wi-Fi', what's the diff?
                    # Sometimes Scapy needs the \Device\NPF_{...} string. 
                    # Let's look for 'pcap_name' if it exists, or verify with 'show_interfaces()' output logic.
                    pass
        except ImportError:
            pass


    print(f"[+] Capturing on interface: {interface}")

    _running = True
    global current_interface
    current_interface = interface
    metrics.reset()
    threats.clear()
    protocols.update({"TCP": 0, "UDP": 0, "Other": 0})
    
    # Reset all trackers for fresh analysis
    active_flows.clear()
    src_ip_counts.clear()
    ip_download_bytes.clear()
    ip_traffic.clear()
    scan_tracker.clear()
    auth_tracker.clear()
    mitigated_threats.clear()  # Reset mitigation tracking
    reset_threat_trackers()
    
    # Reset timing variables
    global last_dos_check, packet_rate, last_bandwidth_alert, last_packet_time
    last_dos_check = 0
    packet_rate = 0
    last_bandwidth_alert = 0
    last_packet_time = None

    _capture_thread = threading.Thread(
        target=_capture_loop,
        args=(interface,),
        daemon=True
    )
    _capture_thread.start()



def stop_live_capture():
    global _running, current_interface
    _running = False
    current_interface = None


def inject_test_threat(threat_type="dos", count=5):
    """
    Programmatically inject threats for testing purposes.
    This simulates threat detection without requiring actual malicious traffic.
    """
    global threats
    now = time.time()
    event_time_str = time.strftime("%H:%M:%S", time.localtime(now))
    
    if threat_type == "dos":
        # Inject multiple DOS simulation threats
        for i in range(count):
            threat = {
                "timestamp": event_time_str,
                "src": f"192.168.1.{100 + i}",  # Simulated attacker IPs
                "dst": "8.8.8.8",
                "protocol": "UDP",
                "alert": "Performance Simulation Test",
                "metadata": {
                    "title": "Performance Simulation Test",
                    "type": "Developer Test",
                    "cause": "High packet rate with developer simulation marker detected.",
                    "risk": "None - this is a controlled test for system capacity.",
                    "mitigation": "No action needed. You can stop the test via the sidebar."
                },
                "mitigated": False,
                "mitre": map_to_mitre("Performance Simulation Test", "Developer Test")
            }
            threats.append(threat)
            # Add a small delay to show different timestamps
            time.sleep(0.1)
    
    print(f"[TEST] Injected {count} test threats of type: {threat_type}")


def analyze_pcap(path):
    metrics.reset()
    threats.clear()
    active_flows.clear()
    src_ip_counts.clear()
    scan_tracker.clear()
    auth_tracker.clear()
    ip_download_bytes.clear()
    ip_traffic.clear()
    mitigated_threats.clear()  # Reset mitigation tracking
    reset_calculating_device_ips()
    reset_threat_trackers()
    protocols.update({"TCP": 0, "UDP": 0, "IP": 0, "ICMP": 0, "Other": 0})

    packets = rdpcap(path)
    for pkt in packets:
        # Pass packet timestamp to avoid messing up live metrics
        process_packet(pkt, timestamp=pkt.time)


def get_interfaces_list():
    import psutil
    try:
        from scapy.arch.windows import get_windows_if_list
        win_list = get_windows_if_list()
        
        # Get system traffic counters and stats
        try:
            io_counters = psutil.net_io_counters(pernic=True)
        except Exception:
            io_counters = {}
        
        try:
            iface_stats = psutil.net_if_stats()
        except Exception:
            iface_stats = {}
        
        # Get default route interface
        from scapy.all import conf
        default_iface_name = None
        try:
            route = conf.route.route("8.8.8.8")
            default_iface_name = route[0]
        except Exception:
            pass

        # Keywords to include: only WiFi, LAN/Ethernet, and physical Adapters
        include_keywords = [
            "Wi-Fi", "WiFi", "Wireless", "802.11",
            "Ethernet", "LAN", "Local Area",
            "Adaptor", "Adapter",
            "Realtek", "Intel", "Qualcomm", "Atheros", "Broadcom",
            "Gigabit", "Family Controller"
        ]
        # Targeted exclusion of software-defined/virtual noise
        exclude_keywords = [
            "Loopback", "VMware", "VirtualBox", "Pseudo", "Tunnel", "vEthernet", 
            "Hyper-V", "Host-Only", "TAP", "TUN", "Bridge", "Npcap", 
            "Internal", "Teredo", "WSL", "ISATAP", "IP-HTTPS"
        ]

        interfaces = []
        for x in win_list:
            name = x.get('name', 'Unknown')
            desc = x.get('description', '')
            guid = x.get('guid', '')
            
            # Combine name and description for filtering
            full_identity = f"{name} {desc}".lower()
            
            # 1. Must match at least one inclusion keyword (Physical markers)
            is_match = any(k.lower() in full_identity for k in include_keywords)
            # 2. Check if it matches exclusion keywords (Aggressive virtual blocks)
            is_excluded = any(k.lower() in full_identity for k in exclude_keywords)
            
            # ... existing exclusion refinements ...

            if not is_match or is_excluded:
                continue

            # Resolve traffic flow
            flow = 0
            if io_counters and name in io_counters: flow = io_counters[name].bytes_sent + io_counters[name].bytes_recv
            elif io_counters and desc in io_counters: flow = io_counters[desc].bytes_sent + io_counters[desc].bytes_recv
            
            # Resolve connection status
            is_connected = False
            speed = 0
            
            # psutil sometimes reports isup=True with speed==0 for disconnected
            if iface_stats and name in iface_stats:
                is_connected = iface_stats[name].isup
                speed = iface_stats[name].speed
            elif iface_stats and desc in iface_stats:
                is_connected = iface_stats[desc].isup
                speed = iface_stats[desc].speed

            # do **not** force a disconnect just because speed == 0 –
            # Bluetooth adapters and some Ethernet NICs report 0 until
            # they have an IP. we will verify with the address below.
            # if is_connected and speed == 0:
            #     is_connected = False

            # Verify with IP – must have a non‑APIPA, non‑0.0.0.0 address
            try:
                ip = get_if_addr(name)
                if not ip or ip == "0.0.0.0" or ip.startswith("169.254"):
                    is_connected = False
                else:
                    is_connected = True
                # if the adapter really is up it will override the earlier
                # psutil check, regardless of speed.
            except Exception:
                # leave whatever we got from psutil
                pass
            
            # Identify the primary interface (recommended)
            is_recommended = (name == default_iface_name or guid == default_iface_name or desc == default_iface_name)
            
            # If it's recommended, it MUST have a route, so it's connected
            if is_recommended: is_connected = True
                    
            interfaces.append({
                "name": name, 
                "description": desc, 
                "guid": guid,
                "flow": flow,
                "is_recommended": is_recommended,
                "is_connected": is_connected
            })
        
        return interfaces
    except Exception as e:
        print(f"[ERROR] Interface detection failed: {e}")
        from scapy.all import get_if_list
        return [{"name": x, "description": "Generic Interface", "guid": x, "flow": 0, "is_recommended": False, "is_connected": True} for x in get_if_list()]



def get_capture_status():
    # Return top 10 most recent flows to avoid bloating packet
    sorted_flows = sorted(list(active_flows))[-15:]  # type: ignore
    
    # Calculate Top IP Talkers (descending by bytes)
    top_talkers = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]  # type: ignore
    # Format for JSON: [{"ip": "...", "bytes": ...}, ...]
    top_talkers_fmt = [{"ip": ip, "bytes": b} for ip, b in top_talkers]

    # format suspicious ip list for JSON
    with _sip_lock:
        sip_list = [v for v in suspicious_ips.values()]

    return {
        "running": _running,
        "last_packet_time": last_packet_time,
        "packet_rate": metrics.packet_rate_live() if _running else 0,
        "bandwidth": metrics.bandwidth() if _running else 0,
        "flow_count": len(active_flows) if _running else 0,
        "flows": sorted_flows,
        "top_talkers": top_talkers_fmt,
        "suspicious_ips": sip_list,
        "current_interface": current_interface
    }
