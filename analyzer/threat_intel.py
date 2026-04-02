# analyzer/threat_intel.py

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
import time

MALICIOUS_IPS = {
    "185.220.101.1",
    "45.33.32.156",
    "91.214.124.143",
    "64.233.191.255" # Example
}

# Phishing Keywords for DNS/HTTP
PHISHING_KEYWORDS = ["secure", "login", "verify", "account", "update", "bank", "paypal", "signin", "support", "office365", "microsoft"]

from typing import Dict, Set

# ARP tracking for spoofing detection
# {ip: mac}
arp_cache: Dict[str, str] = {}
# Threat Stats for stateful detection
syn_tracker: Dict[str, int] = {} # {src_ip: count}
# track ports seen per source for port scan detection
port_scan_tracker: Dict[str, Set[int]] = {}  # {src_ip: set(dst_ports)}
# track potential botnet C2 comms: external dst -> set(src_ips)
botnet_tracker: Dict[str, Set[str]] = {}  # {dst_ip: set(src_ips)}
# track intranet lateral movement attempts
lateral_movement_tracker: Dict[str, int] = {}  # {src_ip: {dst_ip: count}} for lateral movement

# IP of the machine running the analyzer to exclude its own traffic from threat detection
CALCULATING_DEVICE_IPS: Set[str] = set(["127.0.0.1", "::1"])

def set_calculating_device_ip(ip):
    if ip:
        CALCULATING_DEVICE_IPS.add(ip)

def reset_calculating_device_ips():
    CALCULATING_DEVICE_IPS.clear()
    CALCULATING_DEVICE_IPS.add("127.0.0.1")
    CALCULATING_DEVICE_IPS.add("::1")

def reset_threat_trackers():
    """Reset all threat detection trackers for fresh analysis"""
    global arp_cache, syn_tracker, port_scan_tracker, botnet_tracker, lateral_movement_tracker
    arp_cache.clear()
    syn_tracker.clear()
    port_scan_tracker.clear()
    botnet_tracker.clear()
    lateral_movement_tracker.clear()

def is_internal(ip):
    # Standard RFC1918 + APIPA + Localhost
    if not ip or not isinstance(ip, str): return False
    parts = ip.split('.')
    if len(parts) != 4: return ip == "127.0.0.1" or ip == "::1"
    
    try:
        p1, p2 = int(parts[0]), int(parts[1])
        return (p1 == 10 or 
                (p1 == 172 and 16 <= p2 <= 31) or 
                (p1 == 192 and p2 == 168) or
                (p1 == 169 and p2 == 254) or
                p1 == 127)
    except (ValueError, IndexError):
        return False

def analyze_threat(pkt, packet_info=None):
    """
    Advanced threat analysis with Intranet and Cyber Attack focus.
    Returns list of dicts with title, type, cause, risk, mitigation (dict with summary and steps).
    """
    alerts = []
    
    # Identify Source IP
    src_ip = None
    if IP in pkt:
        src_ip = pkt[IP].src
    elif ARP in pkt:
        src_ip = pkt[ARP].psrc
        
    # Note: We now detect ALL threats on the network, including those involving the calculating device
    # This ensures threats to/from the network host are properly identified

    # 1. ARP Spoofing (Intranet)
    if ARP in pkt and pkt[ARP].op in [1, 2]:
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        if src_ip in arp_cache and arp_cache[src_ip] != src_mac:
            alerts.append({
                "title": "ARP Poisoning / Spoofing",
                "type": "Network Layer Attack",
                "cause": f"MAC address mismatch for {src_ip} (Old: {arp_cache[src_ip]}, New: {src_mac})",
                "risk": "Man-in-the-Middle (MITM), traffic sniffing, account takeover.",
                "mitigation": {
                    "summary": "Enable 'Dynamic ARP Inspection' (DAI) on switches and use static ARP for gateways.",
                    "steps": [
                        "Contact your network administrator or IT team to enable Dynamic ARP Inspection (DAI) on your network switches. DAI is a security feature that prevents attackers from impersonating other devices on your local network by validating IP-to-MAC address mappings.",
                        "Configure static ARP entries for critical network devices like your router or gateway. This means manually setting the IP address to MAC address mapping so it cannot be changed by malicious devices.",
                        "Set up monitoring tools to watch for unusual ARP traffic patterns, such as multiple devices claiming the same IP address.",
                        "Install and configure ARP spoofing detection software or use network monitoring tools that can alert you to suspicious ARP activity."
                    ]
                },
                "direct_action": {"type": "block_ip", "ip": src_ip}
            })
        arp_cache[src_ip] = src_mac

    # 2. IP & Cyber Attack Logic
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        is_src_int = is_internal(src)
        is_dst_int = is_internal(dst)
        
        # External Malicious IPs
        if not is_src_int and src in MALICIOUS_IPS:
            alerts.append({
                "title": "Blacklisted Host Connection",
                "type": "Cyber Attack / C2",
                "cause": f"Traffic detected from known malicious IP: {src}",
                "risk": "Data exfiltration, malware injection, or botnet communication.",
                "mitigation": {
                    "summary": "Immediately block this IP on the firewall and scan local hosts for infections.",
                    "steps": [
                        "Access your firewall or router's control panel and add the malicious IP address to the blocked list. This prevents any further communication with that IP.",
                        "Run a full system scan on all computers and devices connected to your network using reputable antivirus software to check for malware or viruses.",
                        "Review your firewall logs and network traffic history to identify any other suspicious IP addresses that may have communicated with your network.",
                        "Update your threat intelligence feeds and security software to ensure you have the latest information about known malicious IPs and threats."
                    ]
                },
                "direct_action": {"type": "block_ip", "ip": src}
            })
        # per-destination botnet behaviour: many internal hosts contacting same external IP
        dst = pkt[IP].dst if IP in pkt else None
        # track connections to external hosts regardless of source internal/external
        if dst and not is_dst_int:
            botnet_tracker.setdefault(dst, set()).add(src)
            if len(botnet_tracker[dst]) > 20:
                alerts.append({
                    "title": "Potential Botnet Command/Control",
                    "type": "Botnet Traffic",
                    "cause": f"Multiple hosts contacting external IP {dst}",
                    "risk": "Compromised machines participating in botnet activity.",
                    "mitigation": {
                        "summary": "Investigate infected machines and block the C2 server.",
                        "steps": [
                            "Identify which computers or devices on your network are connecting to the suspicious external IP. Check device logs or use network monitoring tools to find the infected machines.",
                            "Isolate the infected devices from your network by disconnecting them or placing them on a separate network segment to prevent further spread of the infection.",
                            "Block the command and control (C2) server IP address on your firewall to prevent any further communication between infected devices and the botnet controller.",
                            "Remove the malware from infected systems using antivirus software, and change all passwords on affected devices and accounts."
                        ]
                    }
                })
                botnet_tracker[dst].clear()

        # 3. SYN Flood Detection (Cyber Attack)
        if TCP in pkt and pkt[TCP].flags == 0x02: # SYN only
            syn_tracker[src] = syn_tracker.get(src, 0) + 1
            if syn_tracker[src] > 50:
                alerts.append({
                    "title": "TCP SYN Flood Attack",
                    "type": "DoS / Cyber Attack",
                    "cause": f"Abnormally high rate of SYN packets from {src}",
                    "risk": "Service unavailability, server crash due to half-open connection exhaustion.",
                    "mitigation": {
                        "summary": "Enable SYN Cookies on the server and use cloud-based DDoS protection.",
                        "steps": [
                            "Enable SYN Cookies on your server or contact your hosting provider to enable this feature. SYN Cookies help prevent SYN flood attacks by not allocating resources until the connection is fully established.",
                            "Implement rate limiting on your firewall or server to restrict the number of incoming connection attempts from a single IP address within a time period.",
                            "Use a cloud-based DDoS protection service (like Cloudflare, Akamai, or AWS Shield) to filter out malicious traffic before it reaches your network.",
                            "Monitor your server's performance and connection logs during the attack to understand the impact and adjust your defenses accordingly."
                        ]
                    }
                })
                syn_tracker[src] = 0 # Reset after alert
        # 3b. Port scan detection (many distinct destination ports in a short time)
        if (TCP in pkt or UDP in pkt) and IP in pkt:
            proto_layer = TCP if TCP in pkt else UDP
            dst_port = pkt[proto_layer].dport
            port_scan_tracker.setdefault(src, set()).add(dst_port)
            if len(port_scan_tracker[src]) > 100:
                alerts.append({
                    "title": "Port Scan Detected",
                    "type": "Reconnaissance",
                    "cause": f"Source {src} has probed {len(port_scan_tracker[src])} unique ports",
                    "risk": "Attackers gathering information on open services.",
                    "mitigation": {
                        "summary": "Rate-limit and block scanning hosts; deploy IDS/IPS.",
                        "steps": [
                            "Configure your firewall to limit the rate of incoming connections from the scanning IP address, preventing it from quickly probing many ports.",
                            "Add the scanning IP address to your firewall's block list to prevent any further access attempts from that source.",
                            "Install and configure an Intrusion Detection System (IDS) or Intrusion Prevention System (IPS) to automatically detect and block port scanning activity.",
                            "Review the scan logs to understand what ports were probed and ensure those services are properly secured or disabled if not needed."
                        ]
                    },
                    "direct_action": {"type": "block_ip", "ip": src}
                })
                port_scan_tracker[src].clear()

        # 4. ICMP Anomaly (Ping of Death / Flood)
        if ICMP in pkt:
            if len(pkt) > 1500:
                alerts.append({
                    "title": "Ping of Death (Oversized ICMP)",
                    "type": "Protocol Exploit",
                    "cause": f"ICMP packet size ({len(pkt)}) exceeds standard MTU buffers.",
                    "risk": "Target system crash or memory corruption during reassembly.",
                    "mitigation": {
                        "summary": "Filter ICMP traffic at the edge and drop fragmented ICMP packets.",
                        "steps": [
                            "Configure your firewall to filter out oversized ICMP (ping) packets that exceed normal size limits, as these can cause system crashes.",
                            "Set your firewall rules to drop all fragmented ICMP packets, which are often used in ping of death attacks.",
                            "Monitor your network for unusual ICMP traffic patterns and set up alerts for suspicious activity.",
                            "Ensure all systems and devices on your network have the latest security patches to protect against known vulnerabilities that ping of death exploits."
                        ]
                    }
                })

    # 5. Phishing / DNS Security & tunneling/exfiltration heuristics
    if DNS in pkt and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').lower()
        # phishing keywords
        for kw in PHISHING_KEYWORDS:
            if kw in qname and not any(ok in qname for ok in ["google.com", "microsoft.com", "apple.com"]):
                alerts.append({
                    "title": "Potential Phishing Domain Access",
                    "type": "Social Engineering",
                    "cause": f"Suspicious keyword '{kw}' found in DNS query: {qname}",
                    "risk": "Credential theft, user data compromise.",
                    "mitigation": {
                        "summary": "Block domain via DNS filter and educate users on phishing links.",
                        "steps": [
                            "Configure your DNS filtering service or firewall to block access to the suspicious domain, preventing users from visiting potentially harmful websites.",
                            "Educate all users about phishing awareness, including how to recognize suspicious emails, links, and websites that might steal login credentials.",
                            "Check user accounts and systems for any signs of compromise, such as unauthorized access or unusual activity.",
                            "Monitor network traffic for access to similar suspicious domains and update your security policies accordingly."
                        ]
                    }
                })
                break
        # DNS tunneling detection: very long or deeply nested domain names
        if len(qname) > 60 or len(qname.split('.')) > 6:
            alerts.append({
                "title": "Possible DNS Tunneling",
                "type": "Data Exfiltration",
                "cause": f"Unusually long DNS query name: {qname}",
                "risk": "Covert channel for data exfiltration or command/control.",
                "mitigation": {
                    "summary": "Monitor DNS for anomalies and restrict external DNS to trusted resolvers.",
                    "steps": [
                        "Set up monitoring tools to watch for unusual DNS query patterns, such as very long domain names or queries that don't follow normal patterns.",
                        "Configure your network to only use trusted DNS servers (like those provided by your ISP or Google Public DNS) and block access to unknown DNS servers.",
                        "Implement DNS traffic analysis tools that can detect and alert on potential tunneling attempts.",
                        "Block suspicious DNS traffic at your firewall and review DNS logs regularly for signs of data exfiltration."
                    ]
                }
            })
        # simple data exfiltration via TXT records in answers
    if DNS in pkt and getattr(pkt, 'ancount', 0) and pkt[DNS].ancount > 0:
        try:
            for i in range(pkt[DNS].ancount):
                ans = pkt[DNS].an[i]
                if ans.type == 16 and hasattr(ans, 'rdata'):
                    # rdata may be list (for TXT) or bytes/string; normalize
                    data = ans.rdata
                    if isinstance(data, (list, tuple)):
                        # join all parts
                        try:
                            data = b"".join(x.encode() if isinstance(x, str) else x for x in data)
                        except Exception:
                            data = str(data)
                    if isinstance(data, str):
                        length = len(data)
                    else:
                        try:
                            length = len(data)
                        except Exception:
                            length = 0
                    if length > 100:
                        alerts.append({
                            "title": "Potential Data Exfiltration via DNS",
                            "type": "Data Exfiltration",
                            "cause": f"Large TXT DNS answer observed ({length} bytes)",
                            "risk": "Sensitive information leaving the network covertly.",
                            "mitigation": {
                                "summary": "Inspect DNS payloads and block suspicious domains.",
                                "steps": [
                                    "Use DNS inspection tools to examine the content of DNS responses, particularly TXT records, for any encoded or hidden data.",
                                    "Block access to domains that are found to be involved in data exfiltration attempts using your DNS filtering or firewall rules.",
                                    "Set up continuous monitoring of outbound DNS traffic to detect unusual patterns or large data transfers through DNS.",
                                    "Implement data loss prevention (DLP) solutions that can detect and prevent sensitive information from being sent through DNS channels."
                                ]
                            }
                        })
        except Exception:
            pass

    # 6. Insecure Protocols
    if TCP in pkt or UDP in pkt:
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        if dport == 23:
            alerts.append({
                "title": "Insecure Cleartext Protocol (Telnet)",
                "type": "Security Configuration",
                "cause": f"Telnet traffic detected on port 23.",
                "risk": "Usernames and passwords captured in plain text by anyone on the wire.",
                "mitigation": {
                    "summary": "Disable Telnet and use SSH for all remote management.",
                    "steps": [
                        "Disable the Telnet service on all network devices and servers, as it sends all data including passwords in plain text that can be easily intercepted.",
                        "Enable Secure Shell (SSH) on all devices that require remote management, as SSH encrypts all communication including login credentials.",
                        "Update your network management policies to require SSH for all remote access and prohibit the use of Telnet.",
                        "Review and audit all remote access logs to ensure no unauthorized access has occurred through Telnet connections."
                    ]
                }
            })
        if dport == 21:
            alerts.append({
                "title": "Insecure Cleartext Protocol (FTP)",
                "type": "Security Configuration",
                "cause": f"FTP traffic detected on port 21.",
                "risk": "Login credentials and file contents exposed in cleartext.",
                "mitigation": {
                    "summary": "Switch to SFTP (SSH File Transfer Protocol) or FTPS.",
                    "steps": [
                        "Disable the standard FTP service on your server, as it transmits files and login credentials without encryption.",
                        "Implement SFTP (Secure File Transfer Protocol) or FTPS (FTP Secure) which encrypt both the data and commands during file transfers.",
                        "Update all FTP client configurations and user instructions to use the secure SFTP or FTPS protocols instead.",
                        "Train users on the importance of using encrypted file transfer methods and provide guidance on configuring secure connections."
                    ]
                }
            })

    # 7. Intranet Lateral Movement Threats
    if IP in pkt and is_internal(src) and is_internal(dst):
        # Lateral movement between internal hosts
        
        # 7a. Internal port scanning (reconnaissance for lateral movement)
        if (TCP in pkt or UDP in pkt):
            proto_layer = TCP if TCP in pkt else UDP
            dst_port = pkt[proto_layer].dport
            
            # Track internal scans separately
            scan_key = f"{src}_internal"
            port_scan_tracker.setdefault(scan_key, set()).add(dst_port)
            
            if len(port_scan_tracker[scan_key]) > 20:  # Lower threshold for internal scans
                alerts.append({
                    "title": "Intranet Lateral Movement: Port Scanning Detected",
                    "type": "Intranet Lateral Movement - Reconnaissance",
                    "cause": f"Internal device {src} has probed {len(port_scan_tracker[scan_key])} unique ports on {dst}, indicating reconnaissance for vulnerability exploitation.",
                    "risk": "Compromised internal device attempting to move laterally through the network to other systems.",
                    "mitigation": {
                        "summary": "Isolate the suspicious internal device and investigate for compromise.",
                        "steps": [
                            "Immediately disconnect the device at {src} from the network or place it in a quarantine VLAN (isolated network segment).",
                            "Scan the suspicious device for malware, rootkits, and unauthorized access using antivirus software from a clean machine.",
                            "Change all passwords on the affected device and reset credentials for any services it can access.",
                            "Review user activity logs and system access logs on the compromised device to identify when it was compromised and what other systems it accessed.",
                            "Restore the device from a clean backup or perform a fresh operating system installation.",
                            "Implement microsegmentation on your network so devices cannot freely scan and communicate with all other systems."
                        ]
                    }
                })
                port_scan_tracker[scan_key].clear()
        
        # 7b. RDP/SSH brute force from internal device (lateral movement via credential attack)
        if TCP in pkt:
            dport = pkt[TCP].dport
            if dport in [22, 3389]:  # SSH or RDP
                auth_key = f"{src}_to_{dst}_{dport}"
                lateral_movement_tracker.setdefault(auth_key, 0)
                lateral_movement_tracker[auth_key] += 1
                # Alert if many connection attempts in short time
                if lateral_movement_tracker[auth_key] > 30:
                    proto_name = "SSH" if dport == 22 else "RDP"
                    alerts.append({
                        "title": f"Intranet Lateral Movement: {proto_name} Brute Force Attack",
                        "type": "Intranet Lateral Movement - Credential Attack",
                        "cause": f"Internal device {src} is performing a brute force attack on {proto_name} (port {dport}) on internal host {dst}. This indicates lateral movement attempts.",
                        "risk": "Attacker attempting to gain unauthorized access to other internal systems using compromised or weak credentials.",
                        "mitigation": {
                            "summary": "Isolate the attacking device and implement strong authentication controls.",
                            "steps": [
                                "Immediately isolate the internal device at {src} from the network to prevent further attacks on other systems.",
                                "Check all systems for unauthorized access from {src} by reviewing authentication logs and failed login attempts.",
                                "On the target system {dst}, change all user passwords immediately, especially administrator and service accounts.",
                                "Implement rate limiting and account lockout policies to automatically block brute force attempts after a certain number of failed logins.",
                                "Enable multi-factor authentication (MFA) on all sensitive systems to prevent unauthorized access even with compromised credentials.",
                                "Scan the source device {src} for malware and rootkits that may be orchestrating the attack."
                            ]
                        },
                        "direct_action": {"type": "block_ip", "ip": src}
                    })
                    lateral_movement_tracker[auth_key] = 0
        
        # 7c. SMB/NetBIOS activity for lateral movement (Windows environments)
        if TCP in pkt or UDP in pkt:
            dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            if dport in [135, 139, 445]:  # SMB/NetBIOS ports
                # Track SMB activity from internal source to internal destination
                smb_key = f"{src}_to_{dst}_smb"
                lateral_movement_tracker.setdefault(smb_key, 0)
                lateral_movement_tracker[smb_key] += 1
                
                if lateral_movement_tracker[smb_key] > 50:  # Unusual SMB activity
                    alerts.append({
                        "title": "Intranet Lateral Movement: Suspicious SMB Activity",
                        "type": "Intranet Lateral Movement - Windows Lateral Moves",
                        "cause": f"Internal device {src} is showing unusually high SMB/Windows file sharing traffic to {dst}, suggesting potential lateral movement or data exfiltration.",
                        "risk": "Compromised Windows device attempting to access and exploit other Windows systems on the network.",
                        "mitigation": {
                            "summary": "Restrict SMB access and implement Windows security hardening.",
                            "steps": [
                                "Disable SMB v1 protocol on all systems, as it has critical vulnerabilities. Use SMB v3 or higher instead.",
                                "Configure Windows Firewall rules to restrict SMB access (ports 135, 139, 445) between internal network segments based on business needs.",
                                "Isolate the suspicious device {src} and scan it for malware, especially ransomware and Windows-specific malware.",
                                "Implement Active Directory hardening: disable credential caching, enable Kerberos signing, and require strong credentials.",
                                "Monitor all SMB connections using Windows Event Viewer and security information and event management (SIEM) tools.",
                                "Consider implementing network microsegmentation using firewalls or virtual network segments to limit lateral movement."
                            ]
                        },
                        "direct_action": {"type": "block_ip", "ip": src}
                    })
                    lateral_movement_tracker[smb_key] = 0

    # 8. Threats targeting the network host
    if IP in pkt:
        dst = pkt[IP].dst
        if dst in CALCULATING_DEVICE_IPS:
            # Traffic targeting the calculating device
            if TCP in pkt or UDP in pkt:
                dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                # Sensitive ports that should not be exposed externally
                sensitive_ports = {22, 23, 21, 3389, 445, 135, 139, 1433, 3306, 5432}  # SSH, Telnet, FTP, RDP, SMB, etc.
                if dport in sensitive_ports and not is_internal(src_ip):
                    alerts.append({
                        "title": "External Access to Sensitive Port on Host",
                        "type": "Host Security Threat",
                        "cause": f"External IP {src_ip} accessed sensitive port {dport} on the network host.",
                        "risk": "Potential unauthorized access, data breach, or malware infection.",
                        "mitigation": {
                            "summary": "Restrict access to sensitive ports and monitor for unauthorized connections.",
                            "steps": [
                                "Configure your firewall to only allow access to sensitive ports from trusted internal IPs.",
                                "Disable unnecessary services and ports on the host.",
                                "Implement network segmentation to isolate the host from external threats.",
                                "Monitor access logs and set up alerts for suspicious connections to sensitive ports."
                            ]
                        }
                    })
            # Check for potential DoS targeting the host
            if ICMP in pkt and len(pkt) > 1000:  # Large ICMP packets
                if not is_internal(src_ip):
                    alerts.append({
                        "title": "Large ICMP Packet to Host",
                        "type": "Potential DoS Attack on Host",
                        "cause": f"Large ICMP packet ({len(pkt)} bytes) received from external IP {src_ip} targeting the host.",
                        "risk": "Possible ping flood or other ICMP-based attack attempting to overwhelm the host.",
                        "mitigation": {
                            "summary": "Filter ICMP traffic and monitor for flooding patterns.",
                            "steps": [
                                "Configure rate limiting for ICMP packets on your firewall.",
                                "Block unnecessary ICMP types while allowing essential ones like echo reply.",
                                "Monitor ICMP traffic patterns and set up alerts for unusual volumes.",
                                "Consider using a DDoS protection service if attacks persist."
                            ]
                        }
                    })

    return alerts

class ThreatIntel:
    """Legacy class for PCAP analyzer compatibility"""
    def __init__(self):
        self.alerts = []

    def inspect(self, pkt):
        res = analyze_threat(pkt)
        self.alerts.extend(res)

    def report(self):
        # return a de-duplicated list of alerts while preserving order
        seen = set()
        unique = []
        for alert in self.alerts:
            try:
                key = tuple(sorted(alert.items()))
            except Exception:
                key = str(alert)
            if key not in seen:
                seen.add(key)
                unique.append(alert)
        return unique
