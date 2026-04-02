import re
import math
import hashlib

def calculate_entropy(data):
    """Calculate Shannon entropy of a string, useful for detecting DGA or DNS tunneling."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_ja3_fingerprint(client_hello_bytes):
    """
    Very basic JA3 hashing pseudo-implementation.
    In a real implementation, this extracts SSLVersion, Cipher, Extensions, 
    EllipticCurves, and EllipticCurvePointFormats.
    For this module, we will compute a hash over the raw bytes of the ClientHello.
    """
    return hashlib.md5(client_hello_bytes).hexdigest()

def inspect_packet_l7(pkt, packet_info):
    """
    Deep Packet Inspection (DPI) & Protocol Decoder.
    Returns a list of alerts if malicious Layer 7 activity is found.
    """
    alerts = []
    
    try:
        from scapy.all import DNSQR, DNS, TCP, UDP, Raw
    except ImportError:
        return alerts

    src_ip = packet_info.get("src_ip", "")
    dst_port = packet_info.get("dst_port", 0)

    # 1. DNS Analysis & Tunneling Detection
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname
        if qname:
            domain = qname.decode("utf-8", errors="ignore").lower()
            # Entropy analysis for DNS Tunneling or DGA (Domain Generation Algorithm)
            # Normal domains usually have an entropy < 4.0. Hex/Base64 strings have high entropy.
            domain_core = domain.replace('.com.', '').replace('.net.', '').replace('.org.', '').replace('.', '')
            entropy = calculate_entropy(domain_core)
            
            if entropy > 4.5 and len(domain_core) > 20:
                alerts.append({
                    "title": "DNS Tunneling / DGA Detected",
                    "type": "C2 Communications",
                    "cause": f"High entropy ({entropy:.2f}) query for domain: {domain}",
                    "risk": "Data exfiltration via DNS or malware beaconing.",
                    "mitigation": "Block the domain and isolate the host for forensic analysis."
                })
            
            # Known Bad DNS
            if "mining" in domain or "monero" in domain:
                alerts.append({
                    "title": "Crypto-Mining DNS Query",
                    "type": "Resource Hijacking",
                    "cause": f"Query to known cryptojacking pool: {domain}",
                    "risk": "Compute resources are being consumed by unauthorized coin miners.",
                    "mitigation": "Quarantine the host and remove malware."
                })

    # 2. HTTP Analysis
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load
        
        # Check if HTTP
        if dst_port in [80, 8080] or payload.startswith(b"GET ") or payload.startswith(b"POST "):
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Simple User-Agent baseline anomaly (flagging empty, generic python, curl, default nmap)
            ua_match = re.search(r"User-Agent:\s*(.*)\r\n", payload_str)
            if ua_match:
                ua = ua_match.group(1).strip()
                suspicious_uas = ["curl", "python-requests", "nmap script engine", "masscan", "sqlmap", "nikto"]
                if any(bad_ua in ua.lower() for bad_ua in suspicious_uas):
                    alerts.append({
                        "title": "Suspicious HTTP User-Agent",
                        "type": "Automated Recon/Exploitation",
                        "cause": f"Client utilized unusual User-Agent: '{ua}'",
                        "risk": "Automated tools or scripts enumerating or attacking the server.",
                        "mitigation": "Implement WAF rules to block non-standard User-Agents."
                    })
                    
            # Cleartext Credentials / Passwords in URL or Body
            if "password=" in payload_str.lower() or "passwd=" in payload_str.lower():
                alerts.append({
                    "title": "Cleartext Credentials Exposed",
                    "type": "Data Leak",
                    "cause": "HTTP traffic contains 'password=' over an unencrypted channel.",
                    "risk": "Credentials can be intercepted by anyone on the network.",
                    "mitigation": "Enforce HTTPS/TLS for all authentications."
                })

    # 3. TLS / HTTPS JA3 Fingerprinting
    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and dst_port == 443:
        payload = pkt[Raw].load
        # Quick check for TLS Handshake Record (0x16) and Client Hello (0x01)
        if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
            ja3_hash = calculate_ja3_fingerprint(payload)
            # In a real engine, we check the hash against abuse.ch JA3 lists.
            # Here we just mock a known malicious signature for demonstration.
            malicious_ja3_signatures = [
                "a0e9f5d64349fb13191bc781f81f42e1", # Trickbot / Emotet generic Mock
            ]
            if ja3_hash in malicious_ja3_signatures:
                 alerts.append({
                    "title": "Malicious TLS JA3 Fingerprint",
                    "type": "C2 Beacon",
                    "cause": f"TLS ClientHello matches known malware profile (JA3: {ja3_hash})",
                    "risk": "System likely infected with active remote-access trojan.",
                    "mitigation": "Immediately isolate host and deploy memory forensics."
                })

    # 4. SMB Lateral Movement Analysis
    if pkt.haslayer(TCP) and pkt.haslayer(Raw) and dst_port == 445:
        payload = pkt[Raw].load
        # SMB Header (0xFF 'S' 'M' 'B' or \xfeSMB for SMBv2/3)
        if payload.startswith(b'\xffSMB') or payload.startswith(b'\xfeSMB'):
            payload_str = payload.decode('ascii', errors='ignore')
            
            # Common ransomware / Pass-the-hash indicators
            # (In reality, SMB needs complex parsing of tree connections/IPC$)
            if "IPC$" in payload_str or "ADMIN$" in payload_str or "C$" in payload_str:
                alerts.append({
                    "title": "Suspicious SMB Admin Share Access",
                    "type": "Lateral Movement",
                    "cause": "Access attempt to administrative hidden shares (IPC$/ADMIN$/C$).",
                    "risk": "Attacker may be attempting Pass-The-Hash or remote service execution (PsExec).",
                    "mitigation": "Restrict SMB traffic between workstations and monitor authentication logs."
                })

    return alerts
