from scapy.all import rdpcap, IP, TCP, UDP, ICMP
# use additional layers for application protocol detection
from scapy.layers.dns import DNS
from analyzer.metrics import Metrics
from analyzer.threat_intel import ThreatIntel

def analyze_pcap(path):
    metrics = Metrics()
    threats = ThreatIntel()

    packets = rdpcap(path)
    for pkt in packets:
        if IP in pkt:
            proto = "OTHER"
            is_error = False

            # network layer
            if TCP in pkt:
                proto = "TCP"
                if pkt[TCP].flags & 0x04:
                    is_error = True
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
                if pkt[ICMP].type == 3:
                    is_error = True

            # application layer classification based on ports and layers
            # prefer explicit layers (DNS) over port heuristics
            if DNS in pkt:
                proto = "DNS"
            elif TCP in pkt or UDP in pkt:
                # fallback to port numbers for common services (explicit equality)
                dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                # for application-level protocols we only examine destination port
                if dport == 80:
                    proto = "HTTP"
                elif dport == 443:
                    proto = "HTTPS"
                    # further distinguish pure TLS handshakes (port 443 may carry HTTP or raw TLS)
                    try:
                        raw = bytes(pkt[TCP].payload)
                        if raw.startswith(b"\x16\x03"):
                            proto = "TLS"
                    except Exception:
                        pass
                elif dport in (20, 21):
                    proto = "FTP"
                elif dport == 22:
                    proto = "SSH"
                elif dport == 25:
                    proto = "SMTP"
                elif dport == 53:
                    # if DNS already caught this will not be reached, but ensure
                    proto = "DNS"

            metrics.update(len(pkt), proto, is_error=is_error)
            threats.inspect(pkt)

    return {
        "metrics": metrics.summary(),
        "threats": threats.report()
    }
