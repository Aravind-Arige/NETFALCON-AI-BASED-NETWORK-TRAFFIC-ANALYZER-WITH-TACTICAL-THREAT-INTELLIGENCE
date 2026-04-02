import analyzer.engine as eng
from scapy.all import IP,TCP

pkt = IP(src='1.2.3.4', dst='5.6.7.8')/TCP(dport=80, flags=0x02)
for i in range(120):
    eng.process_packet(pkt, timestamp=str(i))

print('suspicious:', eng.suspicious_ips)
print('threats len', len(eng.threats))
