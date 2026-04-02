import subprocess
import re

blocked_ips = set()

def block_ip_firewall(ip):
    if not ip or not isinstance(ip, str):
        return False
    
    ip = ip.strip()
    if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
        return False
        
    if ip in blocked_ips:
        return True # already blocked
        
    try:
        rule_name = f"NetFalcon_Block_{ip.replace('.', '_')}"
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}_IN",
            "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], check=True, capture_output=True)
        
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}_OUT",
            "dir=out", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], check=True, capture_output=True)
        
        blocked_ips.add(ip)
        print(f"[FIREWALL] Auto-Mitigation: Blocked IP {ip}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[FIREWALL ERROR] Failed to block {ip}: {e.stderr}")
        blocked_ips.add(ip) # Track it anyway
        return False
    except FileNotFoundError:
        print(f"[FIREWALL WARNING] netsh command not found. Cannot block {ip}")
        blocked_ips.add(ip)
        return False

def unblock_ip_firewall(ip):
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    try:
        rule_name = f"NetFalcon_Block_{ip.replace('.', '_')}"
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"], capture_output=True)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"], capture_output=True)
        blocked_ips.discard(ip)
        print(f"[FIREWALL] Unblocked IP {ip}")
        return True
    except Exception as e:
        print(f"[FIREWALL ERROR] Failed to unblock {ip}: {e}")
        blocked_ips.discard(ip)
        return False

def get_blocked_ips():
    return list(blocked_ips)
