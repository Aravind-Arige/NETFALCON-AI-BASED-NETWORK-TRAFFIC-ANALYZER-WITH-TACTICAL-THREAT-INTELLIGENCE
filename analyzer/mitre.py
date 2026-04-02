# analyzer/mitre.py
from typing import Dict, Any

def map_to_mitre(alert_title, alert_type=""):
    """
    Maps an alert title/type to a MITRE ATT&CK tactic, technique, and kill chain stage.
    Stage: 1 (Recon), 2 (Initial Access/Execution), 3 (Persistence/PrivEsc/Evasion), 
           4 (Lateral Movement/C2), 5 (Exfiltration/Impact)
    """
    title = str(alert_title).lower()
    typ = str(alert_type).lower()
    combined = f"{title} {typ}"

    if "port scan" in combined or "recon" in combined or "scan" in combined:
        return {
            "tactic": "Reconnaissance",
            "technique": "Active Scanning",
            "id": "T1595",
            "stage": 1,
            "color": "#fbbf24" # yellow
        }
    elif "brute force" in combined or "access" in combined:
        return {
            "tactic": "Credential Access",
            "technique": "Brute Force",
            "id": "T1110",
            "stage": 2,
            "color": "#fb923c" # orange
        }
    elif "lateral" in combined or "intranet" in combined:
        return {
            "tactic": "Lateral Movement",
            "technique": "Exploitation of Remote Services",
            "id": "T1210",
            "stage": 4,
            "color": "#f87171" # light red
        }
    elif "data exfiltration" in combined or "massive data" in combined or "hoarding" in combined:
        return {
            "tactic": "Exfiltration",
            "technique": "Automated Exfiltration",
            "id": "T1020",
            "stage": 5,
            "color": "#ef4444" # red
        }
    elif "dos" in combined or "denial of service" in combined or "flood" in combined or "amp" in combined:
        return {
            "tactic": "Impact",
            "technique": "Network Denial of Service",
            "id": "T1498",
            "stage": 5,
            "color": "#dc2626" # dark red
        }
    elif "arp" in combined or "spoof" in combined or "poison" in combined:
        return {
            "tactic": "Credential Access / Discovery",
            "technique": "Network Sniffing",
            "id": "T1040",
            "stage": 2,
            "color": "#f97316" # orange
        }
    elif "beacon" in combined or "c2" in combined or "heartbeat" in combined:
        return {
            "tactic": "Command and Control",
            "technique": "Web Service / Application Layer Protocol",
            "id": "T1102 / T1071",
            "stage": 4,
            "color": "#ec4899" # pink
        }
    else:
        # Default fallback
        return {
            "tactic": "Initial Access / Unknown",
            "technique": "Exploit Public-Facing Application",
            "id": "T1190",
            "stage": 2,
            "color": "#9ca3af" # gray
        }

def group_threats_into_campaigns(threat_list):
    """
    Groups a list of threat dictionaries into campaigns keyed by attacker IP.
    """
    campaigns: Dict[str, Dict[str, Any]] = {}
    
    for t in threat_list:
        src = t.get("src")
        # Ignore systemic or developer simulation generic sources if needed
        if not src or src == "SYSTEM":
            continue
            
        if src not in campaigns:
            campaigns[src] = {
                "attacker_ip": src,
                "first_seen": t.get("timestamp"),
                "last_seen": t.get("timestamp"),
                "events": [],
                "max_stage": 0,
                "target_ips": set()
            }
        
        c = campaigns[src]
        c["last_seen"] = t.get("timestamp")
        dst = t.get("dst")
        if dst: c["target_ips"].add(dst)
        
        mitre = t.get("mitre", {})
        stg = mitre.get("stage", 0)
        if stg > c["max_stage"]:
            c["max_stage"] = stg
            
        c["events"].append({
            "timestamp": t.get("timestamp"),
            "protocol": t.get("protocol"),
            "alert": t.get("alert"),
            "tactic": mitre.get("tactic", "Unknown"),
            "technique_id": mitre.get("id", "Unknown"),
            "stage": stg,
            "color": mitre.get("color", "#9ca3af"),
            "mitigated": t.get("mitigated", False)
        })
        
    # Convert sets to lists
    result = []
    for ip, data in campaigns.items():
        data["target_ips"] = list(data["target_ips"])
        
        # Sort events by stage then by timestamp loosely (timestamp is string so might need careful sorting, but chronological list append mostly works)
        # Actually it's already chronological from the list.
        result.append(data)
        
    # Sort campaigns by max_stage descending
    result.sort(key=lambda x: x["max_stage"], reverse=True)
    return result
