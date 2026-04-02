import psutil
import json
from scapy.arch.windows import get_windows_if_list

sc_if = get_windows_if_list()
ps_stats = psutil.net_if_stats()
results = []

for x in sc_if:
    name = x.get('name')
    desc = x.get('description')
    guid = x.get('guid')
    
    ps_match = None
    if name in ps_stats: ps_match = name
    elif desc in ps_stats: ps_match = desc
    
    isup = False
    speed = 0
    if ps_match:
        isup = ps_stats[ps_match].isup
        speed = ps_stats[ps_match].speed
        
    results.append({
        'sc_name': name,
        'sc_desc': desc,
        'ps_match': ps_match,
        'isup': isup,
        'speed': speed
    })

print(json.dumps(results, indent=2))
