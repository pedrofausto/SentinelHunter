import os
import json
import logging
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AttackGenerator")

def get_client():
    return OpenSearch(
        hosts=[{'host': os.getenv("OPENSEARCH_HOST", "localhost"), 'port': int(os.getenv("OPENSEARCH_PORT", "9200"))}],
        use_ssl=False, verify_certs=False
    )

def generate_ransomware_scenario(index_name):
    """Scenario: Encoded powershell -> Payload Drop -> Massive File Access"""
    now = datetime.now(timezone.utc).isoformat()
    tree_id = "attack_ransomware_001"
    
    events = [
        {"@timestamp": now, "process.name": "explorer.exe", "target.process.name": "powershell.exe", "event.action": "process_created", "process_tree_id": tree_id, "process.command_line": "powershell.exe -enc Zm9yZWFjaCAoJGZpbGUgaW4gZ2V0LWNoaWxkaXRlbSBDOlwuLi4="},
        {"@timestamp": now, "process.name": "powershell.exe", "file.path": "C:\\Windows\\Temp\\locker.exe", "event.action": "file_created", "process_tree_id": tree_id},
        {"@timestamp": now, "process.name": "locker.exe", "file.path": "C:\\Users\\admin\\Documents\\financials.xlsx", "event.action": "file_read", "process_tree_id": tree_id},
        {"@timestamp": now, "process.name": "locker.exe", "file.path": "C:\\Users\\admin\\Documents\\financials.xlsx.locked", "event.action": "file_created", "process_tree_id": tree_id},
        {"@timestamp": now, "process.name": "locker.exe", "destination.ip": "194.5.67.12", "dst_port": 4444, "event.action": "network_connection", "process_tree_id": tree_id}
    ]
    return events

def generate_exfiltration_scenario(index_name):
    """Scenario: SQL Injection -> Database Dump -> Outbound Flow"""
    now = datetime.now(timezone.utc).isoformat()
    session_id = "attack_exfil_99"
    
    events = [
        {"@timestamp": now, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.20", "dst_port": 80, "url": "/login?user=admin' OR '1'='1", "event.action": "web_request", "session_id": session_id},
        {"@timestamp": now, "src_ip": "10.0.0.20", "dst_ip": "10.0.0.50", "dst_port": 3306, "event.action": "db_query", "query": "SELECT * FROM users_credit_cards", "session_id": session_id},
        {"@timestamp": now, "src_ip": "10.0.0.20", "dst_ip": "45.33.12.100", "dst_port": 443, "Rate": 15000.0, "AVG": 14000.0, "event.action": "data_exfiltration", "session_id": session_id}
    ]
    return events

def generate_lateral_movement(index_name):
    """Scenario: Compromised user -> RDP to Peer -> LSASS access"""
    now = datetime.now(timezone.utc).isoformat()
    tree_id = "attack_lateral_505"
    
    events = [
        {"@timestamp": now, "src_ip": "10.0.0.15", "dst_ip": "10.0.0.16", "dst_port": 3389, "event.action": "rdp_connection", "user.name": "malicious_actor", "process_tree_id": tree_id},
        {"@timestamp": now, "process.name": "rdpclip.exe", "target.process.name": "mimikatz.exe", "event.action": "process_created", "process_tree_id": tree_id},
        {"@timestamp": now, "process.name": "mimikatz.exe", "target.process.name": "lsass.exe", "event.action": "process_access", "process_tree_id": tree_id}
    ]
    return events

def main():
    client = get_client()
    index = "logs-sentinel"
    
    all_events = []
    all_events.extend(generate_ransomware_scenario(index))
    all_events.extend(generate_exfiltration_scenario(index))
    all_events.extend(generate_lateral_movement(index))
    
    actions = [
        {"_index": index, "_source": e} for e in all_events
    ]
    
    helpers.bulk(client, actions)
    logger.info(f"Successfully injected {len(all_events)} anomalous events into {index}")

if __name__ == "__main__":
    main()
