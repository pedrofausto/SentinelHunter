import os, sys, time, json
from datetime import datetime, timezone
from opensearchpy import OpenSearch
from reporting_engine import ReportingEngine

engine = ReportingEngine()

incident = {
    "incident_title": "Critical: Multi-Stage PowerShell Attack",
    "severity": "Critical",
    "confidence_score": 0.95,
    "risk_justification": "The process chain shows cmd.exe spawning an encoded PowerShell session which then established a network connection to a known C2 IP and dropped a suspicious executable.",
    "summary": "Forensic analysis of session guid-102 reveals a classic APT pattern. An encoded PowerShell command was used to bypass execution policies, followed by a connection to 185.10.197.125 and the creation of update_helper_0.exe in a public directory.",
    "impact_assessment": {
        "confidentiality": "High",
        "integrity": "High",
        "availability": "Medium",
        "blast_radius": "Single Host",
        "technical_description": "The attacker has achieved SYSTEM level execution on win-workstation-02."
    },
    "suspicious_indicators": ["PowerShell ExecutionPolicy Bypass", "Encoded Command", "Outbound C2 Connection", "Suspicious File Drop"],
    "mitre_mappings": [
        {"tactic": "Execution", "technique_id": "T1059.001", "technique_name": "PowerShell"},
        {"tactic": "Command and Control", "technique_id": "T1071.001", "technique_name": "Web Protocols"}
    ],
    "observables": [
        {"type": "ipv4-addr", "value": "185.10.197.125", "description": "C2 Server"},
        {"type": "file:name", "value": "update_helper_0.exe", "description": "Dropped Malware"}
    ],
    "remediation_steps": ["Isolate win-workstation-02", "Terminate suspicious process update_helper_0.exe", "Block IP 185.10.197.125"],
    "strategy": "UNION",
    "graph_id": "e64d0203-2293-407d-ad6b-534cefb204c4_2026-04-02T23:45:48.070Z",
    "source_doc_ids": [] # We will populate this in a second script if needed
}

# Find some real doc_ids from the malicious logs to make reconstruction work
client = OpenSearch([{'host': 'localhost', 'port': 9200}])
res = client.search(index="logs-sentinel*", body={"query": {"match": {"data.win.eventdata.ProcessGuid": "e64d0203-2293-407d-ad6b-534cefb204c4"}}, "size": 10})
doc_ids = [h['_id'] for h in res['hits']['hits']]
incident['source_doc_ids'] = doc_ids

engine.ingest_incident(incident, incident['graph_id'])
print("Successfully forced malicious incident ingestion.")
