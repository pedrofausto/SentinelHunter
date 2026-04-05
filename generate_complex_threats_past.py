import json
import random
import uuid
from datetime import datetime, timedelta, timezone

def get_utc_timestamp(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def generate_complex_threats(output_file, num_incidents=10):
    incidents = []
    now = datetime.now(timezone.utc)
    
    # Common agents
    agents = [
        {"id": "101", "name": "win-workstation-01"},
        {"id": "102", "name": "win-workstation-02"},
        {"id": "105", "name": "srv-prod-01"}
    ]

    for i in range(num_incidents):
        agent = random.choice(agents)
        # Guarantee logs are in the present/future so the active orchestrator catches them
        start_time = now - timedelta(minutes=10) + timedelta(seconds=(i * 10))
        
        # Incident Type: Living off the Land / Execution
        # Chain: Cmd -> PowerShell -> Network -> FileWrite -> Exec
        root_guid = str(uuid.uuid4())
        ps_guid = str(uuid.uuid4())
        loader_guid = str(uuid.uuid4())
        
        # 1. Parent Process (cmd.exe or explorer.exe)
        logs = [
            {
                "@timestamp": get_utc_timestamp(start_time),
                "agent": agent,
                "data": {
                    "win": {
                        "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {
                            "ProcessGuid": root_guid,
                            "Image": "C:\\Windows\\System32\\cmd.exe",
                            "CommandLine": "cmd.exe /c \"powershell.exe -ExecutionPolicy Bypass -encodedcommand ...\"",
                            "ParentImage": "C:\\Windows\\explorer.exe",
                            "User": f"CORP\\user_{agent['id']}"
                        }
                    }
                }
            },
            # 2. PowerShell child
            {
                "@timestamp": get_utc_timestamp(start_time + timedelta(seconds=2)),
                "agent": agent,
                "data": {
                    "win": {
                        "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {
                            "ProcessGuid": ps_guid,
                            "ParentProcessGuid": root_guid,
                            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "CommandLine": "powershell.exe -ExecutionPolicy Bypass ...",
                            "User": f"CORP\\user_{agent['id']}"
                        }
                    }
                }
            },
            # 3. Network Connection (C2)
            {
                "@timestamp": get_utc_timestamp(start_time + timedelta(seconds=5)),
                "agent": agent,
                "data": {
                    "win": {
                        "system": {"eventID": "3", "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {
                            "ProcessGuid": ps_guid,
                            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "SourceIp": "192.168.1.50",
                            "DestinationIp": f"185.10.{random.randint(1,254)}.{random.randint(1,254)}",
                            "DestinationPort": "443",
                            "Protocol": "tcp"
                        }
                    }
                }
            },
            # 4. File Creation (The Dropper)
            {
                "@timestamp": get_utc_timestamp(start_time + timedelta(seconds=10)),
                "agent": agent,
                "data": {
                    "win": {
                        "system": {"eventID": "11", "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {
                            "ProcessGuid": ps_guid,
                            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "TargetFilename": f"C:\\Users\\Public\\update_helper_{i}.exe"
                        }
                    }
                }
            },
            # 5. Execution of the Dropper
            {
                "@timestamp": get_utc_timestamp(start_time + timedelta(seconds=15)),
                "agent": agent,
                "data": {
                    "win": {
                        "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {
                            "ProcessGuid": loader_guid,
                            "ParentProcessGuid": ps_guid,
                            "Image": f"C:\\Users\\Public\\update_helper_{i}.exe",
                            "CommandLine": f"update_helper_{i}.exe --silent",
                            "User": "NT AUTHORITY\\SYSTEM"
                        }
                    }
                }
            },
            # 6. Discovery by Dropper
            {
                "@timestamp": get_utc_timestamp(start_time + timedelta(seconds=20)),
                "agent": agent,
                "data": {
                    "win": {
                        "system": {"eventID": "1", "providerName": "Microsoft-Windows-Sysmon"},
                        "eventdata": {
                            "ProcessGuid": str(uuid.uuid4()),
                            "ParentProcessGuid": loader_guid,
                            "Image": "C:\\Windows\\System32\\whoami.exe",
                            "CommandLine": "whoami /groups",
                            "User": "NT AUTHORITY\\SYSTEM"
                        }
                    }
                }
            }
        ]
        incidents.extend(logs)

    with open(output_file, 'w') as f:
        for log in incidents:
            f.write(json.dumps(log) + '\n')
    
    print(f"Generated {num_incidents} complex attack chains ({len(incidents)} logs) in {output_file}")

if __name__ == "__main__":
    generate_complex_threats("samples/wazuh_mixed_complex.jsonl", num_incidents=10)
