import json
import logging
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from evtx import PyEvtxParser
from opensearchpy import OpenSearch, helpers
import os
import glob

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("EVTXIngestor")

def xml_to_dict(xml_str):
    """Simple XML to Dict converter for EVTX logs."""
    try:
        # PyEvtxParser returns XML strings. We need to parse them.
        # Note: PyEvtxParser's XML can be complex; this is a simplified mapper.
        root = ET.fromstring(xml_str)
        # Remove namespace prefixes for easier mapping
        for el in root.iter():
            if '}' in el.tag:
                el.tag = el.tag.split('}', 1)[1]
        
        result = {}
        
        # Extract System data
        system = root.find("System")
        if system is not None:
            sys_data = {}
            for child in system:
                if child.tag == "TimeCreated":
                    sys_data["TimeCreated"] = child.attrib.get("SystemTime")
                elif child.tag == "Provider":
                    sys_data["ProviderName"] = child.attrib.get("Name")
                elif child.tag == "EventID":
                    sys_data["EventID"] = child.text
                else:
                    sys_data[child.tag] = child.text
            result["System"] = sys_data

        # Extract EventData
        event_data = root.find("EventData")
        if event_data is not None:
            ed_dict = {}
            for data in event_data.findall("Data"):
                name = data.attrib.get("Name")
                if name:
                    ed_dict[name] = data.text
            result["EventData"] = ed_dict
            
        return result
    except Exception as e:
        logger.error(f"Error parsing XML: {e}")
        return None

def ingest_evtx(file_path, client, index_name):
    logger.info(f"Processing {file_path}...")
    parser = PyEvtxParser(file_path)
    
    actions = []
    count = 0
    
    for record in parser.records():
        data = xml_to_dict(record['data'])
        if not data:
            continue
            
        # Format for SentinelHunter (matching sysmon.json parser structure)
        timestamp = data.get("System", {}).get("TimeCreated")
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()
            
        doc = {
            "@timestamp": timestamp,
            "data": {
                "win": {
                    "system": {
                        "providerName": data.get("System", {}).get("ProviderName"),
                        "eventID": data.get("System", {}).get("EventID")
                    },
                    "eventdata": data.get("EventData", {})
                }
            },
            "metadata": {
                "source_file": os.path.basename(file_path),
                "ingest_time": datetime.now(timezone.utc).isoformat()
            }
        }
        
        actions.append({
            "_index": index_name,
            "_source": doc
        })
        
        count += 1
        if len(actions) >= 500:
            helpers.bulk(client, actions)
            actions = []
            
    if actions:
        helpers.bulk(client, actions)
        
    logger.info(f"Successfully ingested {count} records from {file_path}")

def main():
    client = OpenSearch([{'host': 'localhost', 'port': 9200}])
    index_name = "logs-sentinel"
    
    evtx_files = glob.glob("samples/*.evtx")
    if not evtx_files:
        logger.error("No EVTX files found in samples directory.")
        return
        
    for evtx in evtx_files:
        try:
            ingest_evtx(evtx, client, index_name)
        except Exception as e:
            logger.error(f"Failed to ingest {evtx}: {e}")

if __name__ == "__main__":
    main()
