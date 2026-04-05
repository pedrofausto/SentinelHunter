"""
ingest_sample.py
Streams an NDJSON or JSON array log file directly into OpenSearch.
Usage: python tools/ingest_sample.py samples/wazuh_benign.json
"""
import sys
import os
import json
import logging
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from opensearchpy import OpenSearch, helpers

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger("Ingest")

def ingest(file_path: str):
    load_dotenv()
    HOST = os.getenv("OPENSEARCH_HOST", "localhost")
    PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
    INDEX = "logs-sentinel-wazuh"

    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return

    logger.info(f"Connecting to OpenSearch ({HOST}:{PORT})...")
    client = OpenSearch(hosts=[{"host": HOST, "port": PORT}], use_ssl=False, verify_certs=False)
    
    # Ensure index exists
    if not client.indices.exists(index=INDEX):
        client.indices.create(index=INDEX)
        logger.info(f"Created index: {INDEX}")

    logger.info(f"Reading {file_path}...")
    
    def generate_actions():
        with open(file_path, "r", encoding="utf-8") as f:
            # Check if it's a JSON array (like wazuh_mixed.json may be) or NDJSON
            content = f.read(2).strip()
            f.seek(0)
            
            if content.startswith("["):
                # JSON Array
                logs = json.load(f)
                for log in logs:
                    yield {
                        "_index": INDEX,
                        "_source": log
                    }
            else:
                # NDJSON
                for line in f:
                    if not line.strip(): continue
                    try:
                        log = json.loads(line)
                        yield {
                            "_index": INDEX,
                            "_source": log
                        }
                    except json.JSONDecodeError:
                        pass

    logger.info(f"Bulk indexing into {INDEX}...")
    success, failed = helpers.bulk(client, generate_actions(), stats_only=True)
    logger.info(f"Ingestion complete: {success} successful, {failed} failed.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ingest_sample.py <path_to_json>")
        sys.exit(1)
        
    ingest(sys.argv[1])
