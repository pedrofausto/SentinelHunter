import os
import csv
import json
import logging
import argparse
import hashlib
from datetime import datetime, timezone
from dateutil import parser as date_parser
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DataIngestor")

def get_client():
    host = os.getenv("OPENSEARCH_HOST", "localhost")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    return OpenSearch(
        hosts=[{'host': host, 'port': port}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )

def infer_type(val: str):
    """Smartly cast string values to appropriate data types."""
    if val is None or val == "":
        return None
    
    val_lower = str(val).lower()
    if val_lower in ["true", "false"]:
        return val_lower == "true"
        
    try:
        if '.' in val:
            return float(val)
        return int(val)
    except ValueError:
        return val

def generate_doc_id(doc: dict) -> str:
    """Creates a deterministic hash to prevent duplicate ingestion."""
    # Convert doc to a stable string representation
    stable_str = json.dumps(doc, sort_keys=True)
    return hashlib.sha256(stable_str.encode('utf-8')).hexdigest()

def process_row(row: dict) -> dict:
    """Applies schema normalization and timestamp extraction."""
    doc = {}
    ts_found = False
    
    for k, v in row.items():
        if v is None or v == "": continue
        
        # Smart Timestamp Discovery
        if k.lower() in ['@timestamp', 'timestamp', 'time', 'date', 'eventtime', 'timecreated', 'creationtime'] and not ts_found:
            try:
                dt = date_parser.parse(str(v))
                if dt.tzinfo is None:
                    doc['@timestamp'] = dt.isoformat() + "Z"
                else:
                    doc['@timestamp'] = dt.isoformat()
                ts_found = True
                continue # Skip adding the original timestamp field to avoid duplication
            except Exception:
                pass
                
        # Type Inference for numeric and boolean values
        doc[k] = infer_type(v) if isinstance(v, str) else v

    # Fallback if no timestamp found
    if not ts_found or str(doc.get('@timestamp', '')).lower() == 'now':
        doc['@timestamp'] = datetime.now(timezone.utc).isoformat()
        
    return doc

def ingest_data(client, index_name, file_path):
    """
    Reads a CSV or JSON/JSONL file and ingests documents into OpenSearch.
    """
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return

    # Ensure index exists
    if not client.indices.exists(index=index_name):
        client.indices.create(index=index_name)
        logger.info(f"Created index: {index_name}")

    actions = []
    count = 0
    ext = os.path.splitext(file_path)[1].lower()
    
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as f:
            if ext == '.csv':
                reader = csv.DictReader(f)
                iterator = reader
            elif ext in ['.json', '.jsonl']:
                # Assume JSON Lines (one JSON object per line)
                iterator = (json.loads(line) for line in f if line.strip())
            else:
                logger.error(f"Unsupported file format: {ext}")
                return

            for row in iterator:
                doc = process_row(row)
                doc_id = generate_doc_id(doc)
                
                actions.append({
                    "_index": index_name,
                    "_id": doc_id,  # Idempotent indexing
                    "_source": doc
                })
                count += 1

                if len(actions) >= 500:
                    helpers.bulk(client, actions)
                    actions = []

            # Final batch
            if actions:
                helpers.bulk(client, actions)

        logger.info(f"Successfully ingested {count} documents from {file_path} into {index_name}")
    except Exception as e:
        logger.error(f"Error during ingestion: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest CSV/JSON logs into OpenSearch.")
    parser.add_argument("file_path", help="Path to the file to ingest.")
    parser.add_argument("--index", default="logs-sentinel", help="OpenSearch index name.")
    parser.add_argument("--now", action="store_true", help="Override timestamps with current time.")
    
    args = parser.parse_args()
    
    client = get_client()
    if client.ping():
        # Inject the 'now' preference into the process_row logic if needed
        # But a cleaner way is to wrap process_row or pass a flag
        if args.now:
            orig_process_row = process_row
            def process_row_now(row):
                doc = orig_process_row(row)
                doc['@timestamp'] = datetime.now(timezone.utc).isoformat()
                return doc
            globals()['process_row'] = process_row_now
            
        ingest_data(client, args.index, args.file_path)
    else:
        logger.error("Could not connect to OpenSearch.")
