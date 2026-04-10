import os
import json
import logging
from datetime import datetime, timezone
from opensearchpy import OpenSearch, helpers
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RigorousReset")
# Silence the opensearch logger to avoid millions of POST logs
logging.getLogger("opensearch").setLevel(logging.WARNING)

def reset(benign_only: bool = False):
    load_dotenv()
    host = os.getenv("OPENSEARCH_HOST", "localhost")
    port = int(os.getenv("OPENSEARCH_PORT", "9201"))
    client = OpenSearch([{'host': host, 'port': port}])
    
    # 1. Wipe indices
    indices = ['sentinel-incidents', 'sentinel-baseline', 'logs-sentinel', 'logs-sentinel*']
    for idx in indices:
        try:
            client.indices.delete(index=idx, ignore=[400, 404])
            logger.info(f"Deleted index: {idx}")
        except Exception as e:
            logger.error(f"Error deleting index {idx}: {e}")

    # 2. Wipe local state
    files_to_remove = [
        ".sentinel_state.json",
        "models/sentinel_baseline.joblib",
        "models/gnn_weights.pth"
    ]
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)
            logger.info(f"Removed local state file: {f}")

    # 3. Generate fresh threat data (Skip if benign only)
    if not benign_only:
        logger.info("Generating fresh complex threat data...")
        import subprocess
        subprocess.run(["python", "generate_complex_threats.py", "--num_incidents", "50"], check=True)

    # 4. Ingest BENIGN Baseline
    logger.info("Ingesting benign logs for baseline (up to 6000)...")
    benign_path = 'samples/wazuh_benign.json'
    if os.path.exists(benign_path):
        actions = []
        with open(benign_path, 'r') as f:
            for line in f:
                if len(actions) >= 6000: break
                if not line.strip(): continue
                l = json.loads(line.strip())
                l['@timestamp'] = datetime.now(timezone.utc).isoformat()
                actions.append({
                    "_index": "logs-sentinel",
                    "_source": l
                })
        
        if actions:
            helpers.bulk(client, actions)
            logger.info(f"Successfully ingested {len(actions)} benign logs via Bulk API.")

    # 5. Ingest Malicious at current timestamp (Skip if benign only)
    if not benign_only:
        logger.info("Ingesting malicious logs...")
        if os.path.exists('samples/wazuh_mixed_complex.jsonl'):
            actions = []
            with open('samples/wazuh_mixed_complex.jsonl', 'r') as f:
                for line in f:
                    l = json.loads(line.strip())
                    l['@timestamp'] = datetime.now(timezone.utc).isoformat()
                    actions.append({
                        "_index": "logs-sentinel",
                        "_source": l
                    })
            if actions:
                helpers.bulk(client, actions)
                logger.info(f"Successfully ingested {len(actions)} malicious logs via Bulk API.")
        else:
            logger.error("Threat sample file not found!")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--benign-only", action="store_true", help="Skip malicious ingestion")
    args = parser.parse_args()
    reset(benign_only=args.benign_only)
