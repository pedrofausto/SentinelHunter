import os
from dotenv import load_dotenv
load_dotenv()
from opensearchpy import OpenSearch
client = OpenSearch(
    hosts=[{"host": os.getenv("OPENSEARCH_HOST","localhost"), "port": int(os.getenv("OPENSEARCH_PORT","9201"))}],
    use_ssl=False, verify_certs=False
)
incident_id = "KfWOc50By_d8qhMoxsxR"
try:
    r = client.get(index="sentinel-incidents", id=incident_id)
    doc = r["_source"]
    print(f"Incident: {doc.get('incident_title')}")
    print(f"Graph ID: {doc.get('graph_id')}")
    print(f"Source Doc IDs Count: {len(doc.get('source_doc_ids', []))}")
    print(f"Keys present: {list(doc.keys())}")
except Exception as e:
    print(f"Error: {e}")
