import os
from dotenv import load_dotenv
load_dotenv()
from opensearchpy import OpenSearch
client = OpenSearch(
    hosts=[{"host": os.getenv("OPENSEARCH_HOST","localhost"), "port": int(os.getenv("OPENSEARCH_PORT","9201"))}],
    use_ssl=False, verify_certs=False
)
r = client.search(
    index="sentinel-incidents",
    body={
        "query": {"match_all": {}},
        "size": 100,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["incident_title", "timestamp", "graph_id", "confidence_score"]
    }
)
hits = r["hits"]["hits"]
total = r["hits"]["total"]["value"]
print(f"Total incidents: {total}")
for h in hits[:50]:
    s = h["_source"]
    ts = s.get("timestamp", s.get("@timestamp", ""))[:19]
    gid = s.get("graph_id", "?")
    title = s.get("incident_title", "?")
    conf = s.get("confidence_score", 0)
    print(f"  {ts}  conf={conf*100:.1f}%  [{gid[:36]}]  {title}")
