"""
diagnose_schema.py
Samples recent logs from OpenSearch and prints their field structure,
so we can identify what match_rule fields the SchemaMapper parsers need.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from opensearchpy import OpenSearch
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("OPENSEARCH_HOST", "localhost")
PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

client = OpenSearch(hosts=[{"host": HOST, "port": PORT}], use_ssl=False, verify_certs=False)

# ── 1. Fetch a handful of recent docs ────────────────────────────────────────
res = client.search(
    index="logs-*",
    body={"size": 5, "sort": [{"@timestamp": {"order": "desc"}}]}
)

total = res["hits"]["total"]["value"]
print(f"Total docs in logs-*: {total}\n")

def show_fields(d, prefix="", max_depth=4, current=0):
    if current >= max_depth:
        return
    for k, v in list(d.items())[:30]:
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            print(f"  {full_key}:  (dict)")
            show_fields(v, full_key, max_depth, current + 1)
        elif isinstance(v, list):
            print(f"  {full_key}:  (list, len={len(v)})")
        else:
            print(f"  {full_key}: {str(v)[:100]}")

for i, hit in enumerate(res["hits"]["hits"]):
    print(f"{'='*60}")
    print(f"LOG {i+1} | index: {hit['_index']}")
    print(f"{'='*60}")
    show_fields(hit["_source"])
    print()

# ── 2. Identify key discriminator fields used by our parsers ────────────────
CANDIDATE_FIELDS = [
    "decoder.name",
    "data.win.system.providerName",
    "event.category",
    "rule.groups",
    "agent.name",
    "manager.name",
    "data.srcip",
    "data.dstip",
    "data.audit.type",
    "data.win.system.eventID",
]

print(f"\n{'='*60}")
print("FIELD PREVALENCE ANALYSIS (200 docs)")
print(f"{'='*60}")

res2 = client.search(
    index="logs-*",
    body={"size": 200, "sort": [{"@timestamp": {"order": "desc"}}], "_source": CANDIDATE_FIELDS + ["@timestamp"]}
)

counts = {f: 0 for f in CANDIDATE_FIELDS}
sample_vals = {f: set() for f in CANDIDATE_FIELDS}

def get_nested(d, path):
    keys = path.split(".")
    v = d
    for k in keys:
        if isinstance(v, dict):
            v = v.get(k)
        else:
            return None
    return v

for hit in res2["hits"]["hits"]:
    src = hit["_source"]
    for f in CANDIDATE_FIELDS:
        val = get_nested(src, f)
        if val is not None:
            counts[f] += 1
            if isinstance(val, list):
                sample_vals[f].update(str(x) for x in val[:3])
            else:
                sample_vals[f].add(str(val)[:60])

for f in CANDIDATE_FIELDS:
    pct = counts[f] / 2
    samples = list(sample_vals[f])[:5]
    print(f"  {f:<45} {counts[f]:>3}/200 ({pct:.0f}%)  values: {samples}")
