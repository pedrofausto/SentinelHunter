from graph_builder import GraphBuilder
from gnn_encoder import TopologicalGraphEncoder
from anomaly_detector import AnomalyDetector
from reporting_engine import ReportingEngine
from llm_investigator import LLMInvestigator
import networkx as nx
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
load_dotenv()

# 1. Setup
gb = GraphBuilder()
encoder = TopologicalGraphEncoder()
encoder.load('models/gnn_weights.pth')
detector = AnomalyDetector()
detector.load('models/sentinel_baseline.joblib')
re = ReportingEngine()
llm = LLMInvestigator(mode='gemini', api_key=os.environ.get('GEMINI_API_KEY'))


# 2. Fetch malicious logs
# We know they are there from our previous injections
logs = gb.fetch_logs('2026-04-01T00:00:00.000Z', '2026-04-03T00:00:00.000Z')
graphs = gb.build_graphs(logs)
print(f"Total Graphs: {len(graphs)}")

# 3. Detect and Filter
embeddings, ids = encoder.extract_embeddings_with_ids(graphs)
anomalies, scores_map = detector.detect(embeddings.numpy(), ids)
print(f"Detected Anomalies: {len(anomalies)}")

# 4. Investigate a COMPLEX Malicious Anomaly (prefer things with many nodes)
target_id = None
if anomalies:
    # Look for a graph with powershell or cmd to make for a better demo
    for a_id in anomalies:
        for g in graphs:
            if g.graph.get('graph_id') == a_id:
                if any('powershell' in str(node).lower() for node in g.nodes()):
                    target_id = a_id
                    break
        if target_id: break
    
    if not target_id:
        target_id = anomalies[0]
        
    score = scores_map[target_id]['consensus_score']
    print(f"Investigating COMPLEX Anomaly: {target_id} (Score: {score:.4f})")
    
    # THE CRITICAL FIX: Strip suffix for deep dive
    base_id = target_id.rsplit('_', 1)[0] if '_202' in target_id else target_id
    context_logs = gb.fetch_logs_with_ancestry('2000-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z', filter_id=base_id)
    print(f"Reconstructed chain with {len(context_logs)} logs for {base_id}")

    
    context_graphs = gb.build_graphs(context_logs)
    reports = llm.investigate(context_graphs, cti_hints=[f"ENSEMBLE SCORE: {score:.4f}"])
    
    for g_id, report in reports.items():
        # Inject exact OpenSearch document IDs from the context graph
        # This is CRITICAL for the dashboard to find the logs for this specific incident
        source_ids = []
        g_base = g_id.rsplit('_', 1)[0] if '_202' in g_id else g_id
        
        for g in context_graphs:
            curr_id = g.graph.get('graph_id', '')
            curr_base = curr_id.rsplit('_', 1)[0] if '_202' in curr_id else curr_id
            if curr_id == g_id or curr_base == g_base:
                source_ids = g.graph.get('doc_ids', [])
                if source_ids: break
        
        report['source_doc_ids'] = source_ids
        report['graph_id'] = g_id # Explicitly ensure graph_id is in data

        print(f"Pushing Incident: {report['incident_title']} (Evidence docs: {len(source_ids)})")
        re.ingest_incident(report, g_id)


print("Final Count in Index:", re.client.count(index='sentinel-incidents', ignore=[400,404]).get('count', 0))
