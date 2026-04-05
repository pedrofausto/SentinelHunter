import logging
import networkx as nx
from datetime import datetime, timedelta
from graph_builder import GraphBuilder

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VerifyUnification")

def test_unification():
    builder = GraphBuilder()
    
    # 1. Create a set of logs spanning 5 minutes for the same session_id
    base_time = datetime.now()
    logs = []
    session_id = "test_incident_001"
    
    for i in range(5):
        ts = (base_time + timedelta(minutes=i)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        logs.append({
            "@timestamp": ts,
            "data": {
                "win": {
                    "system": {
                        "providerName": "Microsoft-Windows-Sysmon",
                        "eventID": "1"
                    },
                    "eventdata": {
                        "process_tree_id": session_id,
                        "ProcessGuid": f"child_{i}",
                        "ParentProcessGuid": "root_parent",
                        "Image": "cmd.exe",
                        "ParentImage": "explorer.exe",
                        "ProcessId": i + 1000,
                        "ParentProcessId": 500
                    }
                }
            }
        })

    logger.info(f"Generated {len(logs)} logs spanning 5 minutes.")

    # 2. Build graphs (Detection Phase)
    graphs = builder.build_graphs(logs)
    
    logger.info(f"Built {len(graphs)} graphs.")
    
    # Validation
    if len(graphs) == 1:
        logger.info("SUCCESS: All logs unified into a single graph despite spanning multiple minutes.")
        G = graphs[0]
        logger.info(f"Graph Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")
        # Check if they are all connected to the root parent
        components = list(nx.weakly_connected_components(G))
        logger.info(f"Weakly connected components: {len(components)}")
        if len(components) == 1:
            logger.info("SUCCESS: Graph is fully connected.")
    else:
        logger.error(f"FAILURE: Expected 1 graph, but got {len(graphs)}. Slicing is still active!")

if __name__ == "__main__":
    test_unification()
