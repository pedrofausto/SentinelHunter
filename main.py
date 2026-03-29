import logging
import os
import time
from datetime import datetime, timedelta

from graph_builder import GraphBuilder
from gnn_encoder import TopologicalGraphEncoder
from anomaly_detector import AnomalyDetector
from llm_investigator import LLMInvestigator
from cti_integration import CTIIntegration

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger("RetroHuntingMain")

def main():
    """
    Main orchestrator script for the Retro Hunting pipeline.
    Executes the Training/Baseline Phase followed by the Inference/Hunting Phase.
    """
    logger.info("Initializing Retro Hunting Pipeline...")

    # Configuration Parameters
    OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
    OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))

    LLM_MODE = os.environ.get("LLM_MODE", "local") # 'local' or 'cloud'
    OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

    OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://localhost:8080")
    OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "YOUR-OPENCTI-TOKEN")

    # Time window settings (mockup: last 24h as baseline, current hour as inference)
    now = datetime.utcnow()
    baseline_start = (now - timedelta(days=1)).isoformat() + "Z"
    baseline_end = now.isoformat() + "Z"

    inference_start = baseline_end
    # Assuming realtime inference window
    inference_end = (now + timedelta(hours=1)).isoformat() + "Z"

    # Initialize Modules
    graph_builder = GraphBuilder(host=OPENSEARCH_HOST, port=OPENSEARCH_PORT)
    gnn_encoder = TopologicalGraphEncoder(hidden_channels=64, out_channels=32)
    anomaly_detector = AnomalyDetector(nu=0.05)

    try:
        llm_investigator = LLMInvestigator(
            mode=LLM_MODE,
            ollama_host=OLLAMA_HOST,
            api_key=GEMINI_API_KEY
        )
    except ValueError as e:
        logger.error(f"LLM Investigator initialization failed: {e}")
        return

    cti_integration = CTIIntegration(url=OPENCTI_URL, token=OPENCTI_TOKEN)

    # ==========================================
    # PHASE A: Training / Baseline
    # ==========================================
    logger.info("--- STARTING PHASE A: TRAINING / BASELINE ---")

    # 1. Fetch historical logs to build a baseline
    logger.info(f"Fetching baseline logs from {baseline_start} to {baseline_end}")
    baseline_logs = graph_builder.fetch_logs(baseline_start, baseline_end)

    # Generate mock logs for demonstration purposes if OpenSearch is empty/unavailable
    if not baseline_logs:
        logger.warning("No baseline logs found in OpenSearch. Using mock data for demonstration.")
        baseline_logs = [
            {"@timestamp": baseline_start, "process.name": "explorer.exe", "file.path": "C:\\Windows\\System32\\cmd.exe", "event.action": "process_created", "session_id": "session1"},
            {"@timestamp": baseline_start, "process.name": "cmd.exe", "destination.ip": "8.8.8.8", "event.action": "network_connection", "session_id": "session1"},
            {"@timestamp": baseline_start, "process.name": "svchost.exe", "file.path": "C:\\temp\\log.txt", "event.action": "file_written", "session_id": "session2"}
        ]

    # 2. Build Provenance Graphs
    baseline_graphs = graph_builder.build_graphs(baseline_logs, group_by='session_id')

    # 3. Generate Topological Embeddings using GNN
    baseline_embeddings, baseline_ids = gnn_encoder.extract_embeddings_with_ids(baseline_graphs, is_training=True)

    # 4. Train the Anomaly Detector (One-Class SVM)
    if baseline_embeddings.numel() > 0:
        anomaly_detector.train(baseline_embeddings.numpy())
    else:
        logger.error("Failed to generate baseline embeddings. Cannot train model.")
        return

    logger.info("--- PHASE A COMPLETED ---")

    # ==========================================
    # PHASE B: Inference / Hunting
    # ==========================================
    logger.info("--- STARTING PHASE B: INFERENCE / HUNTING ---")

    # 1. Fetch new logs for inference
    logger.info(f"Fetching inference logs from {inference_start} to {inference_end}")
    inference_logs = graph_builder.fetch_logs(inference_start, inference_end)

    # Generate mock anomaly logs for demonstration
    if not inference_logs:
        logger.warning("No inference logs found in OpenSearch. Using mock anomaly data for demonstration.")
        inference_logs = [
             {"@timestamp": inference_start, "process.name": "powershell.exe", "file.path": "malware.exe", "event.action": "file_created", "session_id": "session3"},
             {"@timestamp": inference_start, "process.name": "malware.exe", "destination.ip": "185.15.22.1", "event.action": "network_connection", "session_id": "session3"},
             {"@timestamp": inference_start, "process.name": "malware.exe", "process.name_target": "lsass.exe", "event.action": "process_access", "session_id": "session3"}
        ]

    # 2. Build Provenance Graphs for new logs
    inference_graphs = graph_builder.build_graphs(inference_logs, group_by='session_id')

    # 3. Generate Embeddings (is_training=False)
    inference_embeddings, inference_ids = gnn_encoder.extract_embeddings_with_ids(inference_graphs, is_training=False)

    if inference_embeddings.numel() == 0:
        logger.info("No inference graphs generated. Exiting.")
        return

    # 4. Detect Anomalies
    anomalous_ids, scores = anomaly_detector.detect(inference_embeddings.numpy(), inference_ids)

    if anomalous_ids:
        logger.info(f"Found {len(anomalous_ids)} anomalous subgraphs. Initiating LLM Investigation.")

        # Filter anomalous graphs
        anomalous_graphs = [g for g in inference_graphs if g.graph.get('graph_id') in anomalous_ids]

        # 5. LLM Forensic Investigation
        reports = llm_investigator.investigate(anomalous_graphs)

        # 6. OpenCTI Ingestion
        for graph_id, report_data in reports.items():
            logger.info(f"Report for {graph_id}:\n{report_data}")
            cti_integration.ingest_report(report_data, graph_id)

    else:
        logger.info("No anomalies detected in the inference window. System is secure.")

    logger.info("--- PHASE B COMPLETED ---")
    logger.info("Pipeline execution finished.")

if __name__ == "__main__":
    main()
