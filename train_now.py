import os
import sys
import logging
from datetime import datetime, timedelta, timezone
from main import get_utc_timestamp
from graph_builder import GraphBuilder
from gnn_encoder import TopologicalGraphEncoder
from anomaly_detector import AnomalyDetector
from reporting_engine import ReportingEngine

# Configure logging to stdout
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ManualTrainer")

def train():
    host = os.environ.get("OPENSEARCH_HOST", "localhost")
    port = int(os.environ.get("OPENSEARCH_PORT", "9200"))
    
    gb = GraphBuilder(host, port)
    gnn = TopologicalGraphEncoder(64, 32)
    ad = AnomalyDetector(0.1)
    re = ReportingEngine(host, port)
    
    now = datetime.now(timezone.utc)
    # Broaden window to ensure we catch the just-ingested logs
    start = get_utc_timestamp(now - timedelta(minutes=10))
    end = get_utc_timestamp(now + timedelta(minutes=10))
    
    logger.info(f"Fetching logs for training: {start} to {end}")
    logs = gb.fetch_logs(start, end)
    
    if not logs:
        logger.error("No logs found for training! Baseline is empty.")
        return
    
    logger.info(f"Building graphs from {len(logs)} logs...")
    graphs = gb.build_graphs(logs, group_by='session_id')
    logger.info(f"Built {len(graphs)} graphs.")
    
    if graphs:
        logger.info("Extracting embeddings and fitting anomaly detector...")
        embeddings = gnn.encode_batch(graphs)
        if embeddings.numel() > 0:
            ad.fit(embeddings)
            
            # Save
            model_dir = os.path.join(os.path.dirname(__file__), 'models')
            os.makedirs(model_dir, exist_ok=True)
            ad_path = os.path.join(model_dir, 'sentinel_baseline.joblib')
            gnn_path = os.path.join(model_dir, 'gnn_weights.pth')
            
            ad.save(ad_path)
            gnn.save(gnn_path)
            logger.info(f"Training complete. Models saved to {model_dir}")
        else:
            logger.error("Embeddings tensor is empty.")
    else:
        logger.error("No graphs built.")

if __name__ == "__main__":
    train()
