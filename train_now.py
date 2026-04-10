import os
import sys
import logging
from dotenv import load_dotenv
from graph_builder import GraphBuilder
from gnn_encoder import TopologicalGraphEncoder
from anomaly_detector import AnomalyDetector, VotingStrategy

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ManualTrainer")

def get_utc_timestamp(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def run_weekend_retraining():
    from datetime import datetime, timedelta, timezone
    host = os.getenv("OPENSEARCH_HOST", "localhost")
    port = int(os.getenv("OPENSEARCH_PORT", "9201"))

    gb = GraphBuilder(host=host, port=port)
    gnn = TopologicalGraphEncoder(hidden_channels=64, out_channels=32)
    ad = AnomalyDetector(nu=0.03, contamination=0.03, strategy=VotingStrategy.MAJORITY)

    model_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(model_dir, exist_ok=True)
    MODEL_PATH = os.path.join(model_dir, 'sentinel_baseline.joblib')
    GNN_PATH   = os.path.join(model_dir, 'gnn_weights.pth')

    logger.info("[MLOPS] Starting 14-day historical batch retraining...")
    now = datetime.now(timezone.utc)
    start = get_utc_timestamp(now - timedelta(days=14))
    end   = get_utc_timestamp(now)

    logs = gb.fetch_logs(start, end)
    if not logs:
        logger.warning("[MLOPS] No logs found for the 14-day window. Aborting.")
        sys.exit(1)

    graphs = gb.build_graphs(logs)
    valid  = [g for g in graphs if g.number_of_nodes() >= 2]
    logger.info(f"[MLOPS] Training on {len(valid)} graphs...")
    embeddings, _ = gnn.extract_embeddings_with_ids(valid, is_training=True)
    ad.train(embeddings.numpy())
    ad.save(MODEL_PATH)
    gnn.export_model(GNN_PATH)
    logger.info("[MLOPS] 14-Day Batch Retraining Complete. Models saved.")

if __name__ == "__main__":
    run_weekend_retraining()
