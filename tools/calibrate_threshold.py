"""
calibrate_threshold.py
A tuning tool for the SentinelHunter AnomalyDetector.
Analyzes historically "normal" traffic in the OpenSearch baseline to recommend
an optimal `contamination` (nu/outlier fraction) score for the ML Ensemble.
"""

import sys
import os
import logging
import numpy as np
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
from graph_builder import GraphBuilder
from gnn_encoder import TopologicalGraphEncoder
from anomaly_detector import AnomalyDetector

logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger("Calibration")

def run_calibration(lookback_hours: int = 12):
    load_dotenv()
    HOST = os.getenv("OPENSEARCH_HOST", "localhost")
    PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

    logger.info(f"Connecting to OpenSearch ({HOST}:{PORT})...")
    gb = GraphBuilder(host=HOST, port=PORT, index="logs-sentinel-wazuh")
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)

    logger.info(f"Extracting baseline traffic from {start_time.isoformat()} to {end_time.isoformat()}...")
    
    try:
        # 1. Fetch
        logs = gb.fetch_logs(start_time.isoformat(), end_time.isoformat())
        if not logs:
            logger.error("No logs returned. Cannot calibrate.")
            return

        # 2. Map & Build Graphs
        logger.info(f"Mapping {len(logs)} logs to graph topologies...")
        graphs = gb.build_graphs(logs)
        if not graphs:
            logger.error("Logs contained no structured process/network events (only raw flows). Cannot construct topological baseline.")
            return

        # 3. Encode
        logger.info(f"Encoding {len(graphs)} subgraphs via Graph Neural Network...")
        encoder = TopologicalGraphEncoder()
        embeddings, ids = encoder.extract_embeddings_with_ids(graphs, is_training=True)

        if embeddings.numel() == 0:
            logger.error("Failed to generate PyTorch embeddings.")
            return

        # 4. Calibrate (Mocking the ensemble detector logic to find optimal threshold)
        X = embeddings.numpy()
        logger.info(f"Generated [N={X.shape[0]}, D={X.shape[1]}] embedding matrix.")
        
        from sklearn.ensemble import IsolationForest
        from sklearn.neighbors import LocalOutlierFactor
        
        logger.info("\n--- EXECUTING CALIBRATION SWEEP ---")
        
        test_nus = [0.001, 0.01, 0.05, 0.10, 0.15]
        results = []

        # We assume dataset is 99% clean. We measure how many false positives 
        # each contamination setting would throw on purely benign training data.
        for nu in test_nus:
            # iForest
            iso = IsolationForest(contamination=nu, random_state=42)
            iso_preds = iso.fit_predict(X)
            iso_anomalies = np.sum(iso_preds == -1)
            
            # LOF
            lof = LocalOutlierFactor(contamination=nu, novelty=True)
            lof.fit(X)
            lof_preds = lof.predict(X)
            lof_anomalies = np.sum(lof_preds == -1)
            
            # Simulated Ensemble Logic (OR gate for safety in detection, AND gate for calibration metrics)
            ensemble_anomalies = np.sum((iso_preds == -1) | (lof_preds == -1))
            
            results.append({
                "nu": nu,
                "iso_alerts": iso_anomalies,
                "lof_alerts": lof_anomalies,
                "ensemble_alerts": ensemble_anomalies,
                "alert_rate": (ensemble_anomalies / X.shape[0]) * 100
            })
            
            logger.info(f"Contamination={nu:<5} -> Alerts: {ensemble_anomalies:<4} ({results[-1]['alert_rate']:.1f}% alert noise)")

        # Recommend Settings
        print("\n" + "="*60)
        print(">>> CALIBRATION RECOMMENDATION <<<")
        print("="*60)
        
        target_noise = 2.0 # Target 2% alert noise on baseline data
        best_nu = min(results, key=lambda x: abs(x['alert_rate'] - target_noise))
        
        print(f"Based on {X.shape[0]} baseline subgraphs, the optimal Contamination parameter is Nu = {best_nu['nu']}.")
        print(f"This setting will trigger approximately {best_nu['ensemble_alerts']} alerts per {lookback_hours}-hour period ")
        print(f"({best_nu['alert_rate']:.1f}% daily operational noise floor).")
        print("\nTo apply this, update the initialized `contamination={best_nu['nu']}` inside `anomaly_detector.py`.")
        
    except Exception as e:
        logger.error(f"Calibration failed: {e}")

if __name__ == "__main__":
    hours = 12
    if len(sys.argv) > 1:
        hours = int(sys.argv[1])
    run_calibration(lookback_hours=hours)
