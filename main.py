import logging
import os, time, threading, json, sys, signal, concurrent.futures
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser
from dotenv import load_dotenv
from lib.consumers import LogConsumer, OpenSearchPollingConsumer
from graph_builder import GraphBuilder
from gnn_encoder import TopologicalGraphEncoder
from anomaly_detector import AnomalyDetector, VotingStrategy
from llm_investigator import LLMInvestigator
from cti_integration import CTIIntegration
from reporting_engine import ReportingEngine

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("SentinelHunterOrchestrator")

# @MX:WARN: [AUTO] Global mutable state accessed from main thread and signal handler.
# @MX:REASON: stop_event/state_lock/last_hunted_timestamp are shared across the hunt loop and SIGINT handler;
#             all reads/writes to last_hunted_timestamp MUST be done under state_lock.
stop_event = threading.Event()
state_lock = threading.Lock()
last_hunted_timestamp = None

def get_utc_timestamp(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def save_state(interval):
    with state_lock:
        state = {"last_hunted_timestamp": last_hunted_timestamp, "adaptive_hunt_interval": interval}
        try:
            with open(".sentinel_state.json", 'w') as f:
                json.dump(state, f)
        except Exception as e:
            logger.error(f"[STATE] Save failed: {e}")

def load_state():
    global last_hunted_timestamp
    if os.path.exists(".sentinel_state.json"):
        try:
            with open(".sentinel_state.json", 'r') as f:
                state = json.load(f)
                # Use state_lock for consistency even though load_state runs before the hunt loop starts.
                with state_lock:
                    last_hunted_timestamp = state.get('last_hunted_timestamp')
                return state.get('adaptive_hunt_interval', 1)
        except Exception:
            pass
    return 1

def run_weekend_retraining(builder, encoder, detector, MODEL_PATH, GNN_PATH):
    """
    Scheduled weekend batch retraining over a 14-day historical window.
    Excludes explicitly tagged noisy data (e.g., admin jump-boxes, vulnerability scanners) to prevent concept drift poisoning.
    """
    logger.info("[MLOPS] Starting 14-day historical batch retraining...")
    now = datetime.now(timezone.utc)
    start = get_utc_timestamp(now - timedelta(days=14))
    end = get_utc_timestamp(now)
    
    # Data Cleansing: Tag/Filter specific noisy subnets or entities 
    noisy_exclusion_ids = ["admin_jumpbox_01", "qualys_scanner_group"] 

    logs = builder.fetch_logs(start, end, exclude_ids=noisy_exclusion_ids)
    if logs:
        graphs = builder.build_graphs(logs)
        embeddings, _ = encoder.extract_embeddings_with_ids([g for g in graphs if g.number_of_nodes() >= 2], is_training=True)
        detector.train(embeddings.numpy())
        detector.save(MODEL_PATH)
        encoder.export_model(GNN_PATH)
        logger.info("[MLOPS] 14-Day Batch Retraining Complete. Model exported successfully.")
    else:
        logger.warning("[MLOPS] No logs found for the 14-day retrain period.")

def main():
    global last_hunted_timestamp
    MODEL_PATH = os.getenv("MODEL_PATH", "models/sentinel_baseline.joblib")
    GNN_PATH = os.getenv("GNN_PATH", "models/gnn_weights.pth")

    opensearch_host = os.getenv("OPENSEARCH_HOST", "localhost")
    opensearch_port = int(os.getenv("OPENSEARCH_PORT", "9201"))
    log_consumer = OpenSearchPollingConsumer(host=opensearch_host, port=opensearch_port)
    builder = GraphBuilder(host=opensearch_host, port=opensearch_port, log_consumer=log_consumer)
    encoder = TopologicalGraphEncoder(hidden_channels=64, out_channels=32)
    detector = AnomalyDetector(nu=0.03, contamination=0.03, strategy=VotingStrategy.MAJORITY)
    investigator = LLMInvestigator()
    cti = CTIIntegration()
    engine = ReportingEngine(host=opensearch_host, port=opensearch_port)

    if os.path.exists(MODEL_PATH) and os.path.exists(GNN_PATH):
        logger.info("[INIT] Found models. Rapid Boot initiated...")
        detector.load(MODEL_PATH)
        encoder.load_model_for_inference(GNN_PATH)
    else:
        logger.warning("[INIT] Models not found! You must run the 14-day weekend batch retraining cycle. Operating in degraded mode.")

    # ---------------------------------------------------------
    # Shadow Mode Initialization
    # ---------------------------------------------------------
    SHADOW_MODEL_PATH = os.getenv("SHADOW_MODEL_PATH", "models/sentinel_shadow.joblib")
    SHADOW_GNN_PATH = os.getenv("SHADOW_GNN_PATH", "models/gnn_shadow_weights.pth")
    shadow_detector, shadow_encoder = None, None
    if os.path.exists(SHADOW_MODEL_PATH) and os.path.exists(SHADOW_GNN_PATH):
        logger.info("[INIT] Shadow models found. Enabling Shadow Mode for silent evaluation.")
        shadow_detector = AnomalyDetector(nu=0.03, contamination=0.03, strategy=VotingStrategy.MAJORITY)
        shadow_encoder = TopologicalGraphEncoder(hidden_channels=64, out_channels=32)
        shadow_detector.load(SHADOW_MODEL_PATH)
        shadow_encoder.load_model_for_inference(SHADOW_GNN_PATH)

    load_state()
    logger.info("[SHIELD] SENTINEL HUNTER ACTIVE (3% SENSITIVITY) [SHIELD]")
    
    while not stop_event.is_set():
        try:
            now = datetime.now(timezone.utc)
            with state_lock:
                # The Memory Wall: Bound triage window strictly to 2 hours
                start = last_hunted_timestamp or get_utc_timestamp(now - timedelta(hours=2))
                end = get_utc_timestamp(now)

            logs = builder.fetch_logs(start, end)
            if logs:
                logger.info(f"[HUNT] Window: {start} -> {end} | Logs: {len(logs)}")
                all_graphs = builder.build_graphs(logs)
                graphs = [g for g in all_graphs if g.number_of_nodes() >= 3] # Only complex behaviors
                
                if graphs:
                    logger.info(f"[HUNT] Encoding {len(graphs)} subgraphs...")
                    embeddings, ids = encoder.extract_embeddings_with_ids(graphs)
                    anomalies, scores_map = detector.detect(embeddings.numpy(), ids)
                    
                    # ---------------------------------------------------------
                    # Shadow Mode Telemetry Hook
                    # ---------------------------------------------------------
                    if shadow_detector and shadow_encoder:
                        try:
                            shadow_embeds, _ = shadow_encoder.extract_embeddings_with_ids(graphs)
                            shadow_anomalies, _ = shadow_detector.detect(shadow_embeds.numpy(), ids)
                            if len(shadow_anomalies) != len(anomalies):
                                logger.info(f"[SHADOW MODE] Discrepancy metric logged. Prod found {len(anomalies)} anomalies, Shadow found {len(shadow_anomalies)}.")
                        except Exception as shadow_err:
                            logger.error(f"[SHADOW MODE] Telemetry Error: {shadow_err}")

                    if anomalies:
                        logger.info(f"[ALERT] ANALYZING {len(anomalies)} DETECTIONS IN PARALLEL [ALERT]")

                        # @MX:WARN: [AUTO] ThreadPoolExecutor runs forensic workers concurrently.
                        # @MX:REASON: Each worker calls fetch_logs_with_ancestry and LLM investigate;
                        #             set a per-task timeout to prevent hung threads from blocking shutdown.
                        def forensic_worker(a_id):
                            try:
                                details = scores_map[a_id]
                                context = builder.fetch_logs_with_ancestry(start, end, filter_id=a_id)
                                unified = builder.build_unified_graph(context, graph_id=a_id)
                                if unified:
                                    reports = investigator.investigate([unified], cti_hints=[f"CONF: {details['confidence_score']:.2f}"])
                                    
                                    # Collect original doc IDs for graph reconstruction in the dashboard
                                    src_ids = [l.get('_id') for l in context if l.get('_id')]
                                    
                                    for g_id, r in reports.items():
                                        # Blend: 60% GNN ensemble score (statistical) +
                                        #        40% LLM analytical confidence (evidence quality).
                                        llm_conf = float(r.get('confidence_score', 0.5))
                                        det_conf = float(details['confidence_score'])
                                        blended_conf = round(0.6 * det_conf + 0.4 * llm_conf, 3)
                                        
                                        r.update({
                                            'confidence_score': blended_conf, 
                                            'graph_id': g_id, 
                                            'strategy': details['strategy'],
                                            'source_doc_ids': src_ids
                                        })
                                        engine.ingest_incident(r, g_id)
                                        return f"[ALERT] {r.get('incident_title')}"
                            except Exception as e:
                                return f"[ERROR] {a_id}: {e}"

                        executor = concurrent.futures.ThreadPoolExecutor(
                            max_workers=10, thread_name_prefix="forensic"
                        )
                        try:
                            futures_dict = {executor.submit(forensic_worker, a_id): a_id for a_id in anomalies}
                            
                            # Polling loop to keep the main thread responsive to signals on Windows
                            while not stop_event.is_set() and futures_dict:
                                done, _ = concurrent.futures.wait(
                                    futures_dict.keys(), 
                                    timeout=1.0, 
                                    return_when=concurrent.futures.FIRST_COMPLETED
                                )
                                for f in done:
                                    res = f.result()
                                    if res:
                                        logger.info(res)
                                    futures_dict.pop(f)
                            
                            if stop_event.is_set() and futures_dict:
                                logger.warning(f"[TERMINATION] Cancelling {len(futures_dict)} pending investigative tasks...")
                        finally:
                            # shutdown(cancel_futures=True) is Python 3.9+
                            if sys.version_info >= (3, 9):
                                executor.shutdown(wait=False, cancel_futures=True)
                            else:
                                executor.shutdown(wait=False)
                else:
                    logger.info(f"[HUNT] No complex behaviors in {len(all_graphs)} subgraphs.")
            
            with state_lock:
                last_hunted_timestamp = end
                save_state(1)
            # Use stop_event.wait() instead of time.sleep() so Ctrl+C wakes the loop immediately.
            stop_event.wait(timeout=60)

        except Exception as e:
            logger.error(f"Hunt loop error: {e}", exc_info=True)
            stop_event.wait(timeout=10)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: stop_event.set())
    main()
