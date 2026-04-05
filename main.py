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

def main():
    global last_hunted_timestamp
    MODEL_PATH = os.getenv("MODEL_PATH", "models/sentinel_baseline.joblib")
    GNN_PATH = os.getenv("GNN_PATH", "models/gnn_weights.pth")

    opensearch_host = os.getenv("OPENSEARCH_HOST", "localhost")
    opensearch_port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    log_consumer = OpenSearchPollingConsumer(host=opensearch_host, port=opensearch_port)
    builder = GraphBuilder(log_consumer=log_consumer)
    encoder = TopologicalGraphEncoder(hidden_channels=64, out_channels=32)
    detector = AnomalyDetector(nu=0.03, contamination=0.03, strategy=VotingStrategy.MAJORITY)
    investigator = LLMInvestigator()
    cti = CTIIntegration()
    engine = ReportingEngine()

    if os.path.exists(MODEL_PATH) and os.path.exists(GNN_PATH):
        logger.info("[INIT] Found models. Rapid Boot initiated...")
        detector.load(MODEL_PATH)
        encoder.load(GNN_PATH)
    else:
        logger.info("[INIT] Training required (approx 2 mins)...")
        now = datetime.now(timezone.utc)
        start = get_utc_timestamp(now - timedelta(days=1))
        end = get_utc_timestamp(now)
        logs = builder.fetch_logs(start, end)
        if logs:
            graphs = builder.build_graphs(logs)
            embeddings, _ = encoder.extract_embeddings_with_ids([g for g in graphs if g.number_of_nodes() >= 2], is_training=True)
            detector.train(embeddings.numpy())
            detector.save(MODEL_PATH); encoder.save(GNN_PATH)
    
    load_state()
    logger.info("[SHIELD] SENTINEL HUNTER ACTIVE (3% SENSITIVITY) [SHIELD]")
    
    while not stop_event.is_set():
        try:
            now = datetime.now(timezone.utc)
            with state_lock:
                start = last_hunted_timestamp or get_utc_timestamp(now - timedelta(minutes=15))
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
                                    for g_id, r in reports.items():
                                        r.update({'confidence_score': details['confidence_score'], 'graph_id': g_id, 'strategy': details['strategy']})
                                        engine.ingest_incident(r, g_id)
                                        return f"[ALERT] {r.get('incident_title')}"
                            except Exception as e:
                                return f"[ERROR] {a_id}: {e}"

                        executor = concurrent.futures.ThreadPoolExecutor(
                            max_workers=10, thread_name_prefix="forensic"
                        )
                        try:
                            futures = {executor.submit(forensic_worker, a_id): a_id for a_id in anomalies}
                            for future in concurrent.futures.as_completed(futures, timeout=300):
                                res = future.result()
                                if res:
                                    logger.info(res)
                        finally:
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
