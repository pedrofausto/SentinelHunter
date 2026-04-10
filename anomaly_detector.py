import numpy as np
import logging
import threading
import os
import joblib
from enum import Enum
from sklearn.svm import OneClassSVM
from pyod.models.iforest import IForest
from pyod.models.copod import COPOD
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple, Dict, Any

logger = logging.getLogger(__name__)

class VotingStrategy(Enum):
    AVERAGE = "AVERAGE"   # Weighted average score > threshold
    MAJORITY = "MAJORITY" # 2 out of 3 models flag as anomaly
    UNION = "UNION"       # ANY model flags as anomaly (Highest Recall)

class AnomalyDetector:
    """
    Stabilized Triple Ensemble Anomaly Detector.
    Uses One-Class SVM, Isolation Forest, and COPOD.
    Supports Average, Majority, and Union voting strategies.
    """

    def __init__(self, nu: float = 0.10, contamination: float = 0.10, strategy: VotingStrategy = VotingStrategy.MAJORITY):
        self.nu = nu
        self.contamination = contamination
        self.strategy = strategy
        
        self.weights = {'ocsvm': 0.4, 'iforest': 0.3, 'copod': 0.3}
        self.oc_svm = OneClassSVM(nu=nu, kernel='rbf', gamma='scale')
        self.iso_forest = IForest(contamination=contamination, random_state=42)
        self.copod = COPOD(contamination=contamination)
        self.scaler = StandardScaler()
        
        self.thresholds = {'ocsvm': 0.0, 'iforest': 0.0, 'copod': 0.0, 'consensus': 0.0}
        self.is_trained = False
        self._lock = threading.Lock()

    def train(self, embeddings: np.ndarray):
        if len(embeddings) < 2:
            logger.warning("Insufficient baseline data. Training aborted.")
            return

        logger.info(f"Training Ensemble (OCSVM + IF + COPOD) on {len(embeddings)} samples...")
        new_scaler = StandardScaler()
        scaled = new_scaler.fit_transform(embeddings)

        new_oc_svm = OneClassSVM(nu=self.nu, kernel='rbf', gamma='scale')
        new_iso_forest = IForest(contamination=self.contamination, random_state=42)
        new_copod = COPOD(contamination=self.contamination)

        new_oc_svm.fit(scaled)
        new_iso_forest.fit(scaled)
        new_copod.fit(scaled)
        
        s_scores_base = -new_oc_svm.decision_function(scaled)
        i_scores_base = new_iso_forest.decision_scores_
        c_scores_base = new_copod.decision_scores_
        
        limit = 100 * (1 - self.nu)
        # Enforce a small baseline floor (0.05) to avoid "Zero-Threshold Avalanches" 
        # on very uniform benign datasets.
        new_thresholds = {
            'ocsvm': max(0.05, float(np.percentile(s_scores_base, limit))),
            'iforest': max(0.05, float(np.percentile(i_scores_base, limit))),
            'copod': max(0.05, float(np.percentile(c_scores_base, limit)))
        }
        
        combined_baseline = (s_scores_base * 0.4 + i_scores_base * 0.3 + c_scores_base * 0.3)
        new_thresholds['consensus'] = max(0.05, float(np.percentile(combined_baseline, limit)))

        with self._lock:
            self.scaler, self.oc_svm, self.iso_forest, self.copod = new_scaler, new_oc_svm, new_iso_forest, new_copod
            self.thresholds = new_thresholds
            self.is_trained = True
        logger.info(f"Training Complete. Thresholds: {new_thresholds}")

    def detect(self, embeddings: np.ndarray, graph_ids: List[str]) -> Tuple[List[str], Dict[str, Any]]:
        with self._lock:
            if not self.is_trained: raise ValueError("Detector not trained.")
            m_svm, m_if, m_copod, m_scaler, m_threshs = self.oc_svm, self.iso_forest, self.copod, self.scaler, self.thresholds

        if len(embeddings) == 0: return [], {}
        scaled = m_scaler.transform(embeddings)
        s_scores = -m_svm.decision_function(scaled)
        i_scores = m_if.decision_function(scaled)
        c_scores = m_copod.decision_function(scaled)
        combined_scores = (s_scores * 0.4 + i_scores * 0.3 + c_scores * 0.3)

        anomalous_ids, detailed_scores = [], {}
        for i, g_id in enumerate(graph_ids):
            f_svm = s_scores[i] > m_threshs.get('ocsvm', 0.0)
            f_if = i_scores[i] > m_threshs.get('iforest', 0.0)
            f_copod = c_scores[i] > m_threshs.get('copod', 0.0)
            f_avg = combined_scores[i] > m_threshs.get('consensus', 0.0)
            
            votes = sum([f_svm, f_if, f_copod])
            is_anomaly = False
            if self.strategy == VotingStrategy.AVERAGE: is_anomaly = f_avg
            elif self.strategy == VotingStrategy.MAJORITY: is_anomaly = (votes >= 2)
            elif self.strategy == VotingStrategy.UNION: is_anomaly = (votes >= 1)
            
            if is_anomaly:
                anomalous_ids.append(g_id)
                # Scale confidence using a sigmoid so scores spread across [0.5, 1.0].
                # A score exactly at threshold → ~0.55; 2x threshold → ~0.76; 5x → ~0.93.
                # This prevents all anomalies collapsing to 100% when the ensemble
                # scores are uniformly high (common at nu=0.03).
                base_thresh = m_threshs.get('consensus', 0.1)
                if base_thresh > 0:
                    excess_ratio = combined_scores[i] / base_thresh  # 1.0 = right at threshold
                    norm_conf = float(1.0 / (1.0 + np.exp(-0.8 * (excess_ratio - 2.5))))
                else:
                    norm_conf = 0.5
                detailed_scores[g_id] = {
                    'confidence_score': norm_conf,
                    'raw_consensus': float(combined_scores[i]),
                    'ocsvm_score': float(s_scores[i]),
                    'iforest_score': float(i_scores[i]),
                    'copod_score': float(c_scores[i]),
                    'votes': int(votes),
                    'strategy': self.strategy.value
                }
        return anomalous_ids, detailed_scores

    def save(self, filepath: str):
        with self._lock:
            if not self.is_trained: return False
            state = {
                'scaler': self.scaler, 'oc_svm': self.oc_svm, 'iso_forest': self.iso_forest, 'copod': self.copod,
                'thresholds': self.thresholds, 'nu': self.nu, 'contamination': self.contamination,
                'weights': self.weights, 'strategy': self.strategy.value
            }
            joblib.dump(state, filepath)
            return True

    def load(self, filepath: str):
        if not os.path.exists(filepath): return False
        with self._lock:
            try:
                state = joblib.load(filepath)
                self.scaler, self.oc_svm, self.iso_forest, self.copod = state['scaler'], state['oc_svm'], state['iso_forest'], state['copod']
                self.thresholds = state.get('thresholds', {'consensus': state.get('threshold_score', 0.0)})
                self.nu = state.get('nu', 0.01)
                self.contamination = state.get('contamination', 0.01)
                self.strategy = VotingStrategy[state.get('strategy', 'MAJORITY')]
                self.is_trained = True
                return True
            except Exception: return False
