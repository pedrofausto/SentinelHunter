"""
sequence_detector.py
====================
Option 3: Dedicated Sequence Model (Markov Chain) for Behavioral Detection

This script models traffic not as individual flows, but as SEQUENCES of actions
taken by each Source IP over time.
e.g. A benign user session:  Port 80 -> Port 443 -> URL /login -> URL /dashboard
e.g. A brute force session:  URL /login -> URL /login -> URL /login -> URL /login

It builds an unsupervised Markov Chain of transition probabilities from benign traffic.
Any IP whose sequence contains highly improbable transitions (or incredibly long 
repetitive chains) is flagged as an anomaly.
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import pandas as pd
from collections import defaultdict

# ─── Config ──────────────────────────────────────────────────────────────────
CSV_PATH = os.path.join(os.path.dirname(__file__), "samples", "cybersecurity.csv")
# ─────────────────────────────────────────────────────────────────────────────

class MarkovSequenceDetector:
    def __init__(self):
        # Maps (state_A -> state_B) to a probability count
        self.transitions = defaultdict(lambda: defaultdict(int))
        self.state_counts = defaultdict(int)
        
    def _extract_state(self, row):
        """Define what a 'state' is in our Markov Chain."""
        # If there's a URL, the state is the URL (application layer).
        # Otherwise, the state is the destination port (network layer).
        url = str(row['url'])
        if url != 'nan' and url != '':
            # Just take the base path or a truncated version to group states
            return f"URL:{url.split('?')[0][:30]}"
        return f"PORT:{int(row['dst_port'])}"

    def fit(self, df_benign: pd.DataFrame):
        """Learn normal transitions from benign traffic sequences."""
        print("Training Markov Chain on benign sequences...")
        
        # Sort chronologically
        df_sorted = df_benign.sort_values('timestamp')
        
        # Group by Source IP to get the sequences
        for src_ip, group in df_sorted.groupby('src_ip'):
            states = group.apply(self._extract_state, axis=1).tolist()
            
            # Record transitions
            for i in range(len(states) - 1):
                state_a = states[i]
                state_b = states[i+1]
                self.transitions[state_a][state_b] += 1
                self.state_counts[state_a] += 1
                
        print(f"Learned {len(self.state_counts)} unique states and their normal transitions.")

    def _get_transition_prob(self, a, b):
        """Calculate P(B | A) with simple Laplace smoothing."""
        count_ab = self.transitions.get(a, {}).get(b, 0)
        total_a = self.state_counts.get(a, 0)
        
        # If we've never seen state_a, the probability transitions are unknown (anomaly)
        if total_a == 0:
            return 1e-4
            
        return (count_ab + 0.1) / (total_a + 0.1 * len(self.state_counts))

    def score_sequence(self, sequence):
        """
        Score a sequence using negative log-likelihood.
        Higher score = More anomalous (bizarre sequences).
        We average by sequence length so long benign sessions aren't penalized.
        """
        if len(sequence) < 2:
            return 0.0 # Single events aren't sequences
            
        nll = 0.0
        # Check standard transitions
        for i in range(len(sequence) - 1):
            p = self._get_transition_prob(sequence[i], sequence[i+1])
            nll -= np.log(p)
            
        # Add a penalty for extreme repetition (brute-force signature)
        # If the same state repeats M times in a row, the sequence is suspicious.
        repeats = 0
        for i in range(len(sequence) - 1):
            if sequence[i] == sequence[i+1]:
                repeats += 1
                
        # Heuristic: More than 5 exact repeats of the same URL/Port is highly anomalous
        repetition_penalty = max(0, repeats - 5) * 5.0
        
        return (nll / len(sequence)) + repetition_penalty

    def detect(self, df: pd.DataFrame, threshold: float = 10.0):
        """Score all IPs in the dataframe."""
        df_sorted = df.sort_values('timestamp')
        
        results = []
        for src_ip, group in df_sorted.groupby('src_ip'):
            states = group.apply(self._extract_state, axis=1).tolist()
            score = self.score_sequence(states)
            
            # To measure performance, let's grab the true label of this IP
            # We assume an IP is malicious if *any* of its flows are malicious.
            is_malicious = (group['label'].astype(int) == 1).any()
            attack_type = group['attack_type'].iloc[0] if is_malicious else "benign"
            
            results.append({
                'src_ip': src_ip,
                'is_anomaly': score > threshold,
                'score': score,
                'sequence_length': len(states),
                'true_label': 1 if is_malicious else 0,
                'attack_type': attack_type,
                'sample_sequence': " -> ".join(states[:4]) + ("..." if len(states)>4 else "")
            })
            
        return pd.DataFrame(results)

def main():
    print("\n" + "="*60)
    print(" Option 3: Sequence/Markov Anomaly Detector (Blind Test)")
    print("="*60)
    
    df = pd.read_csv(CSV_PATH)
    
    # 1. Train on Benign only
    df_benign = df[df['label'] == 0].drop(columns=['attack_type', 'label'], errors='ignore')
    
    detector = MarkovSequenceDetector()
    detector.fit(df_benign)
    
    # 2. Score everyone
    print("\nScoring all IPs based on their Action Sequences...")
    results_df = detector.detect(df, threshold=5.0) # threshold chosen heuristically
    
    # 3. Metrics
    y_true = results_df['true_label']
    y_pred = results_df['is_anomaly'].astype(int)
    
    tp = ((y_pred == 1) & (y_true == 1)).sum()
    fp = ((y_pred == 1) & (y_true == 0)).sum()
    tn = ((y_pred == 0) & (y_true == 0)).sum()
    fn = ((y_pred == 0) & (y_true == 1)).sum()
    
    print("\n" + "-"*40)
    print(" IP-Level Sequence Detection Results")
    print("-"*40)
    print(f" Total IPs analyzed : {len(results_df)}")
    print(f" True Positives (Attackers caught) : {tp}")
    print(f" False Positives (Benign flagged)  : {fp}")
    print(f" False Negatives (Attackers missed): {fn}")
    
    if (tp + fp) > 0:
        print(f" Precision: {tp / (tp+fp):.3f}")
    if (tp + fn) > 0:
        print(f" Recall:    {tp / (tp+fn):.3f}")
        
    print("\n Breakdown of Attackers Caught by Sequence Model:")
    malicious = results_df[results_df['true_label'] == 1]
    for atype, grp in malicious.groupby('attack_type'):
        caught = grp['is_anomaly'].sum()
        total = len(grp)
        print(f"   {atype:<20} {caught}/{total} IPs caught ({(caught/total):.0%})")
        
    print("\n Top 3 Most Anomalous Sequences Found:")
    top_anomalies = results_df.sort_values('score', ascending=False).head(3)
    for _, row in top_anomalies.iterrows():
        print(f"   IP: {row['src_ip']:<15} Score: {row['score']:.1f}  Type: {row['attack_type']}")
        print(f"   Seq: {row['sample_sequence']}\n")

if __name__ == "__main__":
    main()
