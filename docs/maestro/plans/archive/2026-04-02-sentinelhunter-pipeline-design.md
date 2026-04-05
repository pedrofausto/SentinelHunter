---
status: approved
created_at: 2026-04-02
design_depth: quick
task_complexity: medium
---

# Design Document: SentinelHunter Threat Pipeline

## 1. Problem Statement
SentinelHunter is an advanced threat hunting orchestrator designed to identify multi-stage attack patterns (APTs) missed by traditional rule-based SIEMs. The primary objective is to build a robust, stateful pipeline that reconstructs fragmented logs from OpenSearch into directed provenance graphs. By leveraging a PyTorch Geometric GNN, the system encodes topological behaviors into fixed-size embeddings. These embeddings are evaluated by a Triple Ensemble (OC-SVM, Isolation Forest, COPOD) using Majority Voting to flag top-percentile anomalies relative to a 24-hour baseline. High-fidelity alerts are then forensically investigated via the Gemini LLM and enriched with OpenCTI data. The solution must support a "Wipe State" mechanism for retroactive hunting via a Streamlit dashboard, handle disconnected graph nodes through ancestry stitching, and manage high-volume logs with OpenSearch connection pooling (maxsize=25). The orchestrator will be refactored and integrated into the existing codebase, using a Hybrid Adapter ingestion layer and Periodic Batch Training for GNN weight updates.

## 2. Requirements

**Functional Requirements:**
- **Graph Reconstruction:** Consume logs via OpenSearch and reconstruct them into directed NetworkX provenance graphs, grouping by `session_id` and stitching execution ancestry (e.g., cmd.exe -> powershell.exe).
- **GNN Embedding:** Process provenance graphs with a Topological GNN (PyTorch Geometric) to extract fixed-size 32-dimensional embeddings via Graph Convolutional Layers and global pooling.
- **Anomaly Detection:** Evaluate embeddings via a Triple Ensemble (OC-SVM, Isolation Forest, COPOD) using Majority Voting (at least 2/3 agree) to flag the top 1% of anomalies against a 24-hour baseline.
- **Forensic Investigation:** Forward high-fidelity anomalous graphs and OpenCTI hints to the Gemini LLM for automated structured JSON reports (Severity, TTPs, Risk Justification).
- **Interactive UI:** Implement a Streamlit dashboard with Cytoscape.js for visual exploration, including a "Wipe State" control to reset checkpoint state for manual re-hunting of backdated data.

**Non-Functional Requirements & Constraints:**
- **Robustness:** Gracefully handle disconnected nodes caused by out-of-order logs. Utilize OpenSearch connection pooling (`maxsize=25`) for IO stability.
- **Integration:** Refactor and integrate existing components (`graph_builder.py`, `gnn_encoder.py`) into a cohesive orchestrator.
- **Ingestion Strategy:** Use a Hybrid Adapter pattern—polling OpenSearch now, but architecturally primed for a future Kafka/Flink streaming migration.
- **Training Strategy:** Adopt Periodic Batch Training for updating the GNN weights to maintain baseline stability without risking catastrophic forgetting.

## 3. Approach

**Selected Approach: Refactor & Integrate with Hybrid Adapter**
The architecture will orchestrate the existing SentinelHunter components (`graph_builder.py`, `gnn_encoder.py`, `llm_investigator.py`, etc.) via a unified controller (`main.py`). The ingestion layer will implement a Hybrid Adapter, polling OpenSearch efficiently with connection pooling (`maxsize=25`) while exposing clean interfaces ready for a future Kafka migration. To reconstruct accurate provenance graphs, the `Graph Builder` will use ancestry-stitching queries to bridge disconnected nodes caused by out-of-order logs. The `Topological GNN` will convert these into 32-dimensional embeddings. The `Triple Ensemble` will evaluate the embeddings using a 2/3 Majority Voting mechanism relative to a 24-hour batch-trained baseline. Flagged anomalies are then enriched with OpenCTI data and passed to the Gemini LLM for a structured JSON forensic report, which is finally rendered on a Streamlit dashboard with Cytoscape.js.

**Alternatives Considered:**
- **Clean Slate Recreation:** Rewriting the pipeline from scratch was rejected because the existing modules already contain robust logic for log parsing and NetworkX conversion; refactoring is the pragmatic path.
- **Immediate Real-Time Streaming:** Attempting a direct Kafka/Flink migration was rejected due to current infrastructure constraints. The Hybrid Adapter provides safety now with scalability later.
- **Incremental GNN Learning:** Dynamic weight updates were rejected in favor of Periodic Batch Training to prevent catastrophic forgetting and ensure a stable 24-hour baseline.

## 4. Risk Assessment

- **Cold-Start Problem (High):** The pipeline requires at least 1 hour of clean traffic to establish a reliable baseline before it can hunt accurately. *Mitigation:* The Hybrid Adapter ingestion layer uses connection pooling to reliably fetch backdated logs, and the Streamlit dashboard provides a "Wipe State" mechanism to re-process historical logs, enabling manual baseline establishment.
- **Disconnected Nodes (Medium):** Logs arriving out of order or lacking shared attributes can fragment the reconstructed execution graphs. *Mitigation:* The `Graph Builder` employs an ancestry-stitching strategy, querying OpenSearch directly to explicitly resolve missing parent/child links via `session_id`, effectively bridging gaps in the provenance graphs.
- **Computational Overhead (Medium):** GNN inference and extensive ancestry fetching are IO- and resource-intensive. *Mitigation:* OpenSearch connection pooling is strictly bounded (`maxsize=25`), and the PyTorch Geometric model is streamlined to output a low-footprint 32-dim embedding vector. The downstream Triple Ensemble evaluation is highly efficient and runs fast on CPU.
- **Model Drift (Low):** The GNN and Ensemble thresholds may lose alignment with normal traffic over time. *Mitigation:* Adopting Periodic Batch Training over incremental learning prevents rapid, catastrophic forgetting and ensures the 24-hour baseline remains stable and explicitly managed.