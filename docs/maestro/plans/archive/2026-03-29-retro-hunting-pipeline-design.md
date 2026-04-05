---
title: Retro Hunting Pipeline MVP Design
status: approved
date: 2026-03-29
design_depth: deep
task_complexity: complex
---

# Design Document: Retro Hunting Pipeline MVP

## 1. Problem Statement
We are building a complete Python-based Minimum Viable Product (MVP) for a 100% autonomous Retro Hunting pipeline. Traditional Security Information and Event Management (SIEM) rules rely on static indicators (Sigma, YARA) which are easily bypassed by Living off the Land (LotL) techniques and Advanced Persistent Threats (APTs). 

This pipeline shifts the paradigm from analyzing isolated logs to evaluating systemic, topological behavior. It ingests historical logs (Wazuh/Sysmon) directly from an OpenSearch cluster, constructs directed Provenance Graphs, and utilizes a Relational Graph Convolutional Network (RGCN) to generate dense vector embeddings that ignore fragile textual attributes. A One-Class Support Vector Machine (SVM) will continuously learn the "normal" baseline of these subgraphs and isolate statistical anomalies. Finally, these anomalies are passed to an LLM (switchable between local Ollama and cloud Gemini) acting as a forensic investigator to extract MITRE ATT&CK TTPs and IOCs, outputting a strict JSON report that is automatically orchestrated into OpenCTI as a structured Incident.

## 2. Requirements

### Functional Requirements
*   **REQ-1**: The system must extract heterogeneous logs (sysmon, auditd, ebpf, Tracee, syslog) from a live OpenSearch cluster for specific time windows.
*   **REQ-2**: The system must convert logs into directed Provenance Graphs (nodes = processes/files/IPs, edges = actions) using NetworkX.
*   **REQ-3**: The system must encode graphs into dense vectors using an RGCN (PyTorch Geometric), initializing nodes with Type + Degree vectors while strictly ignoring textual attributes.
*   **REQ-4**: The system must train a One-Class SVM on baseline graph embeddings, pooling nodes to create embeddings for entire subgraphs (grouped by process tree or logon session) to detect anomalies.
*   **REQ-5**: The orchestrator must run asynchronously, training the model in memory every X minutes on historical data, and hunting on recent data every Y minutes without blocking.
*   **REQ-6**: The LLM module must use a strict DFIR system prompt to analyze anomalous subgraphs, extract IOCs/TTPs, and return strictly formatted JSON, with a fallback mechanism for invalid JSON.
*   **REQ-7**: The system must support a configurable switch between a local LLM (e.g., Llama 3 via Ollama) and a cloud LLM (Google Gemini).
*   **REQ-8**: The CTI module must ingest the LLM's JSON report into OpenCTI via URL/Token, creating an Incident with linked Observables and Attack Patterns.

### Non-Functional & Constraints
*   **REQ-9**: The CTI integration relies entirely on an external instance via environment variables, keeping the local `docker-compose.yml` scoped to OpenSearch and Ollama.
*   **REQ-10**: The code must be production-ready Python, fully modularized (5 specific files + `main.py`), PEP-8 compliant, and include robust `try/except` error handling, type hints, and docstrings.

## 3. Approach

**Selected Approach: Asynchronous Threaded Orchestrator with Subgraph-Level GNN**
The MVP will utilize a multithreaded orchestrator `main.py` where a training thread continuously updates an in-memory Scikit-Learn One-Class SVM every X minutes, while a separate hunting thread evaluates rolling windows every Y minutes. The `graph_builder.py` will parse heterogeneous, real-world log structures (sysmon, auditd, ebpf, Tracee, syslog) into NetworkX graphs. Nodes will be initialized strictly via their topological role (Type + Degree). Crucially, the PyTorch Geometric RGCN will generate embeddings that are then pooled into representations of entire subgraphs (grouped by process trees or logon sessions). The anomaly detector will evaluate these subgraph-level vectors. Anomalies are passed to a polymorphic LLM interface (Ollama/Gemini) enforcing strict JSON output, which is finally orchestrated into an external, existing OpenCTI instance via environment variables.

**Key Decisions**
*   **Subgraph-Level Anomaly Detection** — *[Selected because evaluating entire process trees or logon sessions provides the necessary context to detect LotL techniques, rather than alerting on isolated anomalous nodes]* (Traces To: REQ-4).
*   **Asynchronous Threads** — *[Selected because the system must guarantee strict Y-minute SLAs for hunting regardless of baseline training time]* (Traces To: REQ-5).
*   **External OpenCTI Integration** — *[Selected to keep the local `docker-compose.yml` lean, relying on URL/API keys to connect to an existing CTI infrastructure]* (Traces To: REQ-9).
*   **Multi-format Log Support** — *[Selected to handle real-world telemetry (sysmon, auditd, ebpf, etc.) without requiring a normalized intermediary format upfront]* (Traces To: REQ-1).

## 4. Architecture

1.  **Data Ingestion (`graph_builder.py`)**: Connects to OpenSearch. Fetches heterogeneous logs based on defined time windows. Parses these into `NetworkX.DiGraph` objects where nodes are entities and edges are actions.
2.  **Topological Encoding (`gnn_encoder.py`)**: Converts NetworkX graphs into `torch_geometric.data.Data`. Node features are initialized as Type + Degree vectors. The RGCN computes node-level embeddings, pooled at the subgraph level (`process_tree_id` or `logon_id`) to create a single dense vector representing the systemic action.
3.  **Anomaly Detection (`anomaly_detector.py`)**: Maintains a thread-safe `sklearn.svm.OneClassSVM` model in memory. The Training Thread updates this model using baseline vectors. The Hunting Thread calculates distance from the normality hypersphere, flagging outliers.
4.  **Forensic Reasoning (`llm_investigator.py`)**: Outlier subgraphs are sent to the configured LLM. Applies a strict DFIR system prompt to extract IOCs/TTPs, returning validated JSON.
5.  **CTI Orchestration (`cti_integration.py`)**: Parses the LLM JSON and pushes findings to OpenCTI as an Incident with linked Observables and Attack Patterns.

## 5. Agent Team
*   **`data_engineer`**: Implements `graph_builder.py` (OpenSearch queries, log parsing, graph construction).
*   **`coder`**: Implements `gnn_encoder.py`, `anomaly_detector.py`, `llm_investigator.py`, and `main.py` orchestration.
*   **`security_engineer`**: Implements `cti_integration.py` and crafts the DFIR system prompt.
*   **`code_reviewer`**: Runs final quality gate.

## 6. Risk Assessment
**Risk Level**: High
1.  **Memory Exhaustion (GNN/Graphs)**: Limit nodes per subgraph, garbage collect older graphs, use efficient pooling.
2.  **LLM JSON Hallucination**: Implement 3x retry with regex fallback in `llm_investigator.py`.
3.  **Thread Safety (Model Updating)**: Training thread instantiates a new SVM object and swaps via mutex to prevent blocking/corruption.
4.  **Log Parsing Fragility**: Use generic, permissive schema focusing strictly on the 5-tuple (source, action, target, timestamp, type).

## 7. Success Criteria
1.  **Pipeline Autonomy**: `main.py` runs continuously, handling train/hunt loops asynchronously.
2.  **Structural GNN Resistance**: Embeddings rely purely on topology (Type + Degree), ignoring text.
3.  **Accurate Detection**: Outlier subgraphs are isolated correctly.
4.  **Resilient LLM Parsing**: Consistent JSON output from local or cloud LLMs.
5.  **Successful CTI Ingestion**: verifiable Incidents in external OpenCTI.
6.  **Code Quality**: PEP-8 compliant, type hints, docstrings.
