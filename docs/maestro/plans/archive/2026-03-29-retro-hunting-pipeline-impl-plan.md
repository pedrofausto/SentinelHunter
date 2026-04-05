---
title: Retro Hunting Pipeline MVP Implementation Plan
status: draft
date: 2026-03-29
task_complexity: complex
---

# Implementation Plan: Retro Hunting Pipeline MVP

## 1. Plan Overview
- **Total Phases**: 5
- **Agents Involved**: `data_engineer`, `coder`, `security_engineer`, `code_reviewer`
- **Estimated Effort**: High

### Token Budget Estimation
| Phase | Agent | Model | Est. Input | Est. Output | Est. Cost |
|-------|-------|-------|-----------|------------|----------|
| 1 | `data_engineer` | gemini-2.5-pro | 2000 | 500 | $0.06 |
| 2 | `coder` | gemini-2.5-pro | 3000 | 800 | $0.09 |
| 3a | `coder` | gemini-2.5-pro | 1500 | 400 | $0.05 |
| 3b | `security_engineer` | gemini-2.5-pro | 1500 | 400 | $0.05 |
| 4 | `coder` | gemini-2.5-pro | 3000 | 600 | $0.08 |
| 5 | `code_reviewer` | gemini-2.5-pro | 4000 | 200 | $0.07 |
| **Total** | | | **15000** | **2900** | **$0.40** |

## 2. Dependency Graph
```
Phase 1 (Data Ingestion - graph_builder.py)
  │
  ▼
Phase 2 (Core ML - gnn_encoder.py, anomaly_detector.py)
  │
  ├──► Phase 3a (AI Reasoning - llm_investigator.py) [PARALLEL]
  │
  └──► Phase 3b (CTI Integration - cti_integration.py) [PARALLEL]
         │      │
         ▼      ▼
Phase 4 (Orchestration - main.py)
  │
  ▼
Phase 5 (Quality & Validation)
```

## 3. Execution Strategy Table
| Stage | Phase | Agent | Files Targeted | Parallel |
|-------|-------|-------|----------------|----------|
| 1. Foundation | 1. Data Ingestion | `data_engineer` | `graph_builder.py` | No |
| 2. Core Domain | 2. Core ML | `coder` | `gnn_encoder.py`, `anomaly_detector.py` | No |
| 3. Integration | 3a. AI Reasoning | `coder` | `llm_investigator.py` | Yes |
| 3. Integration | 3b. CTI Orchestration | `security_engineer` | `cti_integration.py` | Yes |
| 4. Orchestration | 4. Async Threads | `coder` | `main.py` | No |
| 5. Quality | 5. Code Review | `code_reviewer` | All | No |

## 4. Phase Details

### Phase 1: Data Ingestion & Graph Building
- **Objective**: Refactor `graph_builder.py` to parse sysmon/auditd logs from OpenSearch and construct NetworkX graphs with Type + Degree node features, grouping them by `process_tree_id` or `logon_id` as distinct subgraphs.
- **Agent Assignment**: `data_engineer` (Data modeling and OpenSearch integration expertise).
- **Files to Modify**:
  - `graph_builder.py`: Implement logic to calculate in/out degree during graph creation. Implement logic to group parsed logs into lists of subgraphs.
- **Validation Criteria**: `python main.py` (mock logs) should successfully build graphs containing node features with degree metrics.
- **Dependencies**: 
  - `blocked_by`: []
  - `blocks`: [2]

### Phase 2: Core ML (GNN & SVM)
- **Objective**: Implement thread-safe pooling and mappings in `gnn_encoder.py` to aggregate node embeddings into a single subgraph vector. Update `anomaly_detector.py` to train/predict on these subgraph vectors with thread-safety in mind.
- **Agent Assignment**: `coder` (ML engineering expertise).
- **Files to Modify**:
  - `gnn_encoder.py`: Add a pooling layer (e.g., global_mean_pool) after the RGCN. Make the edge mapping thread-safe or predefined.
  - `anomaly_detector.py`: Ensure `train()` instantiates a *new* SVM and swaps it safely to avoid blocking `predict()`.
- **Validation Criteria**: `python main.py` should successfully train the model without crashing and return anomaly scores.
- **Dependencies**: 
  - `blocked_by`: [1]
  - `blocks`: [3a, 3b]

### Phase 3a: AI Forensic Reasoning
- **Objective**: Refactor `llm_investigator.py` to support dual Ollama/Gemini execution based on env variables, enforce strict JSON output with a 3x retry mechanism, and use a strict DFIR prompt.
- **Agent Assignment**: `coder` (AI engineering and retry logic).
- **Files to Modify**:
  - `llm_investigator.py`: Add regex fallback parsing. Implement the switch between `ollama` and `google-generativeai`.
- **Validation Criteria**: Execute a mock script directly invoking `LLMInvestigator` with dummy graph data to verify JSON extraction.
- **Dependencies**: 
  - `blocked_by`: [2]
  - `blocks`: [4]

### Phase 3b: CTI Integration
- **Objective**: Refactor `cti_integration.py` to use environment variables (`OPENCTI_URL`, `OPENCTI_TOKEN`) and translate the exact JSON schema from Phase 3a into `pycti` Incident and Observable objects.
- **Agent Assignment**: `security_engineer` (Domain knowledge for CTI and STIX mapping).
- **Files to Modify**:
  - `cti_integration.py`: Map LLM JSON (TTPs, IOCs) to OpenCTI.
  - `docker-compose.yml`: Ensure OpenCTI is removed if it's there, keeping only OpenSearch and Ollama.
- **Validation Criteria**: Inspect the code to ensure `pycti` calls are wrapped in `try/except` blocks and environment variables are used.
- **Dependencies**: 
  - `blocked_by`: [2]
  - `blocks`: [4]

### Phase 4: Async Orchestration
- **Objective**: Refactor `main.py` into a multithreaded orchestrator. Thread A trains the baseline every X minutes; Thread B hunts every Y minutes.
- **Agent Assignment**: `coder` (Concurrency and orchestration).
- **Files to Modify**:
  - `main.py`: Implement `threading.Thread` for training and hunting loops. Implement safe state sharing of the SVM model.
- **Validation Criteria**: `python main.py` should print logs showing training and hunting threads running concurrently without locking each other.
- **Dependencies**: 
  - `blocked_by`: [3a, 3b]
  - `blocks`: [5]

### Phase 5: Code Review & Quality Gate
- **Objective**: Perform a final pass to ensure PEP-8 compliance, comprehensive docstrings, and robust error handling across all modules.
- **Agent Assignment**: `code_reviewer`
- **Files to Modify**: None (Code reviewer provides feedback or minor fix directives).
- **Validation Criteria**: No major/critical findings in review report.
- **Dependencies**: 
  - `blocked_by`: [4]
  - `blocks`: []

## 5. File Inventory
| File | Phase | Purpose | Action |
|------|-------|---------|--------|
| `graph_builder.py` | 1 | OpenSearch to Subgraphs | Modify |
| `gnn_encoder.py` | 2 | Subgraph Pooling | Modify |
| `anomaly_detector.py` | 2 | SVM Thread-Safety | Modify |
| `llm_investigator.py` | 3a | Dual LLM & JSON Retry | Modify |
| `cti_integration.py` | 3b | OpenCTI External Mapping | Modify |
| `docker-compose.yml` | 3b | Clean infrastructure | Modify |
| `main.py` | 4 | Multithreading Loop | Modify |

## 6. Risk Classification
- **Phase 1**: MEDIUM (Log parsing fragility with multiple formats).
- **Phase 2**: HIGH (PyTorch Geometric pooling and thread-safe mappings).
- **Phase 3a**: HIGH (LLM Hallucination and JSON parsing).
- **Phase 3b**: LOW (Standard API integration).
- **Phase 4**: HIGH (Thread safety with Scikit-learn and NetworkX).
- **Phase 5**: LOW (Quality checks).

## 7. Execution Profile
- Total phases: 5 (plus one sub-phase)
- Parallelizable phases: 2 (in 1 batch: [3a, 3b])
- Sequential-only phases: 4 (1, 2, 4, 5)
- Estimated parallel wall time: ~10 minutes
- Estimated sequential wall time: ~15 minutes

Note: Native parallel execution currently runs agents in autonomous mode. All tool calls are auto-approved without user confirmation.