---
status: approved
created_at: 2026-04-02
task_complexity: medium
---

# Implementation Plan: SentinelHunter Threat Pipeline

## 1. Plan Overview
- **Total Phases**: 5
- **Agents Involved**: `coder`, `data_engineer`, `tester`
- **Estimated Effort**: Medium

| Phase | Agent | Model | Est. Input | Est. Output | Est. Cost |
|-------|-------|-------|-----------|------------|----------|
| 1 | `coder` | Pro | 1500 | 400 | $0.03 |
| 2 | `data_engineer` | Pro | 1000 | 400 | $0.03 |
| 3 | `coder` | Pro | 2500 | 600 | $0.05 |
| 4 | `coder` | Pro | 1000 | 400 | $0.03 |
| 5 | `tester` | Pro | 2000 | 600 | $0.04 |
| **Total** | | | **8000** | **2400** | **$0.18** |

## 2. Dependency Graph

```text
Layer 1: Phase 1 (Ingestion Layer)
         |
Layer 2: Phase 2 (Graph Builder & Ancestry)
         |
Layer 3: Phase 3 (Detection & LLM Orchestration)
         |
Layer 4: Phase 4 (Dashboard UI)
         |
Layer 5: Phase 5 (Quality & Integration Testing)
```

*Note: Due to the sequential nature of a data pipeline, parallelization is limited. All phases are sequential.*

## 3. Phase Details

### Phase 1: Hybrid Adapter Ingestion Layer
- **Objective**: Implement the Hybrid Adapter for polling OpenSearch with connection pooling (`maxsize=25`) and prepare interfaces for future Kafka streaming.
- **Agent**: `coder`
- **Files to Modify**: `main.py`
- **Implementation Details**: Set up the OpenSearch client with robust connection pooling. Create an abstract `LogConsumer` interface and a concrete `OpenSearchPollingConsumer` class.
- **Validation Criteria**: Run the ingestion script against a local OpenSearch instance or mock to verify connection pool behavior.
- **Dependencies**: None.

### Phase 2: Graph Reconstruction & Ancestry Stitching
- **Objective**: Enhance the Graph Builder to gracefully handle disconnected nodes by querying OpenSearch for missing parent/child links.
- **Agent**: `data_engineer`
- **Files to Modify**: `graph_builder.py`
- **Implementation Details**: Add an ancestry-stitching fallback method. When a log entry's parent is missing in the current batch, query the ingestion layer by `session_id` and `parent_process_id` to fetch the missing context before completing the NetworkX graph.
- **Validation Criteria**: Unit tests verifying that out-of-order logs are correctly assembled into a single connected directed graph.
- **Dependencies**: `blocked_by`: [1]

### Phase 3: Triple Ensemble Detection & LLM Orchestration
- **Objective**: Wire the pipeline: GNN embeddings -> Triple Ensemble -> Gemini LLM. Implement Majority Voting and Periodic Batch Training.
- **Agent**: `coder`
- **Files to Modify**: `main.py`, `anomaly_detector.py`, `llm_investigator.py`
- **Implementation Details**: In `anomaly_detector.py`, configure OC-SVM, Isolation Forest, and COPOD. Implement a 2/3 majority vote logic to flag the top 1% of anomalies. In `main.py`, orchestrate the flow and establish a periodic batch training loop to update GNN weights against a 24h baseline. Forward flagged graphs to `llm_investigator.py`.
- **Validation Criteria**: Run `python main.py --dry-run` to ensure embeddings flow through the ensemble and trigger the LLM mock.
- **Dependencies**: `blocked_by`: [2]

### Phase 4: Dashboard UI & "Wipe State" Mechanism
- **Objective**: Implement the interactive Streamlit dashboard with Cytoscape.js for graph visualization and add the checkpoint reset functionality.
- **Agent**: `coder`
- **Files to Modify**: `dashboard.py`
- **Implementation Details**: Build the Streamlit app. Integrate `st-cytoscape` or similar for NetworkX rendering. Add a "Wipe State" button that clears the current ingestion checkpoint, allowing manual re-hunting of backdated data.
- **Validation Criteria**: Run `streamlit run dashboard.py` and verify UI elements and state reset logic.
- **Dependencies**: `blocked_by`: [3]

### Phase 5: Quality & Integration Testing
- **Objective**: Validate the entire pipeline end-to-end.
- **Agent**: `tester`
- **Files to Create**: `tests/test_advanced_capabilities.py` (Update or recreate)
- **Implementation Details**: Write integration tests that simulate cold-start, process a batch of mock out-of-order logs, verify ancestry stitching, check ensemble majority voting, and confirm LLM report generation.
- **Validation Criteria**: `pytest tests/test_advanced_capabilities.py` passes successfully.
- **Dependencies**: `blocked_by`: [4]

## 4. Execution Profile
- Total phases: 5
- Parallelizable phases: 0 (in 0 batches)
- Sequential-only phases: 5
- Estimated sequential wall time: ~15 minutes

*Note: Native parallel execution currently runs agents in autonomous mode. All tool calls are auto-approved without user confirmation.*