---
title: SentinelHunter Resilience Design
date: 2026-03-31
status: approved
design_depth: Standard
task_complexity: complex
---

# SentinelHunter Resilience Design

## 1. Problem Statement
The SentinelHunter Active Learning Threat Hunting Pipeline is experiencing a critical failure where the `HUNT-DEEP` thread silently stalls during the forensic investigation phase. While the Anomaly Detection ensemble successfully flags threats (e.g., LockBit mock data) and correctly initiates a 24-hour context fetch, the pipeline never completes the forensic report generation or persists the incident to the `sentinel-incidents` index in OpenSearch. This "black hole" behavior bypasses existing timeouts and top-level exception handlers, rendering the dashboard's Incident Feed permanently empty. 

The core of the problem stems from unconstrained resource exhaustion across multiple integration points. First, the `GraphBuilder`'s recursive ancestry fetch suffers from a "query of death" when it encounters generic, high-volume process names (like `explorer.exe`), creating unbounded `match_phrase` queries that stall the OpenSearch client. Second, the `opensearch-py` client is not configured with connection pool limits (`maxsize`) or strict request timeouts, allowing the thread to hang indefinitely on stalled sockets. Third, the `CTIIntegration` attempts to resolve every discovered observable against OpenCTI without filtering for actionable indicators (e.g., the Pyramid of Pain), leading to unnecessary network latency. Finally, the main `hunting_loop` lacks granular `try/except` handling around the deep-dive block, failing to log or recover from these deep integrations when they do timeout or crash. Resolving this requires a holistic resilience upgrade across the orchestration, graph building, and CTI enrichment layers to guarantee that investigations execute swiftly (under 45 seconds) and gracefully degrade if a specific dependency fails.

## 2. Requirements

### Functional Requirements
- The SentinelHunter pipeline MUST successfully process flagged anomalies through the `HUNT-DEEP` phase and generate a JSON forensic report using the Gemini LLM.
- The pipeline MUST persist the completed forensic report to the `sentinel-incidents` OpenSearch index.
- The `GraphBuilder` MUST filter generic and high-frequency process names (e.g., `explorer.exe`, `svchost.exe`) from the `images_to_search` list during recursive ancestry queries to prevent runaway OpenSearch searches.
- The `CTIIntegration` MUST restrict OpenCTI lookups exclusively to high-value indicators defined in the Pyramid of Pain (e.g., IP addresses, domains, hashes, URLs) and ignore low-fidelity observables.
- The main orchestration loop MUST wrap the entire deep-dive execution (from graph building to ingestion) in a granular exception handler that logs failures and continues to the next prioritized anomaly without crashing the thread.

### Non-Functional Requirements
- The end-to-end investigation for a single unique threat MUST complete in under 45 seconds.
- The system MUST gracefully degrade during network partitions, skipping stalled anomalies rather than blocking the real-time detection cycles.

### Constraints
- The `GraphBuilder` instance is shared between the `TRAIN` and `HUNT` threads in `main.py`, requiring thread-safe connection pooling to avoid deadlocks.
- The Python `opensearch-py` library handles the primary database connection and must be explicitly configured with `maxsize` and `request_timeout` parameters rather than relying on default HTTP configurations.
- The `CTIIntegration` has a strict 10-second global timeout for the intel enrichment phase.

## 3. Approach

### Selected Approach: The Resilient Pipeline
The chosen architecture focuses on addressing the root causes of the silent hangs by optimizing the `GraphBuilder`, configuring the OpenSearch connection pool, and tightening the `CTIIntegration` filters. We will instantiate a robust `OpenSearch` client with a `maxsize=25` connection pool, `request_timeout=30`, and a hard limit on retries. In the `fetch_logs_with_ancestry` method, we will implement a "query of death" filter to skip searching for known, high-frequency legitimate processes (e.g., `explorer.exe`, `svchost.exe`). In `cti_integration.py`, the `lookup_observable` function will be restricted to querying only high-value indicators mapped to the Pyramid of Pain (IPs, URLs, Hashes, Domains), preventing network stalls on generic process names. Finally, the main `hunting_loop` will encapsulate the `HUNT-DEEP` execution block within a granular `try/except` clause that explicitly catches `TimeoutError` and `ConnectionError` exceptions. 

*Rationale: Configuring the OpenSearch client explicitly with connection pool limits prevents thread starvation, while the query filters stop the pipeline from entering unbounded searches across millions of generic logs.*

### Alternatives Considered
**In-Memory Reconstruction**: Instead of recursive queries, fetch a massive timeline block and reconstruct the graph entirely in Python memory. *Rejected: This introduces significant RAM overhead and scales poorly on noisy hosts.*
**The Timeout Enforcer**: Wrap the entire `HUNT-DEEP` block in a strict 45-second Python thread timeout (`concurrent.futures.TimeoutError`). *Rejected: While ensuring the loop never stalls, it acts as a band-aid that wastes CPU/DB resources on queries that are destined to fail, rather than fixing the underlying query performance.*

### Decision Matrix
| Criterion | Weight | Approach A (Resilient) | Approach B (In-Memory) | Approach C (Enforcer) |
|-----------|--------|------------------------|------------------------|-----------------------|
| Fixes Root Cause | 40% | 5 | 2 | 1 |
| Performance | 30% | 4 | 3 | 2 |
| Complexity | 30% | 3 | 2 | 4 |
| **Weighted Total** | | **4.1** | **2.3** | **2.2** |

## 4. Architecture

The resilient SentinelHunter architecture modifies the data flow and integration points across three primary modules to guarantee deterministic execution times during the `HUNT-DEEP` forensic investigation.

### Key Components and Interfaces

**1. `main.py` (The Orchestrator)**
- Instantiates a single `GraphBuilder` with a robust `OpenSearch` client configuration (`maxsize=25`, `timeout=30`, `max_retries=3`). 
- The `hunting_loop` prioritizes the top unique anomalies and encapsulates the deep-dive sequence (ancestry fetch, CTI lookup, LLM investigation, ingestion) within a focused `try...except Exception` block.
- Any `TimeoutError` or connection failure during this block is logged as an error, and the thread gracefully skips the compromised anomaly and proceeds to the next item, ensuring the `HUNT` cycle never hangs.

**2. `graph_builder.py` (The Provenance Engine)**
- The `fetch_logs_with_ancestry` method implements a "query of death" blocklist. Before appending a generic process name (e.g., `explorer.exe`, `svchost.exe`, `services.exe`) to the `images_to_search` set, it checks against this static list. If matched, the generic image is ignored, preventing OpenSearch from executing massive `match_phrase` lookups across millions of unrelated logs.
- The client queries are restricted by the 30-second `request_timeout` configured in `main.py`.

**3. `cti_integration.py` (The Intelligence Layer)**
- The `lookup_observable` method implements a structural filter based on the Pyramid of Pain. When parsing the graph observables for enrichment, it only executes `OpenCTI` queries for high-value indicators (`type` in `["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Url", "File"]` representing hashes). Low-fidelity or generic process names are skipped, drastically reducing external network calls and latency during the strict 10-second global intel phase.

### Data Flow Diagram (HUNT-DEEP)
1. `main.py` detects anomaly -> Extracts Top 5 unique IDs.
2. `main.py` -> calls `GraphBuilder.fetch_logs_with_ancestry(a_id)`.
3. `GraphBuilder` recursively queries OpenSearch (skipping `explorer.exe` & `svchost.exe`).
4. `GraphBuilder` returns the connected provenance graph.
5. `main.py` -> calls `CTIIntegration.lookup_observable()` (only for IPs, Domains, Hashes).
6. `main.py` injects CTI hints and calls `LLMInvestigator.investigate()`.
7. `main.py` -> calls `ReportingEngine.ingest_incident()` with the LLM JSON.
8. If any step exceeds its configured timeout, `main.py` logs the error and moves to the next `a_id`.

## 5. Agent Team

The implementation of the Resilient Pipeline will be executed by the following Maestro subagents:

- **`architect`**: Validates the end-to-end integration flow and connection pooling strategy in `main.py` and `graph_builder.py`.
- **`coder`**: Implements the granular `try/except` exception handling and retry logic in `main.py`. Refactors the `GraphBuilder` initialization to include `request_timeout=30`, `maxsize=25`, and `max_retries=3`. Injects the static "query of death" blocklist (e.g., `explorer.exe`, `svchost.exe`) into `fetch_logs_with_ancestry` within `graph_builder.py`. Updates `cti_integration.py` to filter `lookup_observable` requests strictly by Pyramid of Pain indicator types.
- **`code_reviewer`**: Conducts a final static analysis pass to verify that no new deadlocks or unhandled exceptions are introduced in the multi-threaded orchestration loop.

## 6. Risk Assessment

The implementation of the Resilient Pipeline introduces several manageable risks that must be carefully monitored during rollout:

**1. Incomplete Provenance Graphs (Low Risk):**
By intentionally filtering high-frequency, generic processes (e.g., `explorer.exe`, `svchost.exe`, `services.exe`) from the `images_to_search` list in the recursive ancestry query, we risk truncating the absolute root of an execution chain. However, because these LOLBins (Living-Off-The-Land Binaries) are ubiquitous, their omission from the recursive look-back is a necessary trade-off to prevent the "query of death" that currently hangs the entire OpenSearch client. The immediate parent-child relationships surrounding the anomaly (e.g., `certutil.exe`) will still be successfully reconstructed.

**2. Thread Starvation during Timeout (Medium Risk):**
Even with a connection pool of `maxsize=25` and a strict `request_timeout=30`, a severe network partition could still cause the `HUNT-DEEP` thread to hang for up to 30 seconds per query attempt. If multiple retries stack up, the thread may pause its anomaly detection loop for several minutes. The mitigation strategy is the newly implemented granular `try/except` block, which will forcefully abort the stalled investigation and log the timeout, allowing the orchestration to recover and process the next prioritized alert in the queue.

**3. Missed CTI Intel on Low-Fidelity Observables (Low Risk):**
Restricting `CTIIntegration.lookup_observable` to only high-value indicators (IPs, Domains, URLs, Hashes) based on the Pyramid of Pain ensures the strict 10-second global timeout is rarely breached. However, this means that highly contextual, low-fidelity strings (like generic file paths or command-line arguments) will no longer be queried against OpenCTI. This is acceptable, as OpenCTI is optimized for structured STIX2 indicators rather than unstructured generic text.

## 7. Success Criteria

The implementation of the Resilient Pipeline will be deemed a success when the SentinelHunter orchestrator meets the following conditions:

**1. The "Black Hole" Hang is Eliminated:**
The `HUNT-DEEP` thread successfully processes a 19-anomaly LockBit mock sequence without silently stalling. All high-confidence incidents (e.g., `OUTLOOK` -> `WINWORD` -> `certutil`) generate a JSON forensic report using the Gemini LLM.

**2. Successful OpenSearch Ingestion:**
The `sentinel-incidents` index reliably increments with completed LLM reports. The `ReportingEngine` confirms successful ingestion and logs the corresponding incident IDs without encountering a `TimeoutError` or silent failure.

**3. Granular Error Handling and Recovery:**
If the OpenSearch connection pool hangs, or if OpenCTI hits its 10-second timeout, the orchestration loop gracefully catches the `Exception`, logs the failure, and instantly resumes monitoring the next unique anomaly. The main process does not crash or require a restart.

**4. Accelerated Graph Reconstruction:**
The recursive `fetch_logs_with_ancestry` executes efficiently (under 45 seconds per unique threat) by skipping "queries of death" on generic, high-volume process names (e.g., `explorer.exe`, `svchost.exe`).
