---
title: SentinelHunter Resilience Implementation Plan
date: 2026-03-31
status: draft
task_complexity: complex
---

# SentinelHunter Resilience Implementation Plan

## 1. Plan Overview
This plan implements the "Resilient Pipeline" design for the SentinelHunter orchestrator to eliminate the silent hangs during the `HUNT-DEEP` forensic investigation phase. The execution is broken down into 4 implementation phases and 1 quality review phase, addressing connection pooling, CTI filtering, query optimization, and exception handling.

**Estimated Effort:** ~5 phases, 2 agents (`coder`, `code_reviewer`).

## 2. Execution Strategy

| Phase | Objective | Agent | Parallel | Blocked By | Cost Est. |
|-------|-----------|-------|----------|------------|-----------|
| 1 | OpenSearch Client Configuration | `coder` | false | [] | $0.05 |
| 2 | CTI Intelligence Filtering | `coder` | true | [1] | $0.03 |
| 3 | Recursive Ancestry Query Optimization | `coder` | true | [1] | $0.04 |
| 4 | Granular Exception Handling | `coder` | false | [2, 3] | $0.04 |
| 5 | Code Review & Final Validation | `code_reviewer` | false | [4] | $0.02 |

## 3. Phase Details

### Phase 1: OpenSearch Client Configuration
- **Objective:** Configure the `opensearch-py` client in `main.py` with strict connection pool limits and request timeouts.
- **Agent:** `coder`
- **Files to Modify:**
  - `main.py`: Update the `GraphBuilder` and `ReportingEngine` instantiation (or the inner client initialization if done inside the classes, though `GraphBuilder` is initialized in `main.py`) to pass `maxsize=25`, `timeout=30`, and `max_retries=3`. Note: Since `GraphBuilder` encapsulates the `OpenSearch` client, we will need to update its `__init__` in `graph_builder.py` to accept these `**kwargs` and pass them to `OpenSearch(...)`, and then update `main.py` to provide them.
- **Validation:** Run `python main.py` and ensure the orchestrator starts without connection errors.

### Phase 2: CTI Intelligence Filtering
- **Objective:** Restrict `lookup_observable` to Pyramid of Pain indicators to prevent CTI deadlocks.
- **Agent:** `coder`
- **Files to Modify:**
  - `cti_integration.py`: Update `lookup_observable` to only execute queries if the observable matches an IP, Domain, URL, or Hash format (e.g., skip `explorer.exe`).
- **Validation:** Inject a test attack and verify that generic strings are skipped in the CTI lookup logs.

### Phase 3: Recursive Ancestry Query Optimization
- **Objective:** Implement a "query of death" blocklist in the ancestry fetcher.
- **Agent:** `coder`
- **Files to Modify:**
  - `graph_builder.py`: Update `fetch_logs_with_ancestry` to ignore generic process names (e.g., `explorer.exe`, `svchost.exe`, `services.exe`) when populating `images_to_search`.
- **Validation:** Ensure the `HUNT-DEEP` phase does not generate massive `match_phrase` queries for `explorer.exe`.

### Phase 4: Granular Exception Handling
- **Objective:** Wrap the deep-dive sequence in `main.py` with a specific `try/except` block to catch timeouts and continue.
- **Agent:** `coder`
- **Files to Modify:**
  - `main.py`: Inside `hunting_loop`, wrap the prioritized anomaly processing loop (ancestry fetch, CTI lookup, LLM investigation, ingestion) in a `try...except (TimeoutError, ConnectionError, Exception)` block. Log the error and `continue`.
- **Validation:** Manually throw a `TimeoutError` in `cti_integration.py` and ensure the HUNT loop logs it and proceeds to the next anomaly without crashing.

### Phase 5: Code Review & Final Validation
- **Objective:** Verify no new deadlocks or unhandled exceptions are introduced.
- **Agent:** `code_reviewer`
- **Files to Review:** `main.py`, `graph_builder.py`, `cti_integration.py`
- **Validation:** Run the complete test suite and the `generate_attacks.py` script to confirm end-to-end resilience.

## 4. File Inventory
| File | Action | Phase | Description |
|------|--------|-------|-------------|
| `main.py` | Modify | 1, 4 | Orchestration loop, client kwargs, exception handling |
| `graph_builder.py` | Modify | 1, 3 | OpenSearch kwargs, ancestry query blocklist |
| `cti_integration.py` | Modify | 2 | Pyramid of Pain indicator filtering |

## 5. Execution Profile
- Total phases: 5
- Parallelizable phases: 2 (Phases 2 & 3 in 1 batch)
- Sequential-only phases: 3
- Estimated parallel wall time: ~3 mins
- Estimated sequential wall time: ~5 mins
