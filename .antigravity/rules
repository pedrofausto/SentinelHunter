jCodemunch-MCP is available. Use it instead of native file tools for all code exploration.

Start any session: resolve_repo → (if missing) index_folder → suggest_queries

Finding code:
  symbol by name       → search_symbols (kind=, language=, file_pattern= to narrow)
  string/comment/TODO  → search_text (is_regex=true for patterns, context_lines for context)
  database columns     → search_columns

Reading code:
  before opening a file → get_file_outline first
  one or more symbols   → get_symbol_source (symbol_id for one, symbol_ids[] for batch)
  symbol + imports      → get_context_bundle
  line range only       → get_file_content (last resort)

Repo structure:
  overview  → get_repo_outline
  files     → get_file_tree

Relationships & impact:
  what imports a file             → find_importers
  where is a name used            → find_references
  is this identifier used         → check_references
  file dependency graph           → get_dependency_graph
  what breaks if I change X       → get_blast_radius (include_depth_scores=true for layered risk)
  what symbols changed in git     → get_changed_symbols
  find unreachable/dead code      → find_dead_code
  most important symbols          → get_symbol_importance
  class hierarchy                 → get_class_hierarchy
  callers/callees of a symbol     → get_call_hierarchy
  high-risk symbols               → get_hotspots (complexity × churn)
  circular dependencies           → get_dependency_cycles
  symbols by decorator            → search_symbols(decorator="route") or get_blast_radius(decorator_filter="...")

Session awareness:
  starting a new task             → plan_turn (confidence + recommended symbols)
  what have I already read        → get_session_context
  after editing a file            → register_edit (invalidates caches)

Retrieval with token budget:
  best-fit context for a task     → get_ranked_context (query + token_budget)
  bounded symbol bundle           → get_context_bundle (token_budget= to cap size)

After editing a file: index_file { "path": "/abs/path" } to keep the index fresh.