import logging
import re
import networkx as nx
from typing import List, Dict, Any, Optional
from opensearchpy import OpenSearch
from datetime import datetime, timedelta, timezone
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)

class GraphBuilder:
    """
    Module responsible for ingesting logs from OpenSearch and converting them
    into Directed Provenance Graphs (subgraphs) using NetworkX.
    """

    # Mapping to translate categorical data to numeric representations (consistent with encoder)
    node_type_mapping = {'process': 0, 'file': 1, 'ip': 2, 'unknown': 3}

    def __init__(self, host: str = None, port: int = None, index: str = "logs-*", maxsize: int = 25, timeout: int = 30, max_retries: int = 3, log_consumer: Optional[Any] = None):
        host = host or os.getenv('OPENSEARCH_HOST', 'localhost')
        port = port or int(os.getenv('OPENSEARCH_PORT', '9201'))
        self.host = host
        self.port = port
        self.index = index
        self.log_consumer = log_consumer
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            maxsize=maxsize,
            timeout=timeout,
            max_retries=max_retries
        )
        self.shadow_nodes = {} # Cache for nodes mentioned but not yet defined
        self.ancestry_seen_ids = set() # Global cache for the lifetime of this worker to prevent redundant deep ancestry searches
        from schema_mapper import SchemaMapper
        self.mapper = SchemaMapper()
        try:
            # Test connection
            if not self.client.ping():
                logger.warning("Could not connect to OpenSearch. Please ensure it is running.")
            else:
                logger.info(f"Successfully connected to OpenSearch at {host}:{port}")
        except Exception as e:
            logger.error(f"Error initializing OpenSearch client: {e}")

    def clear_caches(self):
        """Clears memory caches to prevent leaks over long-running loops."""
        self.shadow_nodes.clear()
        self.ancestry_seen_ids.clear()

    @staticmethod
    def _validate_filter_id(filter_id: str) -> str:
        """
        Validates filter_id against injection patterns before use in OpenSearch queries.
        Raises ValueError for inputs that could alter query structure.
        """
        if not isinstance(filter_id, str):
            raise ValueError("filter_id must be a string")
        if len(filter_id) > 256:
            raise ValueError("filter_id exceeds maximum allowed length of 256 characters")
        # Whitelist: allow alphanumeric, underscore, hyphen, colon, dot, @, and slash
        # These cover GUIDs, IP:port pairs, process names, and flow IDs.
        if not re.match(r'^[\w@./:\-]+$', filter_id):
            raise ValueError(f"filter_id contains disallowed characters: {filter_id!r}")
        return filter_id

    # @MX:ANCHOR: [AUTO] fetch_logs - called from fetch_logs_with_ancestry, build_graphs, and main hunt loop.
    # @MX:REASON: Central log retrieval method; query structure changes affect all graph-building paths.
    def fetch_logs(self, start_time: str, end_time: str, filter_id: str = None, exclude_ids: List[str] = None) -> List[Dict[str, Any]]:
        """
        Extracts raw logs from a specific time window.
        Optionally EXCLUDES known malicious IDs (for semi-supervised baseline).
        """
        # Memory Wall Guardrail: Prevent loading more than 48 hours for node-specific queries
        if filter_id:
            try:
                end_dt = date_parser.parse(end_time)
                start_dt = date_parser.parse(start_time)
                if (end_dt - start_dt).total_seconds() > 48 * 3600:
                    logger.warning(f"[Memory Wall] Reducing fetch_logs deep dive window from {(end_dt - start_dt).total_seconds()/3600:.1f}h to max 48h.")
                    start_dt = end_dt - timedelta(hours=48)
                    start_time = start_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            except Exception:
                pass

        must_clauses = [
            {
                "range": {
                    "@timestamp": {
                        "gt": start_time,
                        "lte": end_time
                    }
                }
            }
        ]

        mapper = self.mapper

        if filter_id:
            filter_id = self._validate_filter_id(filter_id)
            # Route all targeted forensic queries using the dynamic grouping fields
            # defined across all loaded vendor parsers.
            should_clauses = []
            for parser in mapper.parsers:
                for grp_field in parser.get("group_by", []):
                    should_clauses.append({"match_phrase": {grp_field: filter_id}})

            # Keep DB field fallbacks just in case older normalized logs exist
            should_clauses.extend([
                {"term": {"_id":             filter_id}},
                {"term": {"session_id":      filter_id}},
                {"term": {"process_tree_id": filter_id}},
                {"term": {"logon_id":        filter_id}}
            ])

            must_clauses.append({
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            })

        bool_query = {
            "must": must_clauses
        }
        
        if exclude_ids and len(exclude_ids) > 0:
            # Explicitly exclude the exact OpenSearch document IDs of confirmed threats
            bool_query["must_not"] = [{"terms": {"_id": exclude_ids}}]

        query = {
            "query": {
                "bool": bool_query
            },
            "size": 10000,
            "sort": [{"@timestamp": {"order": "asc"}}]
        }

        logs = []
        try:
            response = self.client.search(
                body=query,
                index=self.index
            )
            hits = response.get('hits', {}).get('hits', [])
            for hit in hits:
                src = hit['_source']
                src['_id'] = hit['_id']  # Inject OpenSearch unique document ID
                logs.append(src)
            logger.info(f"Fetched {len(logs)} logs from OpenSearch (Window: {start_time} to {end_time}, Filter: {filter_id}).")
        except Exception as e:
            logger.error(f"Error fetching logs from OpenSearch: {e}")

        return logs

    def fetch_logs_with_ancestry(self, start_time: str, end_time: str, filter_id: str = None, exclude_ids: List[str] = None) -> List[Dict[str, Any]]:
        """
        Fetches the initial logs for the given filter_id and then recursively queries
        for their parent processes to ensure a fully connected provenance graph.
        """
        # Memory Wall Guardrail: Force strictly bounded windows
        try:
            end_dt = date_parser.parse(end_time)
            start_dt = date_parser.parse(start_time)
            if (end_dt - start_dt).total_seconds() > 48 * 3600:
                logger.warning(f"[Memory Wall] Reducing fetch_logs_with_ancestry window from {(end_dt - start_dt).total_seconds()/3600:.1f}h to 48h.")
                start_dt = end_dt - timedelta(hours=48)
                start_time = start_dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        except Exception:
            pass

        initial_logs = self.fetch_logs(start_time, end_time, filter_id, exclude_ids)
        if not initial_logs:
            return []

        all_logs = {log.get('_id'): log for log in initial_logs if log.get('_id')}
        if not all_logs:
            all_logs = {str(i): log for i, log in enumerate(initial_logs)}

        mapper = self.mapper

        pids_to_search = set()   # numeric PIDs only — safe to query integer-mapped fields
        guids_to_search = set()  # GUIDs / entity_ids — string-only fields; must NOT hit numeric fields
        images_to_search = set()

        qod_blocklist = {'explorer.exe', 'svchost.exe', 'services.exe', 'csrss.exe', 'lsass.exe', 'wininit.exe', 'smss.exe'}

        for log in initial_logs:
            parsed = mapper.parse(log)
            if not parsed: continue
            for node in parsed.get("nodes", []):
                if node.get("type") == "process":
                    ppid = node.get("parent_pid")
                    pguid = node.get("parent_process_guid") or node.get("parent_entity_id")
                    pimage = node.get("parent_image") or node.get("parent_name")

                    if ppid and str(ppid).isdigit():
                        pids_to_search.add(str(ppid))
                    if pguid:
                        guids_to_search.add(str(pguid))
                    if pimage:
                        img_clean = str(pimage).split('\\')[-1].split('/')[-1]
                        if img_clean.lower() not in qod_blocklist:
                            images_to_search.add(img_clean)

        searched_pids = set()
        searched_guids = set()
        searched_images = set()
        max_depth = 5
        current_depth = 0

        while (pids_to_search or guids_to_search or images_to_search) and current_depth < max_depth:
            current_depth += 1
            next_pids = set()
            next_guids = set()
            next_images = set()
            should_clauses = []

            new_searches_this_round = 0

            for pid in pids_to_search:
                cache_key = f"pid_{pid}"
                if cache_key in self.ancestry_seen_ids: continue
                self.ancestry_seen_ids.add(cache_key)
                searched_pids.add(pid)
                new_searches_this_round += 1
                # Numeric-only fields — GUIDs are excluded to avoid 400 type errors
                should_clauses.extend([
                    {"match": {"ProcessId": pid}},
                    {"match": {"process.pid": pid}},
                    {"match": {"pid": pid}},
                    {"match": {"data.audit.pid": pid}},
                ])

            for guid in guids_to_search:
                cache_key = f"guid_{guid}"
                if cache_key in self.ancestry_seen_ids: continue
                self.ancestry_seen_ids.add(cache_key)
                searched_guids.add(guid)
                new_searches_this_round += 1
                # Keyword/string GUID fields only — numeric PID fields excluded
                should_clauses.extend([
                    {"term": {"ProcessGuid": guid}},
                    {"term": {"process.entity_id": guid}},
                    {"term": {"process.parent.entity_id": guid}},
                    {"term": {"data.win.eventdata.ProcessGuid": guid}},
                    {"term": {"data.win.eventdata.ParentProcessGuid": guid}},
                ])

            for img in images_to_search:
                cache_key = f"img_{img}"
                if cache_key in self.ancestry_seen_ids: continue
                self.ancestry_seen_ids.add(cache_key)
                searched_images.add(img)
                new_searches_this_round += 1
                should_clauses.extend([
                    {"match_phrase": {"Image": img}},
                    {"match_phrase": {"process.name": img}},
                    {"match_phrase": {"process.executable": img}},
                    {"match_phrase": {"ParentImage": img}},
                    {"match_phrase": {"process.parent.name": img}}
                ])
            
            if new_searches_this_round == 0 or not should_clauses:
                break
                
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gt": start_time,
                                        "lte": end_time
                                    }
                                }
                            },
                            {
                                "bool": {
                                    "should": should_clauses,
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                },
                "size": 500,
                "sort": [{"@timestamp": {"order": "asc"}}]
            }
            
            try:
                response = self.client.search(body=query, index=self.index)
                hits = response.get('hits', {}).get('hits', [])
                new_logs = []
                for hit in hits:
                    src = hit['_source']
                    src['_id'] = hit['_id']
                    if src['_id'] not in all_logs:
                        all_logs[src['_id']] = src
                        new_logs.append(src)
                
                # Check for parents of these new logs
                for log in new_logs:
                    parsed = mapper.parse(log)
                    if not parsed: continue
                    for node in parsed.get("nodes", []):
                        if node.get("type") == "process":
                            ppid = node.get("parent_pid")
                            pguid = node.get("parent_process_guid") or node.get("parent_entity_id")
                            pimage = node.get("parent_image") or node.get("parent_name")

                            if ppid and str(ppid).isdigit() and str(ppid) not in searched_pids:
                                next_pids.add(str(ppid))
                            if pguid and str(pguid) not in searched_guids:
                                next_guids.add(str(pguid))
                            if pimage:
                                img_clean = str(pimage).split('\\')[-1].split('/')[-1]
                                if img_clean not in searched_images and img_clean.lower() not in qod_blocklist:
                                    next_images.add(img_clean)

                # Only carry forward identifiers not yet searched this run
                pids_to_search = next_pids
                guids_to_search = next_guids
                images_to_search = next_images
            except Exception as e:
                logger.error(f"Error fetching ancestry logs: {e}")
                break

        logger.info(f"Recursive ancestry search completed at depth {current_depth}. Total logs: {len(all_logs)}")
        return list(all_logs.values())

    # ---------------------------------------------------------------------------
    # Query Helpers
    # ---------------------------------------------------------------------------

    def _parse_filter_id_to_query(self, filter_id: str) -> Optional[dict]:
        """
        Decodes a dynamically-generated group_val back into structured
        OpenSearch field queries, avoiding brittle query_string tokenization.

        Supported formats:
          Network : {src_ip}_{dst_ip}_{dst_port}_{proto}_{YYYY-MM-DDTHH:MM}
          Flow    : flow_{proto}_{rate}_{YYYY-MM-DDTHH:MM}
        """
        IP = r'(?:\d{1,3}\.){3}\d{1,3}'
        TS = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})'

        # Pattern 1 – network tuple
        m = re.match(
            rf'^({IP})_({IP})_(\d+)_([^_]+)_{TS}$',
            filter_id
        )
        if m:
            src_ip, dst_ip, dst_port, proto, ts_min = m.groups()
            dt = datetime.fromisoformat(ts_min)
            return {
                "bool": {
                    "must": [
                        {"term": {"src_ip":        src_ip}},
                        {"term": {"dst_ip":        dst_ip}},
                        {"term": {"dst_port":      int(dst_port)}},
                        {"range": {"@timestamp": {
                            "gte": dt.isoformat(),
                            "lt":  (dt + timedelta(minutes=1)).isoformat()
                        }}}
                    ]
                }
            }

        # Pattern 2 – flow profile
        m2 = re.match(rf'^flow_(.+?)_(.+?)_{TS}$', filter_id)
        if m2:
            proto, rate, ts_min = m2.groups()
            dt = datetime.fromisoformat(ts_min)
            return {
                "bool": {
                    "must": [
                        {"term": {"Protocol Type": proto}},
                        {"term": {"Rate":          rate}},
                        {"range": {"@timestamp": {
                            "gte": dt.isoformat(),
                            "lt":  (dt + timedelta(minutes=1)).isoformat()
                        }}}
                    ]
                }
            }

        return None  # Caller will fall back to exact-term DB field match

    # @MX:ANCHOR: [AUTO] _calculate_node_identity - called from _add_parsed_to_graph and _stitch_graph (3+ call sites).
    # @MX:REASON: Identity resolution algorithm determines node deduplication across all graph builders; changes break graph consistency.
    def _calculate_node_identity(self, node_data: Dict[str, Any], agent_id: str = "global", timestamp: str = "") -> str:
        """
        Resolves a universal identity for a node across different log schemas.
        GUID > (PID + Agent + Time) > ID.
        """
        n_type = node_data.get('type')
        n_id = node_data.get('id')
        
        if n_type == 'process':
            # Priority 1: Immutable GUID (Sysmon/SentinelECS)
            guid = node_data.get('guid') or node_data.get('process_guid') or node_data.get('entity_id')
            
            # Check if the 'id' field itself is a GUID (common in optimized parsers)
            if not guid and n_id and isinstance(n_id, str) and len(n_id) > 20 and '-' in n_id:
                guid = n_id
            
            # Level 2 (Composite): Temporal PID (PID + Agent + Approx Time)
            pid = node_data.get('pid') or n_id
            temporal_id = None
            if pid and str(pid).isdigit():
                time_window = ""
                if timestamp:
                    try:
                        dt = date_parser.parse(timestamp)
                        # 24h window suffix
                        time_window = "_" + dt.strftime("%Y%m%d")
                    except Exception:
                        pass
                temporal_id = f"proc_{agent_id}_{pid}{time_window}"
                
            # Priority 3: Fallback Name
            name = node_data.get('name') or node_data.get('image') or node_data.get('process.name')
            name_id = f"proc_name_{name}" if name else None

            # Resolution
            ident = None
            if guid:
                ident = f"proc_{guid}"
            elif temporal_id:
                # Check global cache if mapped previously
                ident = self.shadow_nodes.get(temporal_id, temporal_id)
            elif name_id:
                ident = name_id
            else:
                ident = f"{n_type}_{n_id}"
                
            # If we know the GUID now, update cache for the temporal ID
            if guid and temporal_id:
                self.shadow_nodes[temporal_id] = ident
                
            return ident
            
        return f"{n_type}_{n_id}"

    # @MX:ANCHOR: [AUTO] _add_parsed_to_graph - called from build_unified_graph, build_graphs, and recursive ancestry path (3+ call sites).
    # @MX:REASON: Central node/edge mutation method; all graph-building paths must produce identical node identities.
    def _add_parsed_to_graph(self, G: nx.DiGraph, parsed: Dict[str, Any]):
        """
        Universal node and edge addition with shadow-node merging.
        Uses Multi-Key Identity resolution.
        """
        agent_id = parsed.get("agent_id", "default_agent")
        timestamp = parsed.get("timestamp", "")
        
        # 1. UPSERT Nodes with Identity resolution
        identity_map = {} # Maps original ID in log to resolved graph identity
        for n_data in parsed.get("nodes", []):
            ident = self._calculate_node_identity(n_data, agent_id, timestamp)
            identity_map[n_data['id']] = ident

            # Handle Merge-on-Arrival if temporal shadow node existed but now we resolved an absolute GUID
            temporal_id = None
            if n_data.get('type') == 'process':
                pid = n_data.get('pid') or n_data.get('id')
                if pid and str(pid).isdigit():
                    time_window = ""
                    if timestamp:
                        try:
                            dt = date_parser.parse(timestamp)
                            time_window = "_" + dt.strftime("%Y%m%d")
                        except Exception: pass
                    temporal_id = f"proc_{agent_id}_{pid}{time_window}"
                    
            if temporal_id and temporal_id != ident and G.has_node(temporal_id):
                # MERGE temporal_id into ident
                if not G.has_node(ident):
                    G.add_node(ident, **G.nodes[temporal_id])
                else:
                    G.nodes[ident].update(G.nodes[temporal_id])
                
                # Rewire edges gracefully to the new absolute `ident`
                for src, dst, data in list(G.in_edges(temporal_id, data=True)):
                    G.add_edge(src, ident, **data)
                for src, dst, data in list(G.out_edges(temporal_id, data=True)):
                    G.add_edge(ident, dst, **data)
                
                G.remove_node(temporal_id)
                self.shadow_nodes[temporal_id] = ident
            
            if G.has_node(ident):
                G.nodes[ident].update(n_data)
                # Propagate event timestamp to node
                if timestamp:
                    G.nodes[ident]['timestamp'] = timestamp
                if G.nodes[ident].get('log_type') == 'shadow':
                    G.nodes[ident]['log_type'] = 'real'
            else:
                G.add_node(ident, **n_data, timestamp=timestamp, log_type='real')

        # 2. Add Edges and handle Shadow Parents
        for e_data in parsed.get("edges", []):
            src_orig = e_data.get('src')
            dst_orig = e_data.get('dst')
            
            src_ident = identity_map.get(src_orig)
            dst_ident = identity_map.get(dst_orig)

            # Look up or resolve identity actively for missing nodes in the graph
            if not src_ident:
                 src_ident = self._calculate_node_identity({'id': src_orig, 'type': 'process'}, agent_id, timestamp)
            if not dst_ident:
                 dst_ident = self._calculate_node_identity({'id': dst_orig, 'type': 'process'}, agent_id, timestamp)
            
            # Ensure both nodes exist (Handle Shadow Nodes)
            if not G.has_node(src_ident):
                G.add_node(src_ident, type='process', id=src_orig, timestamp=timestamp, log_type='shadow')
            if not G.has_node(dst_ident):
                G.add_node(dst_ident, type='process', id=dst_orig, timestamp=timestamp, log_type='shadow')
                
            edge_attrs = {k: v for k, v in e_data.items() if k not in ['src', 'dst', 'timestamp']}
            G.add_edge(
                src_ident, dst_ident,
                **edge_attrs,
                timestamp=timestamp,
                log_type='log'
            )

    def _stitch_graph(self, G: nx.DiGraph, graph_id: str = "unknown"):
        """
        Exhaustive Multi-Layer Stitching (Inferred Connections) to unify disconnected components.
        """
        added_edges = 0
        nodes = list(G.nodes(data=True))
        mapper = self.mapper
        
        # B1. GUID/PID Biological Stitching (Recursive)
        # Link children to parents based on parent_process_guid or parent_pid
        for n_id, d in nodes:
            if d.get('type') == 'process':
                p_guid = d.get('parent_process_guid') or d.get('parent_guid')
                ppid = d.get('parent_pid')
                agent = d.get('agent_id', 'default')
                log_ts = d.get('timestamp', '')
                
                # Consistency Fix: Use the same helper to resolve parent identity
                parent_ident = None
                if p_guid or ppid:
                     p_data = {'type': 'process', 'id': ppid, 'guid': p_guid, 'pid': ppid}
                     parent_ident = self._calculate_node_identity(p_data, agent, log_ts)
                
                if parent_ident:
                    if G.has_node(parent_ident):
                        if not G.has_edge(parent_ident, n_id):
                            G.add_edge(parent_ident, n_id, action='spawn (stitch)', log_type='bridge', timestamp=log_ts)
                            added_edges += 1
                    elif getattr(self, 'log_consumer', None) and graph_id != "unknown" and ppid:
                        # Disconnected node detected (parent missing). Fetch missing context.
                        # This forensic branch is usually only hit during deep-dives
                        try:
                            missing_logs = self.log_consumer.fetch_ancestry_by_session(graph_id, ppid)
                            if missing_logs:
                                for m_log in missing_logs:
                                    m_parsed = mapper.parse(m_log)
                                    if m_parsed:
                                        m_parsed['agent_id'] = m_log.get('agent', {}).get('id', 'default')
                                        self._add_parsed_to_graph(G, m_parsed)
                                # Try to link again
                                if G.has_node(parent_ident) and not G.has_edge(parent_ident, n_id):
                                    G.add_edge(parent_ident, n_id, action='spawn (stitch_fallback)', log_type='bridge', timestamp=log_ts)
                                    added_edges += 1
                        except Exception as e:
                            logger.error(f"Error fetching ancestry for session {graph_id}, ppid {ppid}: {e}")

        # B2. IP and Socket Unification
        ip_nodes = {n for n, d in G.nodes(data=True) if d.get('type') == 'ip'}
        for n_id in list(ip_nodes):
            bare_ip = str(n_id).split(':')[0]
            for other in list(ip_nodes):
                if other != n_id and str(other).startswith(bare_ip + ':'):
                    if not G.has_edge(n_id, other):
                        G.add_edge(n_id, other, action='socket_binding', log_type='bridge')
                        added_edges += 1
        return added_edges

    # @MX:ANCHOR: [AUTO] _merge_related_subgraphs - called from build_graphs to unify cross-incident fragments.
    # @MX:REASON: Uses Union-Find to merge subgraphs connected by parent-child GUID links; output size directly affects detection recall.
    def _merge_related_subgraphs(self, graphs: List[nx.DiGraph]) -> List[nx.DiGraph]:
        """
        Merges subgraphs that are connected by parent-child process relationships.
        Fixes incidents fragmented across multiple group_id buckets when a session-level
        ID is absent and grouping fell back to individual entity_id fields.

        Uses Union-Find (path compression) over graph indices.
        """
        if len(graphs) <= 1:
            return graphs

        # Build lookup: resolved node_id -> subgraph index
        node_to_sg: Dict[str, int] = {}
        for sg_idx, G in enumerate(graphs):
            for node_id in G.nodes():
                node_to_sg[node_id] = sg_idx

        # Union-Find with path compression
        uf_parent = list(range(len(graphs)))

        def find(x: int) -> int:
            while uf_parent[x] != x:
                uf_parent[x] = uf_parent[uf_parent[x]]  # path halving
                x = uf_parent[x]
            return x

        def union(x: int, y: int):
            rx, ry = find(x), find(y)
            if rx != ry:
                uf_parent[rx] = ry

        # Detect cross-subgraph parent-child edges via node attributes set by parsers
        for sg_idx, G in enumerate(graphs):
            for n_id, d in G.nodes(data=True):
                if d.get('type') != 'process':
                    continue
                p_guid = (
                    d.get('parent_process_guid') or
                    d.get('parent_guid') or
                    d.get('parent_entity_id')
                )
                if p_guid:
                    parent_node_id = f'proc_{p_guid}'
                    parent_sg_idx = node_to_sg.get(parent_node_id)
                    if parent_sg_idx is not None and parent_sg_idx != sg_idx:
                        union(sg_idx, parent_sg_idx)

        # Group subgraph indices by Union-Find root
        groups: Dict[int, List[int]] = {}
        for i in range(len(graphs)):
            root = find(i)
            groups.setdefault(root, []).append(i)

        merged: List[nx.DiGraph] = []
        for sg_indices in groups.values():
            if len(sg_indices) == 1:
                merged.append(graphs[sg_indices[0]])
            else:
                merged_id = "+".join(
                    graphs[i].graph.get('graph_id', str(i)) for i in sorted(sg_indices)
                )
                all_doc_ids: List[str] = []
                for i in sg_indices:
                    all_doc_ids.extend(graphs[i].graph.get('doc_ids', []))
                G_merged = nx.DiGraph(graph_id=merged_id, doc_ids=all_doc_ids)
                for i in sg_indices:
                    # update() upserts nodes (merging attrs) and copies edges
                    G_merged.update(graphs[i])
                merged.append(G_merged)
                logger.info(
                    f"[MERGE] Unified {len(sg_indices)} incident fragments -> '{merged_id}' "
                    f"({G_merged.number_of_nodes()} nodes, {G_merged.number_of_edges()} edges)"
                )

        return merged

    def build_unified_graph(self, logs: List[Dict[str, Any]], graph_id: str) -> Optional[nx.DiGraph]:
        """
        Builds a SINGLE unified provenance graph with exhaustive cross-node stitching.
        """
        if not logs: return None

        mapper = self.mapper
        G = nx.DiGraph(graph_id=graph_id)
        
        # Part A: Log-based construction
        for log in logs:
            parsed = mapper.parse(log)
            if parsed:
                parsed['agent_id'] = log.get('agent', {}).get('id', 'default')
                self._add_parsed_to_graph(G, parsed)

        # Part B: Exhaustive Multi-Layer Stitching
        added_edges = self._stitch_graph(G, graph_id)

        # ── Topological enrichment ───────────────────────────────────────────
        try:
            centrality = nx.degree_centrality(G)
        except Exception:
            centrality = {n: 0.0 for n in G.nodes()}

        for node in G.nodes():
            n_type_str = G.nodes[node].get('type', 'unknown').lower()
            n_type_idx = float(self.node_type_mapping.get(n_type_str, self.node_type_mapping['unknown']))
            in_deg   = float(G.in_degree(node))
            out_deg  = float(G.out_degree(node))
            cent_val = float(centrality.get(node, 0.0))
            is_root  = 1.0 if in_deg == 0 else 0.0
            G.nodes[node]['centrality'] = cent_val
            G.nodes[node]['is_root']    = bool(is_root)
            G.nodes[node]['features']   = [n_type_idx, in_deg, out_deg, cent_val, is_root]

        # ── Log component info ───────────────────────────────────────────────
        n_components = nx.number_weakly_connected_components(G)
        logger.info(
            f"Unified graph '{graph_id}': {G.number_of_nodes()} nodes, "
            f"{G.number_of_edges()} edges, {n_components} component(s), "
            f"{added_edges} bridge edge(s) added."
        )
        G.graph['n_components'] = n_components

        return G

    # ---------------------------------------------------------------------------
    # Graph Construction
    # ---------------------------------------------------------------------------

    def build_graphs(self, logs: List[Dict[str, Any]], group_by: str = 'auto') -> List[nx.DiGraph]:
        """
        Groups raw logs into distinct subgraphs using the SchemaMapper abstraction.
        Relies on the JSON configurations in `parsers/` to determine the grouping ID natively.

        Pipeline:
          1. Group and parse logs into raw per-group subgraphs.
          2. Merge subgraphs connected by parent-child GUID links across group boundaries.
          3. Stitch inferred edges and compute topological features.
        """
        self.clear_caches()
        mapper = self.mapper

        MAX_LOGS_PER_GROUP = 500
        grouped_logs: Dict[str, List[Dict]] = {}
        doc_ids_by_group: Dict[str, List[str]] = {}

        for log in logs:
            parsed = mapper.parse(log)
            if not parsed:
                continue

            base_id = parsed.get("group_id", "default_group")
            group_val = base_id

            bucket = grouped_logs.setdefault(group_val, [])
            if len(bucket) >= MAX_LOGS_PER_GROUP:
                chunk_idx = len(bucket) // MAX_LOGS_PER_GROUP
                group_val = f"{group_val}_chunk{chunk_idx}"
                grouped_logs.setdefault(group_val, []).append(parsed)
            else:
                bucket.append(parsed)

            doc_id = log.get('_id')
            if doc_id:
                doc_ids_by_group.setdefault(group_val, []).append(doc_id)

        # Phase 1: Build raw subgraphs (no stitching yet — preserve parent-child attrs for merge)
        raw_graphs: List[nx.DiGraph] = []
        for group_val, group_parsed_list in grouped_logs.items():
            G = nx.DiGraph(graph_id=group_val)
            G.graph['doc_ids'] = doc_ids_by_group.get(group_val, [])
            for parsed in group_parsed_list:
                self._add_parsed_to_graph(G, parsed)
            if G.number_of_nodes() > 0:
                raw_graphs.append(G)

        # Phase 2: Merge fragments that belong to the same incident
        # (parent process events and child process events often land in different buckets
        #  when a session-level ID is absent and grouping fell back to entity_id)
        merged_graphs = self._merge_related_subgraphs(raw_graphs)

        # Phase 3: Inferred stitching + topological enrichment per merged subgraph
        # We pass graph_id="unknown" to prevent triggering the remote log_consumer
        # fetch during the main hunt loop (too slow / potentially recursive).
        graphs: List[nx.DiGraph] = []
        for G in merged_graphs:
            self._stitch_graph(G, graph_id="unknown")

            try:
                centrality = nx.degree_centrality(G)
            except Exception:
                centrality = {n: 0.0 for n in G.nodes()}

            for node in G.nodes():
                n_type_str = G.nodes[node].get('type', 'unknown').lower()
                n_type_idx = float(self.node_type_mapping.get(n_type_str, self.node_type_mapping['unknown']))
                in_deg = float(G.in_degree(node))
                out_deg = float(G.out_degree(node))
                cent_val = float(centrality.get(node, 0.0))
                is_root = 1.0 if in_deg == 0 else 0.0
                G.nodes[node].update({
                    'centrality': cent_val,
                    'is_root': bool(is_root),
                    'features': [n_type_idx, in_deg, out_deg, cent_val, is_root]
                })

            graphs.append(G)

        logger.info(
            f"Built {len(graphs)} subgraphs from {len(raw_graphs)} raw groups "
            f"(merged {len(raw_graphs) - len(graphs)} fragment(s))."
        )
        return graphs


