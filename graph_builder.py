import logging
import networkx as nx
from typing import List, Dict, Any
from opensearchpy import OpenSearch
from datetime import datetime

logger = logging.getLogger(__name__)

class GraphBuilder:
    """
    Module responsible for ingesting logs from OpenSearch and converting them
    into Directed Provenance Graphs (subgraphs) using NetworkX.
    """

    def __init__(self, host: str = 'localhost', port: int = 9200, index: str = 'logs-*', **kwargs):
        """
        Initializes the OpenSearch client.
        """
        self.index = index
        try:
            self.client = OpenSearch(
                hosts=[{'host': host, 'port': port}],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                **kwargs
            )
            # Test connection
            if not self.client.ping():
                logger.warning("Could not connect to OpenSearch. Please ensure it is running.")
            else:
                logger.info(f"Successfully connected to OpenSearch at {host}:{port}")
        except Exception as e:
            logger.error(f"Error initializing OpenSearch client: {e}")

    def fetch_logs(self, start_time: str, end_time: str) -> List[Dict[str, Any]]:
        """
        Extracts raw logs (Sysmon, Auditd, eBPF, Tracee, Syslog) from a specific time window.

        Args:
            start_time: ISO 8601 formatted start time string.
            end_time: ISO 8601 formatted end time string.

        Returns:
            List of log dictionaries.
        """
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_time,
                        "lte": end_time
                    }
                }
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
            logs = [hit['_source'] for hit in hits]
            logger.info(f"Fetched {len(logs)} logs from OpenSearch.")
        except Exception as e:
            logger.error(f"Error fetching logs from OpenSearch: {e}")

        return logs

    def build_graphs(self, logs: List[Dict[str, Any]], group_by: str = 'session_id') -> List[nx.DiGraph]:
        """
        Converts a sequence of logs into a list of Directed Provenance Graphs.
        Groups logs into distinct subgraphs based on the `group_by` field (e.g., session_id or process.pid).

        Args:
            logs: List of log dictionaries.
            group_by: Field name used to group logs into distinct subgraphs.

        Returns:
            List of NetworkX DiGraph objects representing subgraphs.
        """
        grouped_logs = {}
        for log in logs:
            # Fallback to a default group if the field is missing
            group_val = log.get(group_by, 'default_group')
            if group_val not in grouped_logs:
                grouped_logs[group_val] = []
            grouped_logs[group_val].append(log)

        graphs = []
        for group_val, group_log_list in grouped_logs.items():
            G = nx.DiGraph(graph_id=group_val)
            for log in group_log_list:
                self._add_log_to_graph(G, log)

            # Only add non-empty graphs
            if G.number_of_nodes() > 0:
                graphs.append(G)

        logger.info(f"Built {len(graphs)} subgraphs from logs.")
        return graphs

    def _add_log_to_graph(self, G: nx.DiGraph, log: Dict[str, Any]):
        """
        Parses a single log and adds nodes/edges to the given graph.
        Handles generic log structures (Sysmon, Auditd, eBPF, Tracee, Syslog).
        """
        # A robust implementation would parse specific fields based on log source.
        # Here we attempt to extract generic entities: source, destination, and action.

        # Determine source node (e.g., process)
        src_node = log.get('process.name') or log.get('source.ip') or log.get('process_name') or 'unknown_process'
        src_type = 'process' if 'process' in str(log).lower() else 'ip'

        # Determine destination node (e.g., file, network IP, or child process)
        dst_node = log.get('file.path') or log.get('destination.ip') or log.get('target.process.name') or log.get('file_name') or 'unknown_target'

        if 'file' in str(log).lower() or 'path' in str(log).lower():
            dst_type = 'file'
        elif 'ip' in str(log).lower():
            dst_type = 'ip'
        else:
            dst_type = 'process'

        # Determine action (edge type)
        action = log.get('event.action') or log.get('action') or log.get('EventID') or 'interacted_with'
        action = str(action).lower()

        # Add nodes with their types (useful for GNN topological embeddings)
        if not G.has_node(src_node):
            G.add_node(src_node, type=src_type)
        if not G.has_node(dst_node):
            G.add_node(dst_node, type=dst_type)

        # Add edge representing the action
        G.add_edge(src_node, dst_node, action=action, timestamp=log.get('@timestamp'))
