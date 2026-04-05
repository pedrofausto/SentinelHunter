import json
import os
import glob
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SchemaMapper:
    """
    Log-Agnostic Abstraction Layer.
    Loads vendor-specific JSON schemas from the 'parsers/' directory and dynamically
    extracts Graph Topology concepts (Nodes, Edges, Grouping IDs) from incoming logs.
    """
    def __init__(self, parsers_dir: str = "parsers"):
        self.parsers = []
        self._load_parsers(parsers_dir)

    def _load_parsers(self, parsers_dir: str):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        target_dir = os.path.join(base_dir, "SentinelHunter", parsers_dir)
        
        # Fallback to current directory if not found (for tests)
        if not os.path.exists(target_dir):
            target_dir = os.path.join(os.path.dirname(__file__), parsers_dir)
            
        if not os.path.exists(target_dir):
            logger.warning(f"Parsers directory not found at {target_dir}. Creating it.")
            os.makedirs(target_dir, exist_ok=True)

        for filepath in glob.glob(os.path.join(target_dir, "*.json")):
            try:
                with open(filepath, 'r') as f:
                    schema = json.load(f)
                    self.parsers.append(schema)
                logger.info(f"Loaded schema parser from {os.path.basename(filepath)}")
            except Exception as e:
                logger.error(f"Failed to load schema {filepath}: {e}")

        # Sort by priority ascending (lower number = more specific = evaluated first).
        # Prevents broad parsers (e.g. ECS with generic EventID list) from shadowing
        # specific vendor parsers (e.g. Sysmon with exact providerName match).
        # Parsers without a priority field default to 50 (mid-range).
        self.parsers.sort(key=lambda p: p.get("priority", 50))

    def _get_field(self, log: Dict[str, Any], path: Any) -> Optional[Any]:
        """
        Extracts a value from a nested dict using dot-notation path.
        If 'path' is a list, evaluates each path in order and returns the first matching value.
        """
        if isinstance(path, list):
            for p in path:
                val = self._get_field(log, p)
                if val is not None:
                    return val
            return None
            
        if not path or not isinstance(path, str):
            return None

        # Try the exact flat key FIRST — handles logs that store fields as literal
        # dotted strings (e.g. {"event.action": "process_create"}) rather than
        # as nested dicts (e.g. {"event": {"action": "process_create"}}).
        if isinstance(log, dict) and path in log:
            return log[path]

        # Fall back to dot-notation nested traversal for truly nested dicts
        keys = path.split('.')
        val = log
        for key in keys:
            if isinstance(val, dict) and key in val:
                val = val.get(key)
            else:
                return None
        return val

    # L4+ required fields — at least one must be present in a log for it to be analyzed
    _L4_FIELDS = [
        "dst_port", "src_port", "destination.port", "source.port",
        "process.name", "process.pid", "Image", "CommandLine",
        "event.action", "EventID", "data.win.system.eventID",
        "data.audit.type", "file.path", "TargetFilename"
    ]

    def _has_layer4(self, log: Dict[str, Any]) -> bool:
        """Returns True if the log contains at least one application/transport-layer indicator."""
        return any(self._get_field(log, f) is not None for f in self._L4_FIELDS)

    def parse(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates the log against all loaded parsers.
        Returns a normalized topology object if a match is found.
        """
        # --- Layer 4+ Pre-Filter ---
        # Skip pure Layer 1-3 router/switch logs that carry no application-layer context.
        if not self._has_layer4(log):
            return None

        for parser in self.parsers:
            # Honor per-parser Layer 4 requirement flag
            if parser.get("require_layer4", False) and not self._has_layer4(log):
                continue

            # 1. Check Match Rule
            match_rule = parser.get("match_rule", {})
            field = match_rule.get("field")
            expected_val = match_rule.get("value")
            
            actual_val = self._get_field(log, field)
            
            # Advanced Match Checking - allows fields to be Lists, and handles missing fields robustly
            is_match = False
            if expected_val is None:
                is_match = True
            else:
                expected_list = expected_val if isinstance(expected_val, list) else [expected_val]
                actual_list = actual_val if isinstance(actual_val, list) else [actual_val]
                
                if any(str(a) in [str(e) for e in expected_list] for a in actual_list if a is not None):
                    is_match = True
                    
            if not is_match:
                continue
                
            # 2. Extract Generic Base/Grouping IDs
            group_id = None
            for p in parser.get("group_by", []):
                val = self._get_field(log, p)
                if val:
                    group_id = str(val)
                    break
                    
            if not group_id:
                group_id = "default_group"

            # 3. Extract Timestamp
            ts = self._get_field(log, parser.get("timestamp", "@timestamp"))
            
            # 4. Extract Event-Specific Topology (Nodes & Edges)
            event_id_path = parser.get("event_id_field")
            event_id = str(self._get_field(log, event_id_path) if event_id_path else "") if event_id_path else ""

            event_schema = parser.get("events", {}).get(event_id)

            # Fallback: try matching using event.action string if EventID lookup missed
            if not event_schema:
                action_val = self._get_field(log, "event.action")
                if action_val:
                    # Try to find an event schema whose action value matches
                    for eid, eschema in parser.get("events", {}).items():
                        if eschema.get("action", "") == str(action_val):
                            event_schema = eschema
                            event_id = eid
                            break

            if not event_schema:
                continue
                
            action = event_schema.get("action", "generic_event")
            
            nodes = []
            for n_schema in event_schema.get("nodes", []):
                n_id = self._get_field(log, n_schema.get("id_field", ""))
                if not n_id:
                    continue
                    
                node_data = {
                    "id": str(n_id),
                    "type": n_schema.get("type", "unknown")
                }
                
                # Extract dynamic attributes (e.g., Command Line, Destination Port)
                for attr_name, attr_path in n_schema.get("attributes", {}).items():
                    attr_val = self._get_field(log, attr_path)
                    if attr_val is not None:
                        node_data[attr_name] = str(attr_val)
                        
                nodes.append(node_data)
                
            edges = []
            for e_schema in event_schema.get("edges", []):
                src = self._get_field(log, e_schema.get("from", ""))
                dst = self._get_field(log, e_schema.get("to", ""))
                if src and dst and src != dst:
                    edge_data = {
                        "src": str(src),
                        "dst": str(dst),
                        "action": e_schema.get("action", action),
                        "timestamp": ts,
                        "event_id": event_id
                    }
                    
                    for attr_name, attr_path in e_schema.get("attributes", {}).items():
                        attr_val = self._get_field(log, attr_path)
                        if attr_val is not None:
                            edge_data[attr_name] = str(attr_val)
                            
                    edges.append(edge_data)
                    
            return {
                "matched_parser": parser.get("name", "Unknown"),
                "group_id": group_id,
                "timestamp": ts,
                "nodes": nodes,
                "edges": edges,
                "raw_event_id": event_id
            }
            
        return None
