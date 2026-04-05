import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pycti import OpenCTIApiClient
from lib.secrets import _SecretStr

logger = logging.getLogger(__name__)

class CTIIntegration:
    """
    Advanced OpenCTI Integration for SentinelHunter.
    Supports proactive observable enrichment and high-fidelity STIX2 reporting.
    """

    def __init__(self, url: str = None, token: str = None):
        """
        Initializes the OpenCTI API Client.
        """
        self.url = url or os.environ.get('OPENCTI_URL')
        # @MX:WARN: [AUTO] token wrapped in _SecretStr to prevent leakage in logs or repr().
        # @MX:REASON: Bare string attributes are serialised by logging frameworks; wrapping masks the value.
        raw_token = token or os.environ.get('OPENCTI_TOKEN')
        self.token: Optional[_SecretStr] = _SecretStr(raw_token) if raw_token else None
        self.api = None
        self._cache = {} # Simple in-memory cache to avoid redundant sequential lookups during forensics

        if not self.url or not self.token:
            logger.warning("OpenCTI URL or Token not provided. Ingestion will be disabled.")
            return

        try:
            self.api = OpenCTIApiClient(self.url, self.token.get())
            logger.info(f"Connected to OpenCTI at {self.url}")
        except Exception as e:
            logger.error(f"Failed to connect to OpenCTI at {self.url}: {e}")
            self.api = None

    # @MX:ANCHOR: [AUTO] lookup_observable - called from forensic workers and report ingestion pipeline.
    # @MX:REASON: Return contract (None | observable dict) relied upon by multiple callers; caching logic must remain consistent.
    def lookup_observable(self, value: str) -> Optional[Dict[str, Any]]:
        """
        Proactively searches OpenCTI for an existing observable.
        Returns the observable object if found in current feeds. Includes local caching.
        """
        if not self.api or not value: return None
        
        # 1. Check Cache
        if value in self._cache:
            return self._cache[value]

        # 2. High-fidelity check to avoid generic strings (e.g., "explorer.exe")
        if not self._is_high_fidelity(value):
            return None

        try:
            # 3. Search OpenCTI
            observable = self.api.stix_cyber_observable.read(
                filters=[{"key": "value", "values": [value]}]
            )
            if observable:
                logger.info(f"[CTI-HINT] Found existing intel for: {value}")
                self._cache[value] = observable
                return observable
            
            # Cache negative hits too for the duration of the run to avoid re-querying misses
            self._cache[value] = None
        except Exception as e:
            logger.error(f"Error looking up observable {value}: {e}")
        return None

    def _is_high_fidelity(self, value: str) -> bool:
        """
        Checks if the value is a high-fidelity indicator (IP, Domain, URL, or Hash).
        """
        if not value or not isinstance(value, str):
            return False
            
        # IPv4
        if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", value):
            return True
        # IPv6 (Basic)
        if ":" in value and re.match(r"^[0-9a-fA-F:]+$", value):
            return True
        # Domain (Basic)
        if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", value):
            return True
        # URL
        if re.match(r"^https?://[^\s/$.?#].[^\s]*$", value, re.IGNORECASE):
            return True
        # Hashes (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", value):
            return True
            
        return False

    def ingest_report(self, report_data: Dict[str, Any], graph_id: str):
        """
        Ingests the high-fidelity forensic report into OpenCTI as a STIX2 Incident
        with linked Observables and MITRE ATT&CK TTPs.
        """
        if not self.api: return

        try:
            # 1. Create the Incident
            incident_title = report_data.get("incident_title", f"SentinelHunter Alert: {graph_id}")
            summary = report_data.get("summary", "No summary provided.")
            severity = report_data.get("severity", "Medium").lower()
            confidence = int(report_data.get("confidence_score", 0.5) * 100)

            logger.info(f"[CTI] Creating Incident: {incident_title}")
            incident = self.api.incident.create(
                name=incident_title,
                description=f"Risk Justification: {report_data.get('risk_justification')}\n\nSummary: {summary}",
                severity=severity,
                confidence=confidence,
                source=f"SentinelHunter - Graph {graph_id}"
            )

            if not incident:
                logger.error("Failed to create Incident in OpenCTI.")
                return

            incident_id = incident["id"]

            # 2. Link Observables
            for obs in report_data.get("observables", []):
                self._create_and_link_observable(incident_id, obs.get("type"), obs.get("value"), obs.get("description"))

            # 3. Link MITRE TTPs
            for ttp in report_data.get("mitre_mappings", []):
                tech_id = ttp.get("technique_id")
                if tech_id:
                    self._link_attack_pattern(incident_id, tech_id, ttp.get("technique_name", tech_id))

            logger.info(f"[CTI] Successfully pushed incident {incident_id} to OpenCTI.")

        except Exception as e:
            logger.error(f"Error during OpenCTI ingestion: {e}")

    def _create_and_link_observable(self, incident_id: str, type_str: str, value: str, description: str = None):
        """Creates or retrieves an observable and links it to the incident."""
        if not type_str or not value: return
        try:
            # Normalize type for OpenCTI
            oc_type = self._normalize_type(type_str)
            
            # Create the observable
            observable = self.api.stix_cyber_observable.create(
                simple_observable_key=oc_type,
                simple_observable_value=value,
                x_opencti_description=description or "Discovered via SentinelHunter"
            )

            if observable:
                # Create relationship: Incident -> related-to -> Observable
                self.api.stix_core_relationship.create(
                    fromId=incident_id,
                    toId=observable["id"],
                    relationship_type="related-to",
                    description="Observable discovered during forensic analysis"
                )
        except Exception as e:
            logger.error(f"Failed to link observable {value}: {e}")

    def _normalize_type(self, type_str: str) -> str:
        """Maps common observable types to OpenCTI keys."""
        t = type_str.lower()
        if "ipv4" in t or "ip" == t: return "IPv4-Addr"
        if "ipv6" in t: return "IPv6-Addr"
        if "file:name" in t or "file" == t: return "File"
        if "domain" in t: return "Domain-Name"
        if "url" in t: return "Url"
        if "hash" in t or "sha" in t or "md5" in t: return "File"
        return "StixFile" # Fallback

    def _link_attack_pattern(self, incident_id: str, tech_id: str, tech_name: str):
        """Finds a MITRE ATT&CK pattern by ID and links it to the incident."""
        try:
            # Try to find the pattern by external ID (e.g., T1059)
            attack_pattern = self.api.attack_pattern.read(
                filters=[{"key": "external_id", "values": [tech_id]}]
            )

            if not attack_pattern:
                logger.warning(f"Attack Pattern {tech_id} not found in OpenCTI. Creating generic pattern.")
                attack_pattern = self.api.attack_pattern.create(
                    name=tech_name,
                    x_mitre_id=tech_id,
                    description=f"MITRE technique {tech_id} identified by SentinelHunter."
                )

            if attack_pattern:
                self.api.stix_core_relationship.create(
                    fromId=incident_id,
                    toId=attack_pattern["id"],
                    relationship_type="uses",
                    description="Technique identified during forensic analysis"
                )
        except Exception as e:
            logger.error(f"Failed to link TTP {tech_id}: {e}")
