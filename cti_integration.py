from pycti import OpenCTIApiClient
from datetime import datetime
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class CTIIntegration:
    """
    Module responsible for integrating with OpenCTI to ingest forensic reports.
    It takes the JSON output from the LLM, creates an Incident, and maps Observables
    and Attack Patterns (TTPs) to it.
    """

    def __init__(self, url: str, token: str):
        """
        Initializes the OpenCTI API Client.

        Args:
            url: The base URL of the OpenCTI instance.
            token: The API token for authentication.
        """
        self.url = url
        self.token = token
        self.api = None

        try:
            self.api = OpenCTIApiClient(self.url, self.token)
            logger.info(f"Successfully connected to OpenCTI at {url}")
        except Exception as e:
            logger.error(f"Failed to connect to OpenCTI: {e}")

    def ingest_report(self, report_data: Dict[str, Any], graph_id: str):
        """
        Takes the parsed JSON from the LLM investigator, creates an Incident,
        and links observables and TTPs.

        Args:
            report_data: The JSON output from the LLM. Expected schema:
                {
                    "summary": "...",
                    "observables": [{"type": "ipv4-addr", "value": "..."}],
                    "ttps": [{"id": "T1059", "name": "..."}]
                }
            graph_id: The identifier of the anomalous subgraph.
        """
        if not self.api:
            logger.error("OpenCTI API client is not initialized. Cannot ingest report.")
            return

        try:
            # 1. Create the Incident representing the anomalous event
            incident_name = f"Anomaly Detected: Subgraph {graph_id} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            summary = report_data.get('summary', 'No summary provided by LLM.')

            logger.info(f"Creating OpenCTI Incident: {incident_name}")
            incident = self.api.incident.create(
                name=incident_name,
                description=summary,
                incident_type="anomalous-activity"
            )

            incident_id = incident["id"]

            # 2. Iterate through Observables and link them
            observables_data = report_data.get('observables', [])
            for obs in observables_data:
                obs_type = obs.get('type')
                obs_value = obs.get('value')

                if obs_type and obs_value:
                    logger.debug(f"Creating Observable: {obs_type} = {obs_value}")
                    observable = self._create_observable(obs_type, obs_value)

                    if observable:
                        # Link observable to incident
                        self.api.stix_core_relationship.create(
                            fromId=incident_id,
                            toId=observable["id"],
                            relationship_type="related-to"
                        )

            # 3. Iterate through TTPs (Attack Patterns) and link them
            ttps_data = report_data.get('ttps', [])
            for ttp in ttps_data:
                ttp_id = ttp.get('id') # Expected format e.g., "T1059"
                ttp_name = ttp.get('name')

                if ttp_id:
                    logger.debug(f"Linking Attack Pattern: {ttp_id} ({ttp_name})")
                    # Try to find the Attack Pattern by external ID (MITRE ATT&CK ID)
                    attack_pattern = self.api.attack_pattern.read(
                        filters=[{"key": "external_id", "values": [ttp_id]}]
                    )

                    if not attack_pattern and ttp_name:
                        # If not found, optionally create it (usually it should exist in a populated OpenCTI)
                        logger.warning(f"Attack Pattern {ttp_id} not found. Creating a generic one.")
                        attack_pattern = self.api.attack_pattern.create(
                            name=ttp_name,
                            description=f"Generated from LLM inference for {ttp_id}",
                            x_mitre_id=ttp_id
                        )

                    if attack_pattern:
                        self.api.stix_core_relationship.create(
                            fromId=incident_id,
                            toId=attack_pattern["id"],
                            relationship_type="uses"
                        )

            logger.info(f"Successfully ingested report for {graph_id} into OpenCTI.")

        except Exception as e:
            logger.error(f"Error during OpenCTI ingestion for {graph_id}: {e}")

    def _create_observable(self, type_str: str, value: str) -> Dict[str, Any]:
        """
        Helper method to create specific STIX Cyber Observables in OpenCTI.
        """
        try:
            if type_str.lower() in ["ipv4-addr", "ip"]:
                return self.api.stix_cyber_observable.create(
                    observableData={"type": "IPv4-Addr", "value": value}
                )
            elif type_str.lower() in ["file", "file:name"]:
                return self.api.stix_cyber_observable.create(
                    observableData={"type": "File", "name": value}
                )
            elif type_str.lower() in ["hash", "file:hashes"]:
                # Assume SHA-256 for simplicity if length is 64, else generic hash
                hash_type = "SHA-256" if len(value) == 64 else "MD5"
                return self.api.stix_cyber_observable.create(
                    observableData={"type": "File", "hashes": {hash_type: value}}
                )
            else:
                logger.warning(f"Unsupported observable type: {type_str}")
                return None
        except Exception as e:
            logger.error(f"Failed to create observable {type_str}:{value} - {e}")
            return None
