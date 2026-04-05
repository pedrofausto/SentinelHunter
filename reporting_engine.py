import logging
import os
from datetime import datetime, timezone
from opensearchpy import OpenSearch
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class ReportingEngine:
    """
    Module responsible for persisting high-fidelity forensic reports
    into a dedicated OpenSearch index for long-term tracking and dashboarding.
    """

    def __init__(self, host: str = 'localhost', port: int = 9200, index: str = 'sentinel-incidents', maxsize: int = 25, timeout: int = 30, max_retries: int = 3, **kwargs):
        self.index = index
        try:
            self.client = OpenSearch(
                hosts=[{'host': host, 'port': port}],
                http_compress=True,
                use_ssl=False,
                verify_certs=False,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                maxsize=maxsize,
                timeout=timeout,
                max_retries=max_retries,
                **kwargs
            )
            # Ensure index exists with proper mapping
            if not self.client.indices.exists(index=self.index):
                mapping = {
                    "mappings": {
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "confidence_score": {"type": "float"},
                            "severity": {"type": "keyword"},
                            "status": {"type": "keyword"}
                        }
                    }
                }
                self.client.indices.create(index=self.index, body=mapping)
                logger.info(f"Created reporting index with mapping: {self.index}")
        except Exception as e:
            logger.error(f"Failed to initialize ReportingEngine OpenSearch client: {e}")

    def ingest_incident(self, report_data: Dict[str, Any], graph_id: str):
        """
        Ingests a forensic report into the incidents index.
        """
        try:
            # Enforce timestamp and status
            incident_doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "graph_id": graph_id,
                "status": "New",
                **report_data # Spread the LLM JSON (summary, severity, ttps, etc.)
            }

            response = self.client.index(
                index=self.index,
                body=incident_doc,
                refresh=True
            )
            logger.info(f"Successfully indexed incident {response.get('_id')} for graph {graph_id}")
            return response.get('_id')
        except Exception as e:
            logger.error(f"Error ingesting incident for {graph_id}: {e}")
            return None

    def get_confirmed_threat_ids(self, lookback_days: int = 7) -> List[str]:
        """
        Retrieves all graph_ids (session_ids) that were flagged as incidents
        and NOT marked as 'False Positive' in the last X days.
        Used to actively sanitize the baseline dataset for semi-supervised learning.
        """
        try:
            if not self.client.indices.exists(index=self.index):
                return []
                
            query = {
                "size": 10000,
                "_source": ["source_doc_ids"],
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": f"now-{lookback_days}d/d",
                                        "lte": "now/d"
                                    }
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "status": "False Positive"
                                }
                            }
                        ]
                    }
                }
            }
            
            response = self.client.search(index=self.index, body=query)
            hits = response.get('hits', {}).get('hits', [])
            
            malicious_ids = []
            for hit in hits:
                doc_ids = hit.get('_source', {}).get('source_doc_ids', [])
                if isinstance(doc_ids, list):
                    malicious_ids.extend(doc_ids)
            return list(set(malicious_ids))
            
        except Exception as e:
            logger.error(f"Error retrieving confirmed threats from {self.index}: {e}")
            return []
