import logging
from abc import ABC, abstractmethod
from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)

class LogConsumer(ABC):
    """
    Abstract interface for log ingestion.
    Prepares the system for future Kafka streaming migration.
    """
    @abstractmethod
    def fetch_logs(self, start_time: str, end_time: str) -> list:
        pass

    @abstractmethod
    def fetch_ancestry_by_session(self, session_id: str, process_id: str = None) -> list:
        pass

class OpenSearchPollingConsumer(LogConsumer):
    """
    Hybrid Adapter for polling OpenSearch efficiently with connection pooling.
    """
    def __init__(self, host='localhost', port=9200, index_name='logs-*', maxsize=25, timeout=30):
        self.index_name = index_name
        self.client = OpenSearch(
            hosts=[{'host': host, 'port': port}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
            maxsize=maxsize,
            timeout=timeout
        )

    def fetch_logs(self, start_time: str, end_time: str) -> list:
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
        try:
            response = self.client.search(index=self.index_name, body=query)
            return [hit['_source'] for hit in response.get('hits', {}).get('hits', [])]
        except Exception as e:
            logger.error(f"Error fetching logs from OpenSearch: {e}")
            return []

    def fetch_ancestry_by_session(self, session_id: str, process_id: str = None) -> list:
        must_clauses = [{"match": {"session_id": session_id}}]
        if process_id:
            must_clauses.append({"match": {"process_id": process_id}})
            
        query = {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            },
            "size": 10000,
            "sort": [{"@timestamp": {"order": "asc"}}]
        }
        try:
            response = self.client.search(index=self.index_name, body=query)
            return [hit['_source'] for hit in response.get('hits', {}).get('hits', [])]
        except Exception as e:
            logger.error(f"Error fetching ancestry from OpenSearch: {e}")
            return []
