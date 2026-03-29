import json
import logging
import requests
import re
from typing import Dict, Any, List
import networkx as nx

logger = logging.getLogger(__name__)

class LLMInvestigator:
    """
    Module responsible for taking anomalous subgraphs and using a local or cloud LLM
    to translate the graph's topology and actions into a readable forensic report.
    Forces output to a strict JSON format containing extracted Observables and MITRE ATT&CK TTPs.
    """

    def __init__(self, mode: str = "local", ollama_host: str = "http://localhost:11434", model_name: str = "llama3", api_key: str = None):
        """
        Initializes the LLM investigator.

        Args:
            mode: 'local' (Ollama) or 'cloud' (Google Gemini).
            ollama_host: The URL for the local Ollama instance.
            model_name: The name of the local model to use in Ollama (e.g., 'llama3', 'qwen:7b').
            api_key: The API key for the cloud service (Google Gemini). Required if mode is 'cloud'.
        """
        self.mode = mode.lower()
        self.ollama_host = ollama_host
        self.model_name = model_name
        self.api_key = api_key

        if self.mode == "cloud" and not self.api_key:
            raise ValueError("API key must be provided when using 'cloud' mode.")

        self.system_prompt = (
            "You are an elite DFIR (Digital Forensics and Incident Response) Threat Hunter analyzing anomalous system behavior.\n"
            "I will provide you with an anomalous provenance graph containing processes, files, network connections, and their interactions.\n"
            "Your task is to analyze these interactions and infer potential malicious activities.\n"
            "You MUST extract Observables (IPs, Hashes, Tools/File names) and map the findings to MITRE ATT&CK TTPs.\n"
            "CRITICAL: You MUST respond ONLY with a valid JSON object. No markdown blocks, no introduction, no conversational text.\n"
            "Ensure the JSON strictly follows this schema:\n"
            "{\n"
            "  \"summary\": \"Brief narrative of the potential attack\",\n"
            "  \"observables\": [\n"
            "    {\"type\": \"ipv4-addr\", \"value\": \"192.168.1.100\"},\n"
            "    {\"type\": \"file:name\", \"value\": \"malware.exe\"}\n"
            "  ],\n"
            "  \"ttps\": [\n"
            "    {\"id\": \"T1059\", \"name\": \"Command and Scripting Interpreter\"}\n"
            "  ]\n"
            "}\n"
        )

    def _graph_to_text(self, G: nx.DiGraph) -> str:
        """
        Converts the NetworkX subgraph into a structured text representation for the LLM prompt.
        """
        nodes_desc = []
        for n, data in G.nodes(data=True):
            node_type = data.get('type', 'unknown')
            nodes_desc.append(f"Node: {n} (Type: {node_type})")

        edges_desc = []
        for u, v, data in G.edges(data=True):
            action = data.get('action', 'interacted_with')
            timestamp = data.get('timestamp', 'unknown_time')
            edges_desc.append(f"{u} --[{action} at {timestamp}]--> {v}")

        return "GRAPH NODES:\n" + "\n".join(nodes_desc) + "\n\nGRAPH ACTIONS:\n" + "\n".join(edges_desc)

    def _call_ollama(self, prompt: str) -> str:
        """Makes an API call to the local Ollama instance."""
        url = f"{self.ollama_host}/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "system": self.system_prompt,
            "stream": False,
            "format": "json" # Force JSON output if supported by model version
        }
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            return response.json().get('response', '')
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling Ollama API: {e}")
            return ""

    def _call_gemini(self, prompt: str) -> str:
        """Makes an API call to Google Gemini Pro."""
        # Using the standard REST API for Gemini
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={self.api_key}"

        full_prompt = f"{self.system_prompt}\n\nUSER PROMPT:\n{prompt}"

        payload = {
            "contents": [{
                "parts": [{"text": full_prompt}]
            }],
            "generationConfig": {
                "temperature": 0.2, # Low temperature for more deterministic/JSON-compliant output
            }
        }
        try:
            response = requests.post(url, json=payload, timeout=60)
            response.raise_for_status()
            # Parse Gemini response structure
            candidates = response.json().get('candidates', [])
            if candidates:
                return candidates[0].get('content', {}).get('parts', [{}])[0].get('text', '')
            return ""
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling Gemini API: {e}")
            return ""

    def _parse_json_fallback(self, text: str) -> Dict[str, Any]:
        """
        Fallback mechanism to extract JSON if the LLM wraps it in markdown blocks
        or includes conversational text despite instructions.
        """
        # Try direct parsing first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Direct JSON parsing failed. Attempting fallback extraction...")

        # Look for JSON block within markdown (```json ... ```)
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Look for anything resembling a JSON object
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        logger.error(f"Failed to extract JSON from LLM response. Raw response: {text[:200]}...")
        # Return a safe default structure to prevent pipeline crashes
        return {
            "summary": "Failed to parse LLM response.",
            "observables": [],
            "ttps": []
        }

    def investigate(self, anomalous_graphs: List[nx.DiGraph]) -> Dict[str, Dict[str, Any]]:
        """
        Takes a list of anomalous subgraphs, generates a report for each,
        and returns a mapping of graph_id to the generated forensic report JSON.
        """
        reports = {}
        for G in anomalous_graphs:
            graph_id = G.graph.get('graph_id', 'unknown_id')
            logger.info(f"Investigating anomalous subgraph: {graph_id} via {self.mode} LLM...")

            graph_text = self._graph_to_text(G)
            prompt = f"Analyze the following provenance graph and provide the JSON report.\n\n{graph_text}"

            if self.mode == 'local':
                raw_response = self._call_ollama(prompt)
            elif self.mode == 'cloud':
                raw_response = self._call_gemini(prompt)
            else:
                logger.error(f"Unknown mode: {self.mode}")
                continue

            if not raw_response:
                logger.warning(f"Received empty response for graph {graph_id}")
                continue

            # Enforce JSON parsing with fallback
            report_json = self._parse_json_fallback(raw_response)
            reports[graph_id] = report_json

        return reports
