import json
import logging
import requests
import re
import os
import time
from typing import Dict, Any, List, Optional
import networkx as nx
from lib.secrets import _SecretStr

logger = logging.getLogger(__name__)

# @MX:NOTE: [AUTO] Required keys for a valid forensic report from the LLM.
# LLM responses that omit these keys are rejected and retried.
_REQUIRED_REPORT_KEYS = {"incident_title", "severity", "confidence_score", "summary"}

class LLMInvestigator:
    """
    Module responsible for taking anomalous subgraphs and using a local or cloud LLM
    to translate the graph's topology and actions into a readable forensic report.
    Forces output to a strict JSON format containing extracted Observables and MITRE ATT&CK TTPs.
    """

    def __init__(self, mode: Optional[str] = None, ollama_host: Optional[str] = None, model_name: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initializes the LLM investigator.
        Args:
            mode: 'ollama' or 'gemini'. Defaults to LLM_MODE env var.
            ollama_host: The URL for the local Ollama instance.
            model_name: The name of the model to use.
            api_key: The API key for Gemini.
        """
        self.mode = (mode or os.getenv("LLM_MODE", "gemini")).lower()
        if self.mode == "local": self.mode = "ollama"
        if self.mode == "cloud": self.mode = "gemini"
        
        self.ollama_host = ollama_host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        # Default to gemini-2.5-flash as per latest listing
        self.model_name = model_name or os.getenv("LLM_MODEL", "gemini-2.5-flash")

        # @MX:WARN: [AUTO] api_key wrapped in _SecretStr to prevent leakage in logs or repr().
        # @MX:REASON: Bare string attributes are serialised by logging frameworks; wrapping masks the value.
        raw_key = api_key or os.getenv("GEMINI_API_KEY")
        self.api_key: Optional[_SecretStr] = _SecretStr(raw_key) if raw_key else None

        if self.mode == "gemini" and not self.api_key:
            logger.warning("GEMINI_API_KEY not found. Gemini calls will fail unless provided in __init__.")

        # Strict DFIR Prompt
        self.system_prompt = (
            "You are an Elite DFIR (Digital Forensics and Incident Response) Analyst and Incident Commander.\n"
            "You are analyzing an anomalous provenance graph. This graph may be heavily focused on NETWORK FLOWS but includes related process and file events.\n\n"
            "### IMPACT ASSESSMENT MANDATE:\n"
            "1. CIA TRIAD: Evaluate the threat across Confidentiality (Data Loss), Integrity (Modification), and Availability (DDoS/Ransomware).\n"
            "2. BLAST RADIUS: Estimate the potential scope of compromise based on process relationships and network reach.\n"
            "3. BUSINESS RISK: Translate technical findings into business risk (e.g., 'Compromise of customer database credentials').\n\n"
            "### OUTPUT RULES:\n"
            "- Respond ONLY with a valid JSON object. No markdown blocks.\n"
            "- Ensure the JSON strictly matches this schema:\n"
            "{\n"
            "  \"incident_title\": \"[TACTIC] e.g. Domain Controller Persistence via Silver Ticket\",\n"
            "  \"severity\": \"Critical | High | Medium | Low\",\n"
            "  \"confidence_score\": 0.98,\n"
            "  \"risk_justification\": \"Why is this anomalous?\",\n"
            "  \"summary\": \"Detailed execution narrative.\",\n"
            "  \"impact_assessment\": {\n"
            "    \"confidentiality\": \"High | Medium | Low | None\",\n"
            "    \"integrity\": \"High | Medium | Low | None\",\n"
            "    \"availability\": \"High | Medium | Low | None\",\n"
            "    \"blast_radius\": \"Single Host | Subnet | Domain-Wide\",\n"
            "    \"technical_description\": \"Detailed impact narrative.\"\n"
            "  },\n"
            "  \"suspicious_indicators\": [\"Indicator A\", \"Indicator B\"],\n"
            "  \"mitre_mappings\": [\n"
            "    {\"tactic\": \"Execution\", \"technique_id\": \"T1059\", \"technique_name\": \"PowerShell\"}\n"
            "  ],\n"
            "  \"observables\": [\n"
            "    {\"type\": \"ipv4-addr\", \"value\": \"...\", \"description\": \"...\"}\n"
            "  ],\n"
            "  \"remediation_steps\": [\"Step 1\", \"Step 2\"]\n"
            "}\n"
        )

    def _graph_to_text(self, G: nx.DiGraph) -> str:
        """
        Converts the NetworkX subgraph into a structured text representation for the LLM prompt.
        Includes rich metadata (Command Line, User, etc.) for deeper forensic context.
        """
        nodes_desc = []
        for n, data in G.nodes(data=True):
            node_type = data.get('type', 'unknown')
            desc = f"Node: {n} (Type: {node_type}"
            
            # Append any available metadata
            metadata_str = ", ".join([f"{k}: {v}" for k, v in data.items() if k not in ['type', 'features']])
            if metadata_str:
                desc += f", Metadata: [{metadata_str}]"
            
            desc += ")"
            nodes_desc.append(desc)

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
            "format": "json" 
        }
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        return response.json().get('response', '')

    def _call_gemini(self, prompt: str) -> str:
        """Makes an API call to Google Gemini using the google-generativeai SDK."""
        if not self.api_key:
            raise ValueError("API key must be provided when using 'gemini' mode.")

        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key.get())
            model = genai.GenerativeModel(
                model_name=self.model_name,
                system_instruction=self.system_prompt
            )
            
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    response_mime_type="application/json"
                )
            )
            return response.text
        except Exception as e:
            logger.error(f"Gemini SDK Error: {e}")
            return ""

    def _parse_json_fallback(self, text: str) -> Dict[str, Any]:
        """
        Fallback mechanism to extract JSON if the LLM wraps it in markdown blocks
        or includes conversational text despite instructions.
        """
        if not text:
            return {}
            
        # Try direct parsing first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Look for JSON block within markdown (```json ... ``` or ``` ... ```)
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Look for anything resembling a JSON object
        json_match = re.search(r'(\{.*\})', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        return {}

    def _validate_report(self, data: Dict[str, Any]) -> bool:
        """Returns True only when the parsed LLM response contains all required report fields."""
        return bool(data) and all(k in data for k in _REQUIRED_REPORT_KEYS)

    # @MX:ANCHOR: [AUTO] investigate - primary entry point called from the main hunt loop and forensic workers.
    # @MX:REASON: Multiple callers rely on consistent return schema {graph_id: report_dict}; any signature change cascades.
    def investigate(self, anomalous_graphs: List[nx.DiGraph], cti_hints: List[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        Takes a list of anomalous subgraphs, generates a report for each,
        and returns a mapping of graph_id to the generated forensic report JSON.
        Injects proactive CTI intelligence hints if provided.
        """
        reports = {}
        for G in anomalous_graphs:
            graph_id = G.graph.get('graph_id', 'unknown_id')
            logger.info(f"Investigating anomalous subgraph: {graph_id} via {self.mode} LLM ({self.model_name})...")

            graph_text = self._graph_to_text(G)
            
            # Incorporate CTI Hints into the prompt
            cti_context = ""
            if cti_hints:
                cti_context = "### PROACTIVE THREAT INTEL HINTS:\n" + "\n".join(cti_hints) + "\n\n"

            prompt = f"{cti_context}Analyze the following provenance graph and provide the JSON report.\n\n{graph_text}"

            final_report = {
                "summary": "Forensic analysis failed after multiple retries.",
                "observables": [],
                "ttps": []
            }

            for attempt in range(1, 4):
                try:
                    if self.mode == 'ollama':
                        raw_response = self._call_ollama(prompt)
                    elif self.mode == 'gemini':
                        raw_response = self._call_gemini(prompt)
                    else:
                        logger.error(f"Unknown mode: {self.mode}")
                        break

                    if raw_response:
                        parsed = self._parse_json_fallback(raw_response)
                        if self._validate_report(parsed):
                            final_report = parsed
                            break

                    logger.warning(f"Attempt {attempt}/3: Invalid or incomplete response for {graph_id}")
                except Exception as e:
                    logger.warning(f"Attempt {attempt}/3: Error calling {self.mode} for {graph_id}: {e}")
                
                if attempt < 3:
                    time.sleep(1)

            reports[graph_id] = final_report

        return reports
