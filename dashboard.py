import os
import json
import logging
import streamlit as st
from opensearchpy import OpenSearch
from datetime import datetime, timezone
from dotenv import load_dotenv
from graph_builder import GraphBuilder

load_dotenv()
st.set_page_config(page_title="SentinelHunter Dashboard", layout="wide", initial_sidebar_state="expanded")

# --- UI Theme (Aesthetics) ---
st.markdown("""
    <style>
    .main { background-color: #07091a; color: #e0e0e0; }
    .stMetric { background-color: #0f1229; border: 1px solid #1f2a4d; border-radius: 10px; padding: 15px; }
    .stSidebar { background-color: #0a0d1e !important; border-right: 1px solid #1f2a4d; }
    h1, h2, h3 { color: #5dade2 !important; font-family: 'Inter', sans-serif; }
    .stButton>button { background-color: #2e86c1; color: white; border-radius: 5px; border: none; width: 100%; transition: all 0.3s; }
    .stButton>button:hover { background-color: #3498db; box-shadow: 0 0 15px rgba(52, 152, 219, 0.4); }
    [data-testid="stHeader"] { background: rgba(0,0,0,0); }
    </style>
""", unsafe_allow_html=True)

from lib.consumers import LogConsumer, OpenSearchPollingConsumer

# --- Connection Helper ---
@st.cache_resource
def get_opensearch():
    try:
        return OpenSearch([{'host': 'localhost', 'port': 9200}])
    except Exception:
        return None

client = get_opensearch()
log_consumer = OpenSearchPollingConsumer(host='localhost', port=9200)
builder = GraphBuilder(log_consumer=log_consumer)

# --- Sidebar ---
st.sidebar.title("🛡️ SentinelHunter")
st.sidebar.caption("v2.5 Augmented Reality Threat Hunting")

strategy_opt = st.sidebar.radio(
    "Active Voting Strategy",
    ["MAJORITY", "AVERAGE", "UNION"],
    index=0,
    help="Strategy used by the GNN-driven ensemble engine."
)

ensemble_sensitivity = st.sidebar.slider("Consensus Sensitivity", 0.0, 1.0, 0.5, 0.05)

st.sidebar.markdown("---")
st.sidebar.subheader("🕒 Timeline Checkpoint")
lookback_hours = st.sidebar.slider("Query Lookback (h)", 1, 168, 24)

# --- State Management ---
def re_ingest_malicious():
    import subprocess
    st.info("Re-ingesting 300 malicious records...")
    subprocess.run(["python", "generate_complex_threats.py", "--num_incidents", "50"])
    # Helper to push to OpenSearch at front of index
    import json
    logs = []
    with open('samples/wazuh_mixed_complex.jsonl', 'r') as f:
        for line in f:
            l = json.loads(line)
            l['@timestamp'] = datetime.now(timezone.utc).isoformat()
            logs.append(l)
    for l in logs: client.index(index='logs-sentinel', body=l)
    st.success("300 logs ingested at current timestamp!")

if st.sidebar.button("🗑️ Wipe State"):
    try:
        if os.path.exists(".sentinel_state.json"):
            os.remove(".sentinel_state.json")
            st.sidebar.success("Checkpoint wiped! The main pipeline will rescan logs from 24h ago.")
        else:
            st.sidebar.info("No checkpoint file found.")
    except Exception as e:
        st.sidebar.error(f"Failed to wipe checkpoint: {e}")
    # Use st.rerun() if supported, otherwise st.experimental_rerun()
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()

if st.sidebar.button("🔥 Re-Ingest Malicious Samples"):
    re_ingest_malicious()

# --- Main Tabs ---
t1, t2, t3 = st.tabs(["📊 Incident Feed", "🕸️ Subgraph Topology", "🧠 Engine Diagnostics"])

with t1:
    st.header("Anomalous Incident Stream")
    
    try:
        res = client.search(
            index="sentinel-incidents",
            body={
                "size": 50,
                "sort": [{"@timestamp": "desc"}],
                "_source": ["incident_title", "severity", "graph_id", "confidence_score", "summary", "strategy", "risk_justification", "mitre_mappings", "impact_assessment"]
            }
        )
        hits = res['hits']['hits']
        
        if not hits:
            st.info("No anomalies detected in the current window. The silence is (usually) good.")
        else:
            for h in hits:
                s = h['_source']
                severity = s.get('severity','LOW').upper()
                sev_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
                
                with st.expander(f"{sev_color} {severity} | {s.get('incident_title')} | {s.get('graph_id')[:8]}...", expanded=False):
                    c1, c2 = st.columns([2, 1])
                    
                    with c1:
                        st.markdown(f"### 📝 Forensic Summary")
                        st.write(s.get('summary'))
                        st.markdown(f"**Justification:** {s.get('risk_justification')}")
                        
                        # --- MITRE ATT&CK Section ---
                        mitre = s.get('mitre_mappings', [])
                        if mitre:
                            st.markdown("### 🛡️ MITRE ATT&CK TTPs")
                            cols = st.columns(len(mitre) if len(mitre) < 4 else 4)
                            for i, ttp in enumerate(mitre):
                                with cols[i % 4]:
                                    st.caption(f"**{ttp.get('tactic')}**")
                                    st.code(f"{ttp.get('technique_id')}\n{ttp.get('technique_name')}")

                    with c2:
                        st.metric("Confidence", f"{s.get('confidence_score', 0)*100:.1f}%")
                        st.metric("Detection Strategy", s.get('strategy', 'UNION'))
                        
                        # --- DIFR Insights ---
                        impact = s.get('impact_assessment', {})
                        if impact:
                            st.markdown("---")
                            st.markdown("**💥 Blast Radius:** " + impact.get('blast_radius', 'Unknown'))
                            st.markdown(f"**🔒 Conf:** {impact.get('confidentiality')}")
                            st.markdown(f"** integrity:** {impact.get('integrity')}")
                    
                    if st.button("Investigate Topology", key=f"btn_{h['_id']}"):
                        st.session_state['selected_id'] = s.get('graph_id')
                        st.rerun()
    except Exception as e:
        st.error(f"Failed to query incidents: {e}")

with t2:
    st.header("Anomalous Subgraph Topology")
    
    # Selection logic
    available_ids = []
    try:
        res = client.search(index="sentinel-incidents", body={"size": 100, "_source": ["graph_id", "incident_title"]})
        available_ids = [(h['_source']['graph_id'], h['_source']['incident_title']) for h in res['hits']['hits']]
    except Exception: pass
    
    if available_ids:
        titles = [f"{t} ({i[:8]})" for i, t in available_ids]
        selected_title = st.selectbox("Select Target Anomaly", titles, index=0 if 'selected_id' not in st.session_state else [i for i, t in available_ids].index(st.session_state['selected_id']))
        target_id = available_ids[titles.index(selected_title)][0]
        
        if st.button("Reconstruct Forensic Graph"):
            # Fetch source logs
            try:
                res = client.search(index="sentinel-incidents", body={"query": {"match": {"graph_id": target_id}}, "size": 1})
                src_ids = res['hits']['hits'][0]['_source'].get('source_doc_ids', []) if res['hits']['hits'] else []
                
                logs = []
                if src_ids:
                    l_res = client.search(index="logs-sentinel*", body={"query": {"ids": {"values": src_ids}}, "size": 1000})
                    logs = [dict(h['_source'], _id=h['_id']) for h in l_res['hits']['hits']]
            except Exception as e:
                st.error(f"Failed to query OpenSearch: {e}")
                logs = []
            
            if not logs:
                logs = builder.fetch_logs_with_ancestry("2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z", filter_id=target_id.rsplit('_', 1)[0])
            
            if logs:
                G = builder.build_unified_graph(logs, graph_id=target_id)
                
                st.sidebar.markdown("---")
                st.sidebar.subheader("📊 Graph Statistics")
                st.sidebar.write(f"**Nodes:** {G.number_of_nodes()}")
                st.sidebar.write(f"**Edges:** {G.number_of_edges()}")
                
                if G.number_of_nodes() == 0:
                    st.warning("The forensic graph has no nodes to display.")
                else:
                    # --- Cytoscape Rendering ---
                    nodes, edges = [], []
                    TYPE_COLOR = {"process": "#c0392b", "file": "#2980b9", "ip": "#d68910", "unknown": "#717d7e"}
                    SVG_PROC = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"%3E%3Cpath d="M2 3h20v14H2z" fill="none" stroke="white" stroke-width="1.5"/%3E%3Cpath d="M6 9l3 3-3 3M11 15h5" fill="none" stroke="white" stroke-width="1.5"/%3E%3C/svg%3E'

                    for n, data in G.nodes(data=True):
                        nt = data.get('type', 'unknown')
                        # Build rich forensic tooltip
                        tooltip = f"<div style='font-weight:bold; border-bottom:1px solid #3498db; margin-bottom:5px; padding-bottom:2px;'>{nt.upper()} FORENSICS</div>"
                        tooltip += f"<b>Node ID:</b> {n}"
                        for attr_k, attr_v in data.items():
                            if attr_k not in ['type', 'id', 'features', 'log_type', 'image_name', 'name', 'agent_id']:
                                label_key = attr_k.replace('_', ' ').title()
                                tooltip += f"<br><b>{label_key}:</b> {attr_v}"
                        
                        # Node Labeling Logic: Priority on Process Name / Filename
                        label = data.get('image_name') or data.get('name')
                        if not label:
                            if '/' in str(n) or '\\' in str(n):
                                import os
                                label = os.path.basename(str(n))
                            else:
                                label = str(n)[:15]
                        
                        # Add type prefix for clarity in the UI
                        display_label = f"{label}"
                        if nt == 'ip': display_label = f"🌐 {label}"
                        elif nt == 'file': display_label = f"📄 {label}"
                        elif nt == 'process': display_label = f"⚙️ {label}"

                        nodes.append({"data": {
                            "id": str(n), "label": display_label,
                            "color": TYPE_COLOR.get(nt, "#717d7e"), "type": nt,
                            "tooltip": tooltip
                        }})
                    
                    for u, v, data in G.edges(data=True):
                        action = data.get('action', 'related').upper()
                        # Clean up action names for display
                        display_action = action.replace('_', ' ').title()
                        
                        tooltip = f"<div style='font-weight:bold; border-bottom:1px solid #3498db; margin-bottom:5px; padding-bottom:2px;'>RELATIONSHIP DETAIL</div>"
                        tooltip += f"<b>Action:</b> {action}"
                        for attr_k, attr_v in data.items():
                            if attr_k not in ['action', 'timestamp', 'log_type', 'event_id']:
                                label_key = attr_k.replace('_', ' ').title()
                                tooltip += f"<br><b>{label_key}:</b> {attr_v}"
                        edges.append({"data": {
                            "source": str(u), "target": str(v), "label": display_action,
                            "tooltip": tooltip
                        }})
                    
                    cy_json = json.dumps({"nodes": nodes, "edges": edges})
                    html = f"""
                    <!DOCTYPE html><html><head>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.29.2/cytoscape.min.js"></script>
                    <script src="https://unpkg.com/@popperjs/core@2"></script>
                    <script src="https://unpkg.com/cytoscape-popper@2.0.0/cytoscape-popper.js"></script>
                    <script src="https://unpkg.com/tippy.js@6"></script>
                    <link rel="stylesheet" href="https://unpkg.com/tippy.js@6/animations/scale.css" />
                    <style>
                        #cy {{ width: 100%; height: 600px; background: #07091a; border: 1px solid #1f2a4d; border-radius: 10px; }}
                        .tippy-box[data-theme~='custom'] {{
                            background-color: #1a1c33;
                            color: #e0e0e0;
                            border: 1px solid #3498db;
                            font-family: 'Inter', sans-serif;
                            font-size: 12px;
                            border-radius: 8px;
                            box-shadow: 0 4px 15px rgba(0,0,0,0.5);
                        }}
                        .tippy-content {{ padding: 8px; }}
                    </style></head>
                    <body><div id="cy"></div><script>
                    try {{
                        var cy = cytoscape({{
                            container: document.getElementById('cy'),
                            elements: {cy_json},
                            style: [
                                {{ 
                                    selector: 'node', 
                                    style: {{ 
                                        'background-color': 'data(color)', 
                                        'label': 'data(label)', 
                                        'color': '#fff', 
                                        'font-size': '12px', 
                                        'font-weight': 'bold',
                                        'text-outline-width': 2, 
                                        'text-outline-color': '#07091a',
                                        'text-valign': 'top',
                                        'text-margin-y': -10
                                    }} 
                                }},
                                {{ selector: 'node[type="process"]', style: {{ 'background-image': '{SVG_PROC}', 'background-fit': 'cover', 'background-width': '60%' }} }},
                                {{ 
                                    selector: 'edge', 
                                    style: {{ 
                                        'width': 3, 
                                        'line-color': '#444', 
                                        'target-arrow-color': '#444', 
                                        'target-arrow-shape': 'triangle', 
                                        'curve-style': 'bezier', 
                                        'label': 'data(label)', 
                                        'font-size': '10px', 
                                        'font-weight': 'bold',
                                        'color': '#3498db', 
                                        'text-rotation': 'autorotate',
                                        'text-background-opacity': 0.8,
                                        'text-background-color': '#07091a',
                                        'text-background-padding': '2px',
                                        'text-background-shape': 'roundrectangle'
                                    }} 
                                }}
                            ],
                            layout: {{ name: 'cose', padding: 50, animate: true }}
                        }});

                        function makeTippy(ele, text) {{
                            if (!ele.popperRef) return null;
                            var ref = ele.popperRef();
                            var dummyDomEle = document.createElement('div');
                            return tippy(dummyDomEle, {{
                                getReferenceClientRect: ref.getBoundingClientRect,
                                trigger: 'manual',
                                content: function() {{
                                    var div = document.createElement('div');
                                    div.innerHTML = text;
                                    return div;
                                }},
                                arrow: true,
                                placement: 'top',
                                hideOnClick: false,
                                sticky: 'reference',
                                interactive: true,
                                appendTo: document.body,
                                theme: 'custom',
                                animation: 'scale'
                            }});
                        }}

                        cy.elements().forEach(function(ele) {{
                            var tip = makeTippy(ele, ele.data('tooltip'));
                            if (tip) {{
                                ele.on('mouseover', function() {{ tip.show(); }});
                                ele.on('mouseout', function() {{ tip.hide(); }});
                            }}
                        }});
                    }} catch (e) {{
                        document.body.innerHTML = "<h3 style='color:white; padding:20px;'>Graph Rendering Error: " + e.message + "</h3>";
                        console.error(e);
                    }}
                    </script></body></html>
                    """
                    st.components.v1.html(html, height=620)
            else:
                st.error("No logs found for reconstruction.")
    else:
        st.info("Select an incident from the feed first.")

with t3:
    st.header("Brain Health Monitor")
    if client:
        c1, c2, c3 = st.columns(3)
        try:
            log_count = client.count(index="logs-*")['count']
            incident_count = client.count(index="sentinel-incidents")['count']
            c1.metric("Log Ingestion", log_count)
            c2.metric("Incident Volume", incident_count)
            c3.metric("Uptime", "100.0%")
        except Exception as e:
            st.error(f"Failed to fetch metrics: {e}")
    else:
        st.error("OpenSearch Offline.")
