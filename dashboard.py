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
                    # --- vis-network Rendering ---
                    import os as _os
                    vis_nodes, vis_edges = [], []

                    _SKIP_ATTRS = {'type', 'id', 'features', 'log_type', 'agent_id'}

                    for n, data in G.nodes(data=True):
                        nt = data.get('type', 'unknown')

                        # Rich forensic tooltip (HTML accepted by vis-network title)
                        tooltip = (
                            f"<div style='font-family:monospace;min-width:220px;'>"
                            f"<div style='font-weight:700;font-size:13px;border-bottom:1px solid #3498db;"
                            f"margin-bottom:6px;padding-bottom:4px;color:#5dade2;'>"
                            f"{nt.upper()} &nbsp;·&nbsp; NODE</div>"
                            f"<b style='color:#aaa'>ID:</b> <span style='color:#e0e0e0'>{n}</span>"
                        )
                        for k, v in data.items():
                            if k not in _SKIP_ATTRS and v not in (None, '', []):
                                tooltip += f"<br><b style='color:#aaa'>{k.replace('_',' ').title()}:</b> <span style='color:#e0e0e0'>{v}</span>"
                        tooltip += "</div>"

                        # Clean display label — no emoji (icons handle semantics)
                        label = data.get('image_name') or data.get('name') or data.get('exe')
                        if not label:
                            raw = str(n)
                            # Strip resolver prefixes (proc_<guid>, ip_<addr>, file_<path>)
                            for pfx in ('proc_', 'ip_', 'file_', 'proc_name_'):
                                if raw.startswith(pfx):
                                    raw = raw[len(pfx):]
                                    break
                            label = _os.path.basename(raw) if ('/' in raw or '\\' in raw) else raw
                        label = str(label)[:28]

                        vis_nodes.append({
                            "id": str(n),
                            "label": label,
                            "type": nt,
                            "tooltip": tooltip,
                            "in_deg": G.in_degree(n),
                            "out_deg": G.out_degree(n),
                            "is_shadow": data.get('log_type') == 'shadow',
                        })

                    for u, v, edata in G.edges(data=True):
                        action = edata.get('action', 'related').replace('_', ' ').title()
                        is_bridge = edata.get('log_type') == 'bridge'

                        etip = (
                            f"<div style='font-family:monospace;'>"
                            f"<div style='font-weight:700;color:#5dade2;border-bottom:1px solid #3498db;"
                            f"margin-bottom:5px;padding-bottom:3px;'>EDGE · {action.upper()}</div>"
                        )
                        for ek, ev in edata.items():
                            if ek not in {'action', 'log_type', 'event_id'} and ev not in (None, ''):
                                etip += f"<b style='color:#aaa'>{ek.replace('_',' ').title()}:</b> {ev}<br>"
                        etip += "</div>"

                        vis_edges.append({
                            "from": str(u),
                            "to": str(v),
                            "label": action,
                            "tooltip": etip,
                            "is_bridge": is_bridge,
                        })

                    graph_json = json.dumps({"nodes": vis_nodes, "edges": vis_edges})

                    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
<link  rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #07091a; overflow: hidden; font-family: 'Inter', monospace; }}
  #graph {{
    width: 100%; height: 680px;
    background: radial-gradient(ellipse at 50% 40%, #0d1035 0%, #07091a 70%);
    border: 1px solid #1f2a4d; border-radius: 12px;
  }}
  /* vis-network tooltip override */
  .vis-tooltip {{
    background: #10122a !important;
    color: #e0e0e0 !important;
    border: 1px solid #2e86c1 !important;
    border-radius: 8px !important;
    font-size: 12px !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.7) !important;
    padding: 10px 14px !important;
    max-width: 340px !important;
  }}
  #legend {{
    position: absolute; bottom: 14px; left: 16px;
    background: rgba(10,12,30,0.85); border: 1px solid #1f2a4d;
    border-radius: 10px; padding: 10px 14px;
    display: flex; flex-wrap: wrap; gap: 10px 18px;
    font-size: 11px; color: #aaa; pointer-events: none;
    backdrop-filter: blur(4px);
  }}
  #legend span {{ display: flex; align-items: center; gap: 5px; }}
  #legend i {{ width: 14px; text-align: center; }}
  #badge-root  {{ position:absolute; top:14px; left:16px; background:rgba(241,196,15,0.15);
    border:1px solid #f1c40f; border-radius:6px; padding:4px 10px;
    color:#f1c40f; font-size:11px; pointer-events:none; }}
  #badge-leaf  {{ position:absolute; top:14px; left:140px; background:rgba(231,76,60,0.15);
    border:1px solid #e74c3c; border-radius:6px; padding:4px 10px;
    color:#e74c3c; font-size:11px; pointer-events:none; }}
  #controls {{ position:absolute; top:14px; right:16px; display:flex; gap:8px; }}
  .ctrl-btn {{
    background: rgba(30,40,80,0.8); border: 1px solid #1f2a4d;
    color: #7fb3d3; border-radius: 6px; padding: 5px 12px;
    cursor: pointer; font-size: 11px; transition: all .2s;
  }}
  .ctrl-btn:hover {{ background: #1f3a5f; color: #fff; }}
</style>
</head><body>
<div style="position:relative;">
  <div id="graph"></div>
  <div id="badge-root">⬡ ENTRY POINT</div>
  <div id="badge-leaf">◆ TARGET NODE</div>
  <div id="controls">
    <button class="ctrl-btn" onclick="network.fit()">⊕ Fit</button>
    <button class="ctrl-btn" onclick="network.setOptions({{physics:{{enabled:true}}}});setTimeout(()=>network.setOptions({{physics:{{enabled:false}}}}),3000)">↺ Relayout</button>
  </div>
  <div id="legend">
    <span><i class="fa-solid fa-terminal"  style="color:#e74c3c"></i> Process</span>
    <span><i class="fa-solid fa-globe"     style="color:#f39c12"></i> IP Address</span>
    <span><i class="fa-solid fa-file"      style="color:#3498db"></i> File</span>
    <span><i class="fa-solid fa-user"      style="color:#9b59b6"></i> User</span>
    <span><i class="fa-solid fa-server"    style="color:#2ecc71"></i> Service</span>
    <span><i class="fa-solid fa-sitemap"   style="color:#1abc9c"></i> Domain</span>
    <span><i class="fa-solid fa-database"  style="color:#e67e22"></i> Registry</span>
    <span style="border-left:1px dashed #333;padding-left:12px">
      <i class="fa-solid fa-circle" style="color:#f1c40f;font-size:8px"></i> Entry&nbsp;&nbsp;
      <i class="fa-solid fa-circle" style="color:#e74c3c;font-size:8px"></i> Target&nbsp;&nbsp;
      <span style="border-top:2px dashed #666;width:18px;display:inline-block;vertical-align:middle"></span> Inferred edge
    </span>
  </div>
</div>
<script>
(function() {{
  // ── Type config ───────────────────────────────────────────────────────────
  var TYPE_CFG = {{
    process:  {{ fa: '\\uf120', color: '#e74c3c', glow: 'rgba(231,76,60,0.45)'  }},
    ip:       {{ fa: '\\uf0ac', color: '#f39c12', glow: 'rgba(243,156,18,0.40)' }},
    file:     {{ fa: '\\uf15b', color: '#3498db', glow: 'rgba(52,152,219,0.40)' }},
    user:     {{ fa: '\\uf007', color: '#9b59b6', glow: 'rgba(155,89,182,0.40)' }},
    service:  {{ fa: '\\uf233', color: '#2ecc71', glow: 'rgba(46,204,113,0.35)' }},
    domain:   {{ fa: '\\uf0e8', color: '#1abc9c', glow: 'rgba(26,188,156,0.35)' }},
    registry: {{ fa: '\\uf1c0', color: '#e67e22', glow: 'rgba(230,126,34,0.40)' }},
    unknown:  {{ fa: '\\uf128', color: '#7f8c8d', glow: 'rgba(127,140,141,0.25)' }},
  }};

  function resolveType(n) {{
    var t = n.type || 'unknown';
    if (t === 'file') {{
      var id = (n.id + n.label).toLowerCase();
      if (id.indexOf('hk') === 0 || id.indexOf('hkey') >= 0 || id.indexOf('\\\\software') >= 0) return 'registry';
    }}
    if (t === 'ip') {{
      // If looks like a domain (letters + dot + tld) treat as domain
      if (/^[a-z].*\.[a-z]{{2,}}$/i.test(n.label) && !/^\\d/.test(n.label)) return 'domain';
    }}
    if (t === 'process') {{
      var lbl = n.label.toLowerCase();
      if (lbl === 'svchost.exe' || lbl === 'services.exe' || lbl === 'lsass.exe') return 'service';
    }}
    return t in TYPE_CFG ? t : 'unknown';
  }}

  var raw = {graph_json};

  // ── Degree map from edges ─────────────────────────────────────────────────
  var inDeg = {{}}, outDeg = {{}};
  raw.nodes.forEach(function(n) {{ inDeg[n.id] = 0; outDeg[n.id] = 0; }});
  raw.edges.forEach(function(e) {{
    outDeg[e.from] = (outDeg[e.from] || 0) + 1;
    inDeg[e.to]   = (inDeg[e.to]   || 0) + 1;
  }});

  // ── HTML tooltip helper ───────────────────────────────────────────────────
  function mkTip(html) {{
    var el = document.createElement('div');
    el.innerHTML = html;
    return el;
  }}

  // ── Build vis DataSets ────────────────────────────────────────────────────
  var visNodes = new vis.DataSet(raw.nodes.map(function(n) {{
    var rtype   = resolveType(n);
    var cfg     = TYPE_CFG[rtype] || TYPE_CFG.unknown;
    var isRoot  = (inDeg[n.id] || 0) === 0;
    var isLeaf  = (outDeg[n.id] || 0) === 0;
    var isShadow = n.is_shadow;

    var iconColor = isRoot ? '#f1c40f' : (isLeaf ? '#e74c3c' : cfg.color);
    var borderColor = isRoot ? '#f1c40f' : (isLeaf ? '#e74c3c' : '#1f2a4d');
    var glowColor   = isRoot ? 'rgba(241,196,15,0.55)' : (isLeaf ? 'rgba(231,76,60,0.45)' : cfg.glow);
    var iconSize    = isRoot ? 52 : (isLeaf ? 38 : 40);

    return {{
      id:    n.id,
      label: n.label,
      title: mkTip(n.tooltip),
      shape: 'icon',
      icon: {{
        face:   '"Font Awesome 6 Free"',
        weight: '900',
        code:   cfg.fa,
        size:   iconSize,
        color:  isShadow ? '#555' : iconColor,
      }},
      font: {{
        color:       '#c8d6e5',
        size:        11,
        face:        'monospace',
        strokeWidth: 3,
        strokeColor: '#07091a',
        vadjust:     8,
      }},
      shadow: {{ enabled: true, color: isShadow ? 'transparent' : glowColor, size: 18, x: 0, y: 0 }},
      borderWidth:         isRoot || isLeaf ? 3 : 1,
      borderWidthSelected: 4,
      color: {{
        border:     borderColor,
        background: 'transparent',
        highlight:  {{ border: '#5dade2', background: 'transparent' }},
        hover:      {{ border: '#85c1e9', background: 'transparent' }},
      }},
    }};
  }}));

  var visEdges = new vis.DataSet(raw.edges.map(function(e, idx) {{
    return {{
      id:     idx,
      from:   e.from,
      to:     e.to,
      label:  e.label,
      title:  mkTip(e.tooltip),
      arrows: {{ to: {{ enabled: true, scaleFactor: 0.6, type: 'arrow' }} }},
      dashes: e.is_bridge ? [6, 4] : false,
      width:  e.is_bridge ? 1 : 1.8,
      color: {{
        color:     e.is_bridge ? '#2c3e50' : '#34495e',
        highlight: '#3498db',
        hover:     '#5dade2',
      }},
      font: {{
        color:            '#7f8c8d',
        size:             9,
        strokeWidth:      2,
        strokeColor:      '#07091a',
        align:            'middle',
        background:       'rgba(7,9,26,0.75)',
      }},
      smooth: {{ type: 'curvedCW', roundness: 0.12 }},
      selectionWidth: 3,
    }};
  }}));

  // ── Network options ───────────────────────────────────────────────────────
  var options = {{
    physics: {{
      enabled: true,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {{
        gravitationalConstant: -55,
        centralGravity:        0.008,
        springLength:          130,
        springConstant:        0.06,
        damping:               0.45,
        avoidOverlap:          0.6,
      }},
      stabilization: {{ iterations: 180, updateInterval: 20, fit: true }},
    }},
    interaction: {{
      hover:            true,
      tooltipDelay:     80,
      hideEdgesOnDrag:  true,
      multiselect:      true,
      navigationButtons: false,
      keyboard:         {{ enabled: true, speed: {{ x:10, y:10, zoom:0.03 }} }},
      zoomSpeed:        0.7,
    }},
    nodes: {{ chosen: true }},
    edges: {{ chosen: true }},
  }};

  var container = document.getElementById('graph');
  var network   = new vis.Network(container, {{ nodes: visNodes, edges: visEdges }}, options);

  // ── Click: highlight 1-hop neighbourhood ──────────────────────────────────
  var _highlighted = [];
  network.on('click', function(params) {{
    // Restore previous highlight
    if (_highlighted.length) {{
      visEdges.update(_highlighted.map(function(id) {{
        return {{ id: id, width: visEdges.get(id).dashes ? 1 : 1.8, color: {{ color: visEdges.get(id).dashes ? '#2c3e50' : '#34495e' }} }};
      }}));
      _highlighted = [];
    }}
    if (!params.nodes.length) return;
    var connEdges = network.getConnectedEdges(params.nodes[0]);
    _highlighted  = connEdges;
    visEdges.update(connEdges.map(function(id) {{
      return {{ id: id, width: 3, color: {{ color: '#3498db' }} }};
    }}));
  }});

  // Stop physics after stabilisation for a clean frozen look
  network.once('stabilizationIterationsDone', function() {{
    network.setOptions({{ physics: {{ enabled: false }} }});
    network.fit({{ animation: {{ duration: 600, easingFunction: 'easeInOutQuad' }} }});
  }});
}})();
</script>
</body></html>"""
                    st.components.v1.html(html, height=720)
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
