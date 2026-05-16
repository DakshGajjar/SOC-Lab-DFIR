"""
soc_dashboard.py — Junior SOC Analyst Streamlit Dashboard

Tabs: Live Alerts, Open Cases, AI Triage, Generate Reports, Generate MOP, Stack Health
"""

import json
import time
import os
import requests
import urllib3
import streamlit as st
import pandas as pd
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WAZUH_URL = os.getenv("WAZUH_URL", "https://localhost:55000")
WAZUH_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_PASS = os.getenv("WAZUH_API_PASSWORD", "wazuh-wui")
IRIS_URL = os.getenv("IRIS_URL", "http://localhost:8000")
IRIS_KEY = os.getenv("IRIS_API_KEY", "")
SHUFFLE_URL = os.getenv("SHUFFLE_URL", "http://localhost:3001")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:7b")

SYSTEM_PROMPT = (
    "You are a junior SOC analyst assistant embedded in a security operations center. "
    "The environment you protect runs Wazuh for SIEM, DFIR IRIS for case management, "
    "and Shuffle for SOAR orchestration. All infrastructure runs on Podman containers "
    "on a local Intel NUC with 12GB RAM. When generating MOPs, incident reports, or "
    "triage summaries, be concise, structured, and actionable. Always include: "
    "MITRE ATT&CK technique if applicable, immediate containment steps, investigation "
    "steps, remediation steps, and reporting requirements. Do not hallucinate. "
    "If unsure, say so."
)

SEVERITY_COLORS = {
    "critical": "#ff4444", "high": "#ff8c00",
    "medium": "#ffd700", "low": "#4caf50", "info": "#2196f3",
}

# ---------------------------------------------------------------------------
# API Helpers
# ---------------------------------------------------------------------------

def _safe_get(url, **kwargs):
    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", 15)
    try:
        r = requests.get(url, **kwargs)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def _safe_post(url, **kwargs):
    kwargs.setdefault("verify", False)
    kwargs.setdefault("timeout", 30)
    try:
        r = requests.post(url, **kwargs)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None

def get_wazuh_token():
    try:
        r = requests.post(
            f"{WAZUH_URL}/security/user/authenticate",
            auth=(WAZUH_USER, WAZUH_PASS), verify=False, timeout=15,
        )
        r.raise_for_status()
        return r.json().get("data", {}).get("token", "")
    except Exception:
        return ""

def get_wazuh_alerts(token, limit=50):
    if not token:
        return []
    headers = {"Authorization": f"Bearer {token}"}
    data = _safe_get(
        f"{WAZUH_URL}/alerts", headers=headers,
        params={"limit": limit, "sort": "-timestamp"},
    )
    if data:
        return data.get("data", {}).get("affected_items", [])
    return []

def get_iris_cases():
    headers = {"Authorization": f"Bearer {IRIS_KEY}"} if IRIS_KEY else {}
    data = _safe_get(f"{IRIS_URL}/api/v1/cases", headers=headers)
    if data:
        return data.get("data", [])
    return []

def create_iris_case_from_dashboard(title, description, severity=3):
    headers = {"Authorization": f"Bearer {IRIS_KEY}", "Content-Type": "application/json"}
    payload = {
        "case_name": title, "case_description": description,
        "case_severity": severity, "case_customer": 1,
    }
    return _safe_post(f"{IRIS_URL}/api/v1/cases", headers=headers, json=payload)

def ollama_generate(prompt, system=SYSTEM_PROMPT, stream=False):
    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "system": system, "stream": stream}
    if stream:
        try:
            r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload,
                              stream=True, verify=False, timeout=300)
            r.raise_for_status()
            return r
        except Exception:
            return None
    return _safe_post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=300)

def check_services():
    checks = {
        "Wazuh Manager": (f"{WAZUH_URL}/manager/info", True),
        "OpenSearch": ("https://localhost:9200", False),
        "Wazuh Dashboard": ("https://localhost:443", True),
        "DFIR IRIS": (f"{IRIS_URL}/api/versions", False),
        "Shuffle": (f"{SHUFFLE_URL}/api/v1/health", False),
        "Ollama": (f"{OLLAMA_URL}/api/tags", False),
    }
    results = {}
    for name, (url, needs_ssl) in checks.items():
        try:
            response = requests.get(url, auth=("admin", "admin"), verify=False, timeout=5)
            results[name] = response.status_code < 500
        except Exception:
            results[name] = False
    return results

# ---------------------------------------------------------------------------
# Page Config & Styling
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="SOC Analyst Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    * { font-family: 'Inter', sans-serif; }
    .main { background: linear-gradient(135deg, #0a0e17 0%, #141b2d 50%, #1a1f35 100%); }
    .stApp { background: linear-gradient(135deg, #0a0e17 0%, #141b2d 50%, #1a1f35 100%); }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #111827 0%, #1e293b 100%);
        border-right: 1px solid rgba(99, 102, 241, 0.2);
    }
    .health-card {
        padding: 1.2rem; border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.08);
        text-align: center; margin: 0.3rem;
        backdrop-filter: blur(10px);
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .health-card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }
    .health-up {
        background: linear-gradient(135deg, rgba(16,185,129,0.15), rgba(6,78,59,0.2));
        border-color: rgba(16,185,129,0.4);
    }
    .health-down {
        background: linear-gradient(135deg, rgba(239,68,68,0.15), rgba(127,29,29,0.2));
        border-color: rgba(239,68,68,0.4);
    }
    .metric-card {
        background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.05));
        border: 1px solid rgba(99,102,241,0.2);
        padding: 1.5rem; border-radius: 16px; text-align: center;
        backdrop-filter: blur(10px);
    }
    .severity-critical { color: #ff4444; font-weight: 700; }
    .severity-high { color: #ff8c00; font-weight: 600; }
    .severity-medium { color: #ffd700; }
    .severity-low { color: #4caf50; }
    h1, h2, h3 { color: #e2e8f0 !important; }
    .stButton>button {
        background: linear-gradient(135deg, #6366f1, #8b5cf6) !important;
        color: white !important; border: none !important;
        border-radius: 10px !important; padding: 0.6rem 1.5rem !important;
        font-weight: 600 !important; transition: all 0.3s !important;
    }
    .stButton>button:hover {
        background: linear-gradient(135deg, #4f46e5, #7c3aed) !important;
        box-shadow: 0 4px 15px rgba(99,102,241,0.4) !important;
        transform: translateY(-1px) !important;
    }
    .stTextArea textarea, .stTextInput input {
        background: rgba(30,41,59,0.8) !important;
        border: 1px solid rgba(99,102,241,0.3) !important;
        color: #e2e8f0 !important; border-radius: 10px !important;
    }
    .stSelectbox > div > div {
        background: rgba(30,41,59,0.8) !important;
        border: 1px solid rgba(99,102,241,0.3) !important;
        border-radius: 10px !important;
    }
    div[data-testid="stExpander"] {
        background: rgba(30,41,59,0.5);
        border: 1px solid rgba(99,102,241,0.15);
        border-radius: 12px;
    }
    .block-container { padding-top: 2rem; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px; background: rgba(15,23,42,0.5);
        padding: 4px; border-radius: 12px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px !important; padding: 8px 20px;
        color: #94a3b8 !important; font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #6366f1, #8b5cf6) !important;
        color: white !important;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("## 🛡️ SOC Stack")
    st.markdown("---")
    st.markdown(f"**Ollama Model:** `{OLLAMA_MODEL}`")
    st.markdown(f"**Wazuh:** `{WAZUH_URL}`")
    st.markdown(f"**IRIS:** `{IRIS_URL}`")
    st.markdown("---")
    if st.button("🔄 Refresh All", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

st.markdown("# 🛡️ SOC Analyst Dashboard")

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🚨 Live Alerts", "📂 Open Cases", "🤖 AI Triage",
    "📊 Reports", "📋 Generate MOP", "💚 Stack Health",
])

# ---- Tab 1: Live Alerts ----
with tab1:
    st.subheader("🚨 Live Alerts")
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=30000, limit=None, key="alerts_refresh")
    except ImportError:
        pass

    token = get_wazuh_token()
    if token:
        alerts = get_wazuh_alerts(token)
        if alerts:
            rows = []
            for a in alerts:
                rule = a.get("rule", {})
                agent = a.get("agent", {})
                mitre = rule.get("mitre", {})
                techniques = ", ".join(mitre.get("technique", [])) if mitre else "N/A"
                level = rule.get("level", 0)
                if level >= 12: sev = "critical"
                elif level >= 8: sev = "high"
                elif level >= 5: sev = "medium"
                else: sev = "low"
                rows.append({
                    "Timestamp": a.get("timestamp", ""),
                    "Rule ID": rule.get("id", ""),
                    "Description": rule.get("description", ""),
                    "Severity": sev,
                    "Level": level,
                    "Agent": agent.get("name", "N/A"),
                    "MITRE": techniques,
                })
            df = pd.DataFrame(rows)
            def color_severity(val):
                c = SEVERITY_COLORS.get(val, "#fff")
                return f"color: {c}; font-weight: bold"
            styled = df.style.applymap(color_severity, subset=["Severity"])
            st.dataframe(styled, use_container_width=True, height=400)

            # Expandable details
            for i, a in enumerate(alerts[:10]):
                with st.expander(f"Alert: {a.get('rule',{}).get('description','N/A')[:80]}"):
                    st.json(a)
        else:
            st.info("No alerts found. Wazuh may still be collecting data.")
    else:
        st.warning("⚠️ Cannot connect to Wazuh API. Check that Wazuh Manager is running.")
        st.markdown("""
        <div class="health-card health-down">
            <h3>Wazuh Unavailable</h3>
            <p>The SIEM is not responding. Alerts will appear once the service is healthy.</p>
        </div>
        """, unsafe_allow_html=True)

# ---- Tab 2: Open Cases ----
with tab2:
    st.subheader("📂 Open Cases — DFIR IRIS")
    cases = get_iris_cases()
    if cases:
        rows = []
        for c in cases if isinstance(cases, list) else []:
            rows.append({
                "Case ID": c.get("case_id", ""),
                "Title": c.get("case_name", ""),
                "Severity": c.get("case_severity", ""),
                "Status": c.get("case_status", ""),
                "Created": c.get("case_open_date", ""),
            })
        if rows:
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, height=400)
            st.markdown(f"[Open DFIR IRIS →]({IRIS_URL})", unsafe_allow_html=True)
        else:
            st.info("No cases found.")
    else:
        st.warning("⚠️ Cannot connect to DFIR IRIS or no cases exist yet.")

# ---- Tab 3: AI Triage Console ----
with tab3:
    st.subheader("🤖 AI Triage Console")
    st.markdown("Paste alert JSON or describe a security event for AI analysis.")

    alert_input = st.text_area(
        "Alert JSON or Event Description",
        height=200,
        placeholder='{"rule": {"id": "5710", "description": "sshd: Attempt to login using a denied user."}, ...}',
        key="triage_input",
    )

    col1, col2 = st.columns(2)

    with col1:
        if st.button("🔍 Analyze with Ollama", use_container_width=True, key="analyze_btn"):
            if alert_input.strip():
                prompt = (
                    f"Analyze this security event and provide:\n"
                    f"1. Summary\n2. MITRE ATT&CK technique\n"
                    f"3. Severity assessment\n4. Immediate containment steps\n"
                    f"5. Investigation steps\n6. Remediation steps\n\n"
                    f"Event:\n{alert_input}"
                )
                with st.spinner("🔄 Ollama is analyzing..."):
                    resp = ollama_generate(prompt, stream=True)
                    if resp:
                        result_container = st.empty()
                        full_response = ""
                        for line in resp.iter_lines():
                            if line:
                                try:
                                    data = json.loads(line)
                                    chunk = data.get("response", "")
                                    full_response += chunk
                                    result_container.markdown(full_response)
                                    if data.get("done"):
                                        break
                                except json.JSONDecodeError:
                                    continue
                        st.session_state["last_triage"] = full_response
                    else:
                        st.error("❌ Could not connect to Ollama. Is it running?")
            else:
                st.warning("Please enter an alert or event description.")

    with col2:
        if st.button("📂 Create IRIS Case", use_container_width=True, key="create_case_btn"):
            triage = st.session_state.get("last_triage", "")
            if triage:
                title = f"AI Triage — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                desc = f"## AI Analysis\n\n{triage}\n\n## Original Input\n\n{alert_input}"
                result = create_iris_case_from_dashboard(title, desc)
                if result:
                    st.success("✅ IRIS case created!")
                else:
                    st.error("❌ Failed to create case. Check IRIS connection.")
            else:
                st.warning("Run an analysis first before creating a case.")

# ---- Tab 4: Generate Reports ----
with tab4:
    st.subheader("📊 Incident Report Generator")
    cases = get_iris_cases()
    case_options = {}
    if cases and isinstance(cases, list):
        for c in cases:
            cid = c.get("case_id", "?")
            name = c.get("case_name", "Unnamed")
            case_options[f"#{cid} — {name}"] = c

    if case_options:
        selected = st.selectbox("Select a case", list(case_options.keys()), key="report_case")
        case_data = case_options[selected]

        if st.button("📝 Generate Incident Report", use_container_width=True, key="gen_report"):
            prompt = (
                f"Generate a comprehensive incident report for this security case:\n\n"
                f"Case: {json.dumps(case_data, indent=2)}\n\n"
                f"Include: Executive Summary, Timeline, Affected Systems, "
                f"MITRE ATT&CK Mapping, Impact Assessment, Containment Actions, "
                f"Remediation Steps, Lessons Learned, Appendix."
            )
            with st.spinner("📝 Generating report..."):
                resp = ollama_generate(prompt, stream=True)
                if resp:
                    result_container = st.empty()
                    full = ""
                    for line in resp.iter_lines():
                        if line:
                            try:
                                data = json.loads(line)
                                full += data.get("response", "")
                                result_container.markdown(full)
                                if data.get("done"):
                                    break
                            except json.JSONDecodeError:
                                continue
                    st.session_state["last_report"] = full

                    # Download buttons
                    col1, col2 = st.columns(2)
                    with col1:
                        st.download_button("📥 Download .md", full,
                                           file_name="incident_report.md",
                                           mime="text/markdown", key="dl_md")
                    with col2:
                        try:
                            from fpdf import FPDF
                            pdf = FPDF()
                            pdf.add_page()
                            pdf.set_font("Helvetica", size=10)
                            for ln in full.split("\n"):
                                pdf.cell(0, 6, ln.encode("latin-1", "replace").decode("latin-1"), ln=True)
                            pdf_bytes = pdf.output()
                            st.download_button("📥 Download .pdf", pdf_bytes,
                                               file_name="incident_report.pdf",
                                               mime="application/pdf", key="dl_pdf")
                        except ImportError:
                            st.info("Install fpdf2 for PDF export")
                else:
                    st.error("❌ Ollama unavailable.")
    else:
        st.info("No IRIS cases found. Create a case first via the AI Triage tab.")

# ---- Tab 5: Generate MOP ----
with tab5:
    st.subheader("📋 Method of Procedure Generator")
    st.markdown("Generate step-by-step procedures for security operations tasks.")

    mop_input = st.text_area(
        "Describe the alert type or procedure needed",
        height=150,
        placeholder="e.g., Brute force SSH attack detected on production server",
        key="mop_input",
    )

    if st.button("📋 Generate MOP", use_container_width=True, key="gen_mop"):
        if mop_input.strip():
            prompt = (
                f"Generate a detailed Method of Procedure (MOP) for the following scenario:\n\n"
                f"{mop_input}\n\n"
                f"Format as:\n"
                f"1. Pre-requisites & Preparation\n"
                f"2. Detection & Validation Steps\n"
                f"3. Containment Procedures\n"
                f"4. Investigation Steps\n"
                f"5. Eradication & Recovery\n"
                f"6. Post-Incident Steps\n"
                f"7. Communication & Escalation Matrix\n"
                f"8. Rollback Plan\n\n"
                f"Be specific with commands, tools, and expected outputs."
            )
            with st.spinner("📋 Generating MOP..."):
                resp = ollama_generate(prompt, stream=True)
                if resp:
                    result_container = st.empty()
                    full = ""
                    for line in resp.iter_lines():
                        if line:
                            try:
                                data = json.loads(line)
                                full += data.get("response", "")
                                result_container.markdown(full)
                                if data.get("done"):
                                    break
                            except json.JSONDecodeError:
                                continue
                    st.download_button("📥 Download MOP (.md)", full,
                                       file_name="mop_procedure.md",
                                       mime="text/markdown", key="dl_mop")
                else:
                    st.error("❌ Ollama unavailable.")
        else:
            st.warning("Please describe the scenario.")

# ---- Tab 6: Stack Health ----
with tab6:
    st.subheader("💚 Stack Health Monitor")
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=60000, limit=None, key="health_refresh")
    except ImportError:
        pass

    results = check_services()
    cols = st.columns(3)
    for i, (svc, ok) in enumerate(results.items()):
        cls = "health-up" if ok else "health-down"
        icon = "✅" if ok else "❌"
        status = "Running" if ok else "Down"
        with cols[i % 3]:
            st.markdown(f"""
            <div class="health-card {cls}">
                <h3 style="color:{'#10b981' if ok else '#ef4444'};margin:0">{icon}</h3>
                <h4 style="color:#e2e8f0;margin:0.3rem 0">{svc}</h4>
                <p style="color:{'#6ee7b7' if ok else '#fca5a5'};margin:0;font-size:0.9rem">{status}</p>
                <p style="color:#64748b;margin:0;font-size:0.75rem">Checked: {datetime.now().strftime('%H:%M:%S')}</p>
            </div>
            """, unsafe_allow_html=True)

    up = sum(1 for v in results.values() if v)
    total = len(results)
    st.markdown(f"### Overall: **{up}/{total}** services healthy")

    # Postgres TCP check
    st.markdown("---")
    import socket
    try:
        with socket.create_connection(("localhost", 5432), timeout=3):
            pg_ok = True
    except Exception:
        pg_ok = False
    cls = "health-up" if pg_ok else "health-down"
    icon = "✅" if pg_ok else "❌"
    st.markdown(f"""
    <div class="health-card {cls}" style="max-width:300px">
        <h4 style="color:#e2e8f0;margin:0">{icon} PostgreSQL</h4>
        <p style="color:{'#6ee7b7' if pg_ok else '#fca5a5'};margin:0">
            {'Running (port 5432)' if pg_ok else 'Down'}
        </p>
    </div>
    """, unsafe_allow_html=True)

