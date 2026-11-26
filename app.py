import streamlit as st
import requests

API_BASE_URL = "http://127.0.0.1:8000/api"

st.set_page_config(
    page_title="SentinelAI | SOC Log & Threat Analyzer",
    layout="wide",
    initial_sidebar_state="expanded"
)


st.markdown("""
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20,400,0,0" />

<style>
    .stApp {
        background-color: #090D16;
        font-family: 'Inter', sans-serif;
    }

    .icon-inline {
        font-family: 'Material Symbols Outlined';
        font-weight: normal;
        font-style: normal;
        font-size: 20px;
        line-height: 1;
        display: inline-flex;
        align-items: center;
        vertical-align: middle;
        margin-right: 6px;
    }

    /* Hero Banner */
    .soc-banner {
        background: linear-gradient(135deg, #0F172A 0%, #1E1B4B 100%);
        border: 1px solid #1E293B;
        border-radius: 12px;
        padding: 24px 30px;
        margin-bottom: 24px;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.45);
    }
    .soc-title {
        font-size: 24px;
        font-weight: 700;
        color: #F8FAFC;
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0;
    }
    .soc-subtitle {
        font-size: 14px;
        color: #94A3B8;
        margin-top: 6px;
    }

    /* KPI Metric Cards */
    .metric-card {
        background-color: #0F172A;
        border: 1px solid #1E293B;
        border-radius: 10px;
        padding: 18px 20px;
    }
    .metric-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        color: #94A3B8;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.6px;
    }
    .metric-value {
        font-size: 26px;
        font-weight: 700;
        color: #F1F5F9;
        margin-top: 8px;
    }

    /* Executive Summary Box */
    .summary-box {
        background-color: #0F172A;
        border-left: 3px solid #6366F1;
        border-top: 1px solid #1E293B;
        border-right: 1px solid #1E293B;
        border-bottom: 1px solid #1E293B;
        padding: 16px 20px;
        border-radius: 0 8px 8px 0;
        color: #CBD5E1;
        font-size: 14px;
        line-height: 1.6;
        margin-bottom: 20px;
    }

    /* Severity Badges */
    .sev-critical {
        background-color: rgba(220, 38, 38, 0.15);
        color: #F87171;
        border: 1px solid rgba(220, 38, 38, 0.4);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
    }
    .sev-high {
        background-color: rgba(234, 88, 12, 0.15);
        color: #FB923C;
        border: 1px solid rgba(234, 88, 12, 0.4);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
    }
    .sev-medium {
        background-color: rgba(234, 179, 8, 0.15);
        color: #FACC15;
        border: 1px solid rgba(234, 179, 8, 0.4);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
    }
    .sev-low {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.4);
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
    }

    .ip-pill {
        background-color: #1E293B;
        color: #38BDF8;
        font-family: 'JetBrains Mono', monospace;
        border: 1px solid #334155;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 12px;
        margin-left: 8px;
    }

    .cmd-box {
        background-color: #020617;
        border: 1px solid #1E293B;
        color: #34D399;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        padding: 10px 14px;
        border-radius: 6px;
        margin-top: 8px;
    }

    .status-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        font-weight: 500;
        color: #94A3B8;
        background: #0F172A;
        padding: 6px 12px;
        border-radius: 6px;
        border: 1px solid #1E293B;
        width: 100%;
    }
    .dot-online { height: 8px; width: 8px; background-color: #10B981; border-radius: 50%; display: inline-block; }
    .dot-offline { height: 8px; width: 8px; background-color: #EF4444; border-radius: 50%; display: inline-block; }
</style>
""", unsafe_allow_html=True)


if "log_text" not in st.session_state:
    st.session_state.log_text = ""
if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []


api_online = False
try:
    r = requests.get("http://127.0.0.1:8000/")
    if r.status_code == 200:
        api_online = True
except requests.exceptions.ConnectionError:
    api_online = False


with st.sidebar:
    st.markdown("""
        <div style="display:flex; align-items:center; gap:8px; font-size:20px; font-weight:700; color:#F8FAFC;">
            <span class="material-symbols-outlined" style="color:#6366F1; font-size:24px;">shield_lock</span>
            SentinelAI SOC
        </div>
        <div style="font-size:12px; color:#94A3B8; margin-top:2px;">AI Threat Detection & Log Forensics</div>
    """, unsafe_allow_html=True)

    st.divider()

    st.markdown("""
        <div style="display:flex; align-items:center; font-size:14px; font-weight:600; color:#E2E8F0; margin-bottom:8px;">
            <span class="icon-inline" style="color:#6366F1;">upload_file</span> Ingest Security Logs
        </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Upload .log or .txt file", type=["log", "txt"])
    if uploaded_file is not None:
        st.session_state.log_text = uploaded_file.read().decode("utf-8", errors="ignore")

    raw_logs = st.text_area(
        "Or paste raw server / auth logs",
        value=st.session_state.log_text,
        height=200,
        placeholder="Paste syslog, auth.log, nginx access.log, or firewall events..."
    )

    if st.button("Analyze Threats", icon=":material/radar:", use_container_width=True, type="primary"):
        if not raw_logs.strip():
            st.warning("Please upload or paste log entries first.")
        else:
            st.session_state.log_text = raw_logs
            st.session_state.chat_history = []
            with st.spinner("Running AI threat hunting & forensics..."):
                res = requests.post(f"{API_BASE_URL}/logs/analyze", json={"log_content": raw_logs})
                if res.status_code == 200:
                    st.session_state.analysis_result = res.json()
                else:
                    st.error(f"Analysis Error: {res.text}")

    st.divider()
    if api_online:
        st.markdown('<div class="status-badge"><span class="dot-online"></span> SOC Engine Online</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="status-badge"><span class="dot-offline"></span> SOC Engine Offline</div>', unsafe_allow_html=True)

# Main Dashboard
st.markdown("""
<div class="soc-banner">
    <div class="soc-title">
        <span class="material-symbols-outlined" style="color:#818CF8; font-size:28px;">security</span>
        Intelligent Security Log & Incident Analyzer
    </div>
    <div class="soc-subtitle">Automated anomaly detection, severity triage, mitigation generation, and forensic log Q&A.</div>
</div>
""", unsafe_allow_html=True)

if not api_online:
    st.error("Cannot connect to FastAPI backend (http://127.0.0.1:8000). Start the Uvicorn server first.")
    st.stop()

if st.session_state.analysis_result is None:
    st.info("Upload a `.log` / `.txt` file or paste raw server logs in the sidebar to begin threat analysis.")
else:
    data = st.session_state.analysis_result
    findings = data.get("findings", [])
    critical_high_count = sum(1 for f in findings if f["severity"] in ["Critical", "High"])

    # KPI Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header"><span>Threat Status</span><span class="material-symbols-outlined" style="color:#F87171;">gpp_maybe</span></div>
                <div class="metric-value">{data['overall_threat_level'].upper()}</div>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header"><span>Events Analyzed</span><span class="material-symbols-outlined" style="color:#38BDF8;">terminal</span></div>
                <div class="metric-value">{data['total_events_analyzed']}</div>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header"><span>Threats Detected</span><span class="material-symbols-outlined" style="color:#FBBF24;">bug_report</span></div>
                <div class="metric-value">{len(findings)}</div>
            </div>
        """, unsafe_allow_html=True)
    with c4:
        st.markdown(f"""
            <div class="metric-card">
                <div class="metric-header"><span>Critical / High</span><span class="material-symbols-outlined" style="color:#EF4444;">warning</span></div>
                <div class="metric-value">{critical_high_count}</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Tabs: Threat Findings vs Interactive Forensic Q&A
    tab1, tab2 = st.tabs(["Detected Threats & Mitigations", "Forensic Log Q&A Assistant"])

    with tab1:
        st.markdown(f"""
            <div class="summary-box">
                <div style="color:#818CF8; font-weight:600; font-size:12px; text-transform:uppercase; margin-bottom:6px; display:flex; align-items:center;">
                    <span class="icon-inline" style="font-size:16px;">auto_awesome</span> Executive Incident Summary
                </div>
                {data['executive_summary']}
            </div>
        """, unsafe_allow_html=True)

        if not findings:
            st.success("No malicious activity or security anomalies detected in the analyzed logs.")
        else:
            for item in findings:
                sev = item["severity"]
                sev_cls = (
                    "sev-critical" if sev == "Critical" else
                    "sev-high" if sev == "High" else
                    "sev-medium" if sev == "Medium" else "sev-low"
                )
                with st.container(border=True):
                    st.markdown(
                        f"<div style='display:flex; justify-content:space-between; align-items:center;'>"
                        f"<span style='font-size:16px; font-weight:600; color:#F8FAFC;'>{item['attack_type']}</span>"
                        f"<div><span class='{sev_cls}'>{sev.upper()}</span><span class='ip-pill'>IP: {item['source_ip']}</span></div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                    st.markdown(f"<p style='color:#94A3B8; font-size:13px; margin-top:10px;'><strong>Evidence:</strong> {item['evidence']}</p>", unsafe_allow_html=True)
                    st.markdown(
                        f"<div style='font-size:12px; color:#94A3B8; font-weight:600;'>RECOMMENDED MITIGATION / REMEDIATION:</div>"
                        f"<div class='cmd-box'>$ {item['mitigation_command']}</div>",
                        unsafe_allow_html=True
                    )

    with tab2:
        st.markdown("Ask natural-language forensic questions about the uploaded log file (e.g., *Which IP targeted the root user?*, *Summarize the timeline of SQL injection attempts*).")

        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        user_q = st.chat_input("Ask a security question about these logs...")
        if user_q:
            st.session_state.chat_history.append({"role": "user", "content": user_q})
            with st.chat_message("user"):
                st.markdown(user_q)

            with st.chat_message("assistant"):
                with st.spinner("Investigating logs..."):
                    q_res = requests.post(
                        f"{API_BASE_URL}/logs/ask",
                        json={"log_content": st.session_state.log_text, "question": user_q}
                    )
                    if q_res.status_code == 200:
                        ans = q_res.json()["answer"]
                        st.markdown(ans)
                        st.session_state.chat_history.append({"role": "assistant", "content": ans})
                    else:
                        st.error(f"Error: {q_res.text}")
