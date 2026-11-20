from __future__ import annotations

from html import escape

import pandas as pd
import streamlit as st

from aegistrace.agent import run_triage
from aegistrace.ai_summary import generate_ai_summary
from aegistrace.ingest import demo_events, parse_bytes
from aegistrace.reporting import safe_csv_cell, to_findings_csv, to_json, to_markdown

st.set_page_config(page_title="AegisTrace | Security Triage Agent", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
:root { --ink:#e8eef8; --muted:#9aa9be; --panel:#111d30; --panel2:#16243a; --line:#273851; --cyan:#5de0d1; }
.stApp { background: radial-gradient(ellipse at 10% 0%, #142541 0%, #0b1423 48%, #08111d 100%); color:var(--ink); }
section[data-testid="stSidebar"] { background:#0c1727; border-right:1px solid #26364c; }
.block-container { padding-top:1.8rem; padding-bottom:2.2rem; max-width:1500px; }
[data-testid="stMetric"] { background:linear-gradient(145deg,#15243a,#101c2d); border:1px solid #2b3d56; padding:14px 16px; border-radius:14px; }
[data-testid="stMetricLabel"] p { color:#aab9cb !important; font-size:.83rem !important; }
[data-testid="stMetricValue"] { color:#f2f7ff !important; }
div[data-testid="stVerticalBlockBorderWrapper"] { background:rgba(17,29,48,.82); border-color:#2b3d56 !important; border-radius:14px !important; }
.stButton button, .stDownloadButton button { border-radius:10px; border:1px solid #47607f; font-weight:650; }
.stButton button[kind="primary"] { background:#087e87; border-color:#20b9ae; color:white; }
.stTabs [data-baseweb="tab-list"] { gap:8px; border-bottom:1px solid #2b3d56; }
.stTabs [data-baseweb="tab"] { color:#b7c5d7; border-radius:8px 8px 0 0; }
.stTabs [aria-selected="true"] { color:#5de0d1 !important; }
.aegis-kicker { color:#65d9d1; font-size:.76rem; font-weight:800; letter-spacing:.16em; text-transform:uppercase; }
.aegis-title { color:#f3f7ff; font-size:2.2rem; line-height:1.1; font-weight:800; margin:0; }
.aegis-subtitle { color:#a9b8cc; font-size:1rem; margin-top:.35rem; }
.pill { display:inline-block; border:1px solid #35536a; background:#142a3b; color:#7be2d8; border-radius:999px; padding:3px 10px; font-size:.75rem; font-weight:700; margin-right:5px; }
.small-muted { color:#9aabc0; font-size:.82rem; }
.incident-title { color:#f5f8ff; font-weight:750; font-size:1rem; }
hr { border-color:#293b52 !important; }
</style>
""", unsafe_allow_html=True)


def _as_frame(events):
    rows = []
    for event in events:
        rows.append({
            "Time (UTC)": event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "Not supplied",
            "Event": event.event_type.replace("_", " ").title(),
            "User": event.username,
            "Source IP": event.source_ip or "—",
            "Host": event.hostname,
            "Event ID": event.event_id or "—",
            "Source": event.source,
        })
    return pd.DataFrame(rows)


def _severity_colour(severity: str) -> str:
    return {"CRITICAL": "#ff6b78", "HIGH": "#ffb454", "MEDIUM": "#6db8ff", "LOW": "#7dd9a6"}.get(severity, "#aab9cb")


def _show_incident(incident, events):
    with st.container(border=True):
        left, right = st.columns([5, 1])
        with left:
            st.markdown(f"<div class='incident-title'>{incident.incident_id} · {incident.title}</div>", unsafe_allow_html=True)
            st.caption(escape(f"{incident.first_seen or 'Time unavailable'} → {incident.last_seen or 'Time unavailable'} · {incident.source_ip or 'No source IP in logs'}"))
        with right:
            st.markdown(f"<div style='text-align:right;color:{_severity_colour(incident.severity)};font-weight:850'>{incident.severity}</div><div style='text-align:right;color:#aab9cb;font-size:.8rem'>Priority {incident.risk_score}/100</div>", unsafe_allow_html=True)
        st.write(incident.finding_titles[0] if len(incident.finding_titles) == 1 else " · ".join(incident.finding_titles))
        st.caption(escape(f"Confidence: {incident.confidence}  |  Accounts: {', '.join(incident.users) or 'Not identified'}  |  Hosts: {', '.join(incident.hostnames) or 'Not identified'}"))
        with st.expander("Inspect evidence & recommended response"):
            st.markdown("**Why AegisTrace raised this incident**")
            for evidence in incident.evidence:
                st.text(f"• {evidence}")
            st.markdown("**Related MITRE ATT&CK techniques**")
            if incident.mitre:
                for item in incident.mitre:
                    st.markdown(f"- `{item}`")
            else:
                st.caption("No mapped technique for this finding.")
            st.markdown("**Recommended human investigation**")
            for number, step in enumerate(incident.recommendations, 1):
                st.markdown(f"{number}. {step}")
            if incident.event_indexes:
                evidence_df = _as_frame([events[index] for index in incident.event_indexes])
                st.markdown("**Source log records**")
                st.dataframe(evidence_df, use_container_width=True, hide_index=True)
            st.info("Human approval required. No IP blocking, account disabling, session termination or endpoint changes are performed.")


if "triage_result" not in st.session_state:
    st.session_state.triage_result = run_triage(demo_events())
    st.session_state.dataset_label = "Built-in synthetic SOC scenario"
    st.session_state.ai_summary = ""

with st.sidebar:
    st.markdown("## 🛡️ AegisTrace")
    st.caption("LOCAL-FIRST SECURITY TRIAGE")
    st.markdown("---")
    st.markdown("**Data source**")
    source_choice = st.radio("Choose input", ["Built-in demo", "Upload security logs"], label_visibility="collapsed")
    if source_choice == "Built-in demo":
        scenario = st.selectbox("Demo scenario", [
            "Full multi-signal simulation",
            "Credential attack & suspected takeover",
            "Privilege changes & audit tampering",
            "Normal baseline",
        ])
        if st.button("Load demo scenario", use_container_width=True, type="primary"):
            all_events = demo_events()
            if scenario == "Credential attack & suspected takeover":
                selected = [e for e in all_events if e.source_ip in {"198.51.100.24", "203.0.113.77"}]
            elif scenario == "Privilege changes & audit tampering":
                selected = [e for e in all_events if e.event_type in {"privileged_login", "account_created", "group_membership_added", "audit_log_cleared"}]
            elif scenario == "Normal baseline":
                selected = [e for e in all_events if e.source_ip == "192.0.2.10"]
            else:
                selected = all_events
            st.session_state.triage_result = run_triage(selected)
            st.session_state.dataset_label = scenario
            st.session_state.ai_summary = ""
            st.rerun()
    else:
        uploaded = st.file_uploader("Upload CSV, JSON, JSONL or Linux .log", type=["csv", "json", "jsonl", "log", "txt"], help="Maximum 5 MB and 20,000 records. Files are processed in memory and not saved by AegisTrace.")
        if uploaded is not None:
            st.caption(f"Selected: {uploaded.name} · {uploaded.size / 1024:.1f} KB")
            if st.button("Analyse uploaded logs", use_container_width=True, type="primary"):
                try:
                    events, warnings = parse_bytes(uploaded.name, uploaded.getvalue())
                    st.session_state.triage_result = run_triage(events, warnings)
                    st.session_state.dataset_label = uploaded.name
                    st.session_state.ai_summary = ""
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))
    st.markdown("---")
    st.markdown("**Detection coverage**")
    st.caption("Brute force · Password spraying · Login after failures · Privileged access · Audit log clearing · Group changes · New accounts · Lockout bursts")
    st.markdown("---")
    st.caption("Privacy: the core engine makes no outbound calls and the app does not persist uploads. In a hosted deployment, uploaded logs and any entered API key pass through the hosting runtime; use synthetic data there. Use a trusted local run for sensitive logs. Optional Gemini receives anonymised aggregate metadata only after explicit opt-in.")
    st.caption("AegisTrace is a triage aid, not a replacement for a SIEM or incident-response team.")

result = st.session_state.triage_result

st.markdown("<div class='aegis-kicker'>DEFENSIVE AI · SECURITY OPERATIONS</div><div class='aegis-title'>Security signal, made actionable.</div><div class='aegis-subtitle'>A transparent triage agent that turns raw authentication events into evidence-backed incidents and safe investigation steps.</div>", unsafe_allow_html=True)
st.markdown(f"<span class='pill'>PS06 · Cybersecurity Triage</span><span class='pill'>LOCAL-FIRST</span><span class='pill'>HUMAN-IN-THE-LOOP</span><span class='small-muted'>Dataset: {escape(str(st.session_state.dataset_label))}</span>", unsafe_allow_html=True)
st.write("")

metric_cols = st.columns(5)
metric_cols[0].metric("Events analysed", f"{len(result.events):,}")
metric_cols[1].metric("Detection signals", f"{len(result.findings):,}")
metric_cols[2].metric("Correlated incidents", f"{len(result.incidents):,}")
metric_cols[3].metric("Critical incidents", f"{result.critical_count:,}")
metric_cols[4].metric("High incidents", f"{result.high_count:,}")

if result.warnings:
    with st.expander(f"Input notes ({len(result.warnings)})", expanded=False):
        for warning in result.warnings:
            st.warning(warning)

overview_tab, incidents_tab, events_tab, analyst_tab = st.tabs(["Overview", "Incident queue", "Event explorer", "AI analyst"])

with overview_tab:
    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Priority incident queue")
        if not result.incidents:
            st.success("No supported detection rules fired for this dataset.")
        else:
            for incident in result.incidents[:3]:
                _show_incident(incident, result.events)
            if len(result.incidents) > 3:
                st.caption(f"{len(result.incidents) - 3} additional incident(s) are available in the Incident queue tab.")
    with right:
        st.subheader("Agent execution trace")
        for step in result.pipeline_steps:
            icon = "🟢" if step["status"] == "Complete" else "🟡"
            with st.container(border=True):
                st.markdown(f"**{icon} {step['name']}**")
                st.caption(step["detail"])
        st.subheader("Detection mix")
        if result.findings:
            counts = pd.Series([f.rule_id.replace("_", " ").title() for f in result.findings]).value_counts()
            st.bar_chart(counts, height=260)
        else:
            st.caption("Detection counts will appear when a rule matches.")
    st.markdown("---")
    st.subheader("What this agent does — and does not do")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**It does**")
        st.markdown("- Normalise supported log formats\n- Detect suspicious authentication and privilege patterns\n- Correlate related evidence into incidents\n- Rank incidents and prepare investigation playbooks\n- Export traceable reports")
    with c2:
        st.markdown("**It never does automatically**")
        st.markdown("- Block an IP address\n- Disable or lock an account\n- Terminate a user session\n- Modify endpoint or firewall settings\n- Claim that a detection proves compromise")

with incidents_tab:
    st.subheader("Correlated incidents")
    if not result.incidents:
        st.info("No incidents to review. Try the built-in credential-attack scenario or upload a supported log export.")
    else:
        severity_filter = st.multiselect("Filter by severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        filtered = [incident for incident in result.incidents if incident.severity in severity_filter]
        st.caption(f"Showing {len(filtered)} of {len(result.incidents)} incidents")
        for incident in filtered:
            _show_incident(incident, result.events)

with events_tab:
    st.subheader("Normalised event explorer")
    event_types = sorted({event.event_type for event in result.events})
    selected_types = st.multiselect("Event types", event_types, default=event_types)
    visible = [event for event in result.events if event.event_type in selected_types]
    st.caption(f"Showing {len(visible):,} of {len(result.events):,} records · all times shown in UTC")
    st.dataframe(_as_frame(visible), use_container_width=True, hide_index=True, height=420)
    safe_frame = _as_frame(visible).apply(lambda column: column.map(safe_csv_cell))
    st.download_button("Download normalised events (CSV)", safe_frame.to_csv(index=False).encode("utf-8"), file_name="aegistrace_normalised_events.csv", mime="text/csv")

with analyst_tab:
    st.subheader("Optional Gemini analyst narrative")
    st.write("The deterministic detection engine is the source of truth. Gemini can help turn the anonymised incident summary into a concise executive narrative; it cannot change detections or execute response actions. Priority scores and confidence labels are heuristic indicators, not calibrated probabilities.")
    consent = st.checkbox("I explicitly consent to sending anonymised incident counts, rule IDs, severities and evidence counts to Google Gemini. Raw logs, IP addresses, usernames, hostnames and messages are not sent.", value=False)
    api_key = st.text_input("Gemini API key (or configure Streamlit secrets)", type="password", help="Optional. The local triage workflow works without an API key.")
    secret_key = ""
    secret_model = None
    try:
        secret_key = st.secrets.get("GEMINI_API_KEY", "")
        secret_model = st.secrets.get("GEMINI_MODEL")
    except Exception:
        pass
    if st.button("Generate AI narrative", disabled=not consent, type="primary"):
        try:
            with st.spinner("Generating a privacy-minimised narrative…"):
                st.session_state.ai_summary = generate_ai_summary(result, api_key=api_key or secret_key or None, model=secret_model)
        except Exception as exc:
            st.error(str(exc))
    if st.session_state.ai_summary:
        st.markdown("#### Analyst narrative")
        st.markdown(st.session_state.ai_summary)
    else:
        st.info("AI narrative not requested. All findings, risk scores, evidence and playbooks are available from the local engine.")

st.markdown("---")
st.subheader("Export investigation report")
st.warning("Exports may include usernames, source IPs, hostnames and raw source-log messages. Treat downloaded reports as confidential and do not commit real-world logs to a public repository.")
report_cols = st.columns(3)
report_cols[0].download_button("Download report · Markdown", to_markdown(result).encode("utf-8"), file_name="aegistrace_report.md", mime="text/markdown", use_container_width=True)
report_cols[1].download_button("Download report · JSON", to_json(result).encode("utf-8"), file_name="aegistrace_report.json", mime="application/json", use_container_width=True)
report_cols[2].download_button("Download incidents · CSV", to_findings_csv(result).encode("utf-8"), file_name="aegistrace_incidents.csv", mime="text/csv", use_container_width=True)
st.caption("Synthetic demo addresses use documentation-only IP ranges. Always validate detections against your environment and approved incident-response procedures.")
