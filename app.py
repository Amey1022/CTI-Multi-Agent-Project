"""
Streamlit dashboard for the CTI multi-agent platform.

    streamlit run app.py
"""

import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent

for path in (ROOT, ROOT / "agents"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

load_dotenv()

import workflow                                              # noqa: E402
from ioc_extractor import flatten, count as ioc_count        # noqa: E402

STATUS_ICON = {"ok": "✅", "warning": "⚠️", "error": "❌", "skipped": "⏭️"}

MIME = {"markdown": "text/markdown", "html": "text/html",
        "pdf": "application/pdf"}

st.set_page_config(page_title="CTI Multi-Agent Platform",
                   page_icon="🛡️", layout="wide")


# ------------------------------------------------------------------
# running the workflow
# ------------------------------------------------------------------

def run_with_progress(initial):

    """Runs the graph and shows each agent's progress live."""

    final = dict(initial)

    with st.status("Running the agents...", expanded=True) as box:

        slot = st.empty()
        slot.write("⏳ Reading input...")

        for node, update, merged in workflow.stream_workflow(initial):

            final = merged
            event = merged["events"][-1]

            icon = STATUS_ICON.get(event["status"], "•")
            detail = f" - {event['detail']}" if event["detail"] else ""
            st.write(f"{icon} **{event['label']}** ({event['seconds']}s){detail}")

            done = {e["node"] for e in merged["events"]}
            pending = [n for n in workflow.planned_nodes(merged) if n not in done]

            if pending and not merged.get("fatal_error"):
                slot.write(f"⏳ Next: {workflow.LABELS[pending[0]]}...")
            else:
                slot.empty()

        failed = bool(final.get("fatal_error"))
        box.update(label="Failed" if failed else "Analysis complete",
                   state="error" if failed else "complete", expanded=False)

    return final


# ------------------------------------------------------------------
# result rendering
# ------------------------------------------------------------------

def render_results(state):

    from report_generator import parse_threat_analysis, to_list

    if state.get("fatal_error"):
        st.error(state["fatal_error"])
        return

    risk = state.get("risk") or {}
    mitre = state.get("mitre") or {}
    iocs = state.get("iocs") or {}
    report = state.get("report") or {}

    for message in state.get("errors", []):
        st.warning(message)

    for message in (state.get("document_info") or {}).get("warnings", []):
        st.info(message)

    # ---- headline numbers ----
    c = st.columns(6)

    if risk.get("status") != "error" and risk.get("severity"):
        c[0].metric("Severity", risk["severity"], f"{risk['severity_score']}/10",
                    delta_color="off")
        c[1].metric("Likelihood", risk["likelihood"])
        c[2].metric("Priority", risk["priority"].split(" - ")[0])
    else:
        c[0].metric("Severity", "n/a")

    c[3].metric("ATT&CK techniques", mitre.get("total_techniques", 0))
    c[4].metric("Indicators", ioc_count(iocs))
    c[5].metric("CVEs", len(iocs.get("cves", [])))

    if report.get("executive_summary"):
        st.subheader("Executive summary")
        st.write(report["executive_summary"])

    tabs = st.tabs(["Threat overview", "MITRE ATT&CK", "Risk", "Mitigation",
                    "Evidence", "Downloads", "Run log"])

    # ---- threat overview ----
    with tabs[0]:

        sections = parse_threat_analysis(state.get("threat_analysis", ""))

        if any(sections.values()):
            st.markdown(f"**Threat type:** {sections['Threat Type'] or 'n/a'}")
            st.markdown(f"**Malware:** {sections['Malware'] or 'n/a'}")
            st.markdown("**Attack summary**")
            st.write(sections["Attack Summary"] or "n/a")
            if sections["Affected Systems"]:
                st.markdown("**Affected systems**")
                for item in to_list(sections["Affected Systems"]):
                    st.markdown(f"- {item}")
        else:
            st.info("The Threat Analyzer produced no output.")

        rows = flatten(iocs)

        if rows:
            st.markdown("**Indicators found in the document** (pattern matching)")
            st.dataframe(pd.DataFrame(rows, columns=["Type", "Value"]),
                         hide_index=True)

        if iocs.get("cves"):
            st.markdown("**CVEs referenced**")
            for cve in iocs["cves"]:
                st.markdown(f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")

        unverified = (state.get("ioc_verification") or {}).get("unverified", [])

        if unverified:
            st.warning("Listed by the Threat Analyzer but not found in the "
                       "document (treat as unverified): " + ", ".join(unverified))

    # ---- MITRE ----
    with tabs[1]:

        mappings = mitre.get("mappings", [])

        if mappings:
            if mitre.get("attack_flow"):
                st.markdown("**Attack flow:** " + " → ".join(mitre["attack_flow"]))
            st.dataframe(pd.DataFrame([{
                "ID": m["technique_id"], "Technique": m["technique_name"],
                "Tactic": m["tactic"], "Confidence": m.get("confidence"),
            } for m in mappings]), hide_index=True)
        else:
            st.info("No ATT&CK techniques were identified.")

    # ---- risk ----
    with tabs[2]:

        if risk.get("status") == "error" or not risk:
            st.info(risk.get("summary", "Risk assessment not available."))
        else:
            st.markdown(f"**{risk['severity']}** ({risk['severity_score']}/10), "
                        f"likelihood **{risk['likelihood']}**, "
                        f"priority **{risk['priority']}**")
            st.write(risk.get("justification", ""))
            for title, key in (("Business impact", "business_impact"),
                               ("Affected assets", "affected_assets"),
                               ("Assumptions", "assumptions")):
                if risk.get(key):
                    st.markdown(f"**{title}**")
                    for item in risk[key]:
                        st.markdown(f"- {item}")
            if risk.get("baseline_reasons"):
                with st.expander("How the baseline score was computed"):
                    st.write(f"Baseline: {risk.get('baseline_score')}")
                    for r in risk["baseline_reasons"]:
                        st.markdown(f"- {r}")
            if risk.get("validation_notes"):
                st.caption("Validation: " + " ".join(risk["validation_notes"]))

    # ---- mitigation ----
    with tabs[3]:

        mit = state.get("mitigation") or {}

        if mit.get("status") == "error" or not mit:
            st.info(mit.get("summary", "Mitigation plan not available."))
        else:
            st.info(f"Response urgency: {mit['urgency']}")
            for title, key in (("Immediate actions", "immediate_actions"),
                               ("Prevention", "prevention"),
                               ("Detection", "detection"),
                               ("Recovery", "recovery")):
                if mit.get(key):
                    with st.expander(title, expanded=(key == "immediate_actions")):
                        for item in mit[key]:
                            tag = (f" `{', '.join(item['technique_ids'])}`"
                                   if item["technique_ids"] else "")
                            why = f" - {item['rationale']}" if item["rationale"] else ""
                            st.markdown(f"- {item['action']}{why}{tag}")
            if mit.get("attack_mitigations"):
                st.markdown("**ATT&CK mitigation reference**")
                st.dataframe(pd.DataFrame([{
                    "Technique": f"{d['technique_id']} {d['technique_name']}",
                    "Mitigations": ", ".join(f"{x['id']} {x['name']}"
                                             for x in d["mitigations"]) or "None",
                    "Detection": d["detection"],
                } for d in mit["attack_mitigations"]]), hide_index=True)

    # ---- evidence ----
    with tabs[4]:

        evidence = state.get("evidence", [])

        if evidence:
            st.dataframe(pd.DataFrame([{
                "Origin": e.get("origin", ""), "Source": e["source"],
                "Page": e["page"], "Distance": e.get("distance"),
                "Text": e["text"][:200].replace("\n", " "),
            } for e in evidence]), hide_index=True)
        if state.get("plan"):
            with st.expander("Planner output"):
                st.text(state["plan"])

    # ---- downloads ----
    with tabs[5]:

        files = report.get("files", {})

        if not files:
            st.info("No report files were produced.")

        for kind, path in files.items():
            with open(path, "rb") as handle:
                st.download_button(
                    f"Download {kind}", handle.read(),
                    file_name=Path(path).name, mime=MIME.get(kind),
                    key=f"dl_{kind}")

        if report.get("markdown"):
            with st.expander("Preview report"):
                st.markdown(report["markdown"])

    # ---- run log ----
    with tabs[6]:

        st.dataframe(pd.DataFrame([{
            "Step": e["label"], "Status": e["status"],
            "Seconds": e["seconds"], "Detail": e["detail"],
        } for e in state.get("events", [])]), hide_index=True)


# ------------------------------------------------------------------
# page
# ------------------------------------------------------------------

st.title("🛡️ Cyber Threat Intelligence Platform")
st.caption("Multi-agent RAG: upload an unstructured threat report and get a "
           "structured, evidence-backed CTI report.")

with st.sidebar:

    st.header("Input")

    mode = st.radio("Mode", ["Analyze a PDF report", "Ask the knowledge base"])

    use_kb = st.checkbox("Use the knowledge base for extra context", value=True,
                         help="Needs ingest.py to have been run.")

    max_chunks = st.slider("Evidence chunks taken from the PDF", 6, 16, 10,
                           help="More chunks give more context but use more "
                                "of the model's token limit.")

    if os.getenv("GROQ_API_KEY"):
        st.success("Groq API key found")
    else:
        st.error("GROQ_API_KEY is not set (add it to .env)")

    st.divider()
    st.caption("Agents: Planner, Retriever, Threat Analyzer, MITRE Mapper, "
               "Risk Assessment, Mitigation, Report Generator.")

ready = bool(os.getenv("GROQ_API_KEY"))

if mode == "Analyze a PDF report":

    upload = st.file_uploader("Threat report (PDF)", type=["pdf"])

    if st.button("Analyze report", type="primary",
                 disabled=not (upload and ready)):

        st.session_state["result"] = run_with_progress({
            "pdf": upload.getvalue(), "filename": upload.name,
            "use_kb": use_kb, "max_chunks": max_chunks,
            "output_dir": str(ROOT / "reports"),
            "events": [], "errors": [], "timings": {},
        })
        st.rerun()

else:

    question = st.text_input("Question", placeholder="e.g. How does ransomware "
                             "typically gain initial access?")

    if st.button("Ask", type="primary", disabled=not (question and ready)):

        st.session_state["result"] = run_with_progress({
            "question": question, "use_kb": use_kb,
            "output_dir": str(ROOT / "reports"),
            "events": [], "errors": [], "timings": {},
        })
        st.rerun()

if "result" in st.session_state:
    st.divider()
    render_results(st.session_state["result"])
