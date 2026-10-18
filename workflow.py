"""
LangGraph workflow for the CTI multi-agent system.

    prepare_input -> planner -> retriever -> [threat_analyzer ->
    mitre_mapper -> risk -> mitigation] -> report

The planner's "AGENTS TO ACTIVATE" decides which analysis agents run
(question mode). For an uploaded report every analysis agent runs,
because the goal is a complete CTI report. Dependencies are always
respected: Risk needs the threat analysis and MITRE mapping, and so on.

Every node catches its own errors, records them in the state and lets
the workflow continue, so a failing agent never loses the whole run.
"""

import importlib
import re
import sys
import time
from pathlib import Path

from langgraph.graph import END, START, StateGraph

ROOT = Path(__file__).resolve().parent

for path in (ROOT, ROOT / "agents"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from state import CTIState                                  # noqa: E402
from ioc_extractor import verify_listed_iocs                # noqa: E402
import pdf_loader                                           # noqa: E402
from retry import call_with_retry                           # noqa: E402


ANALYSIS_ORDER = ["threat_analyzer", "mitre_mapper", "risk", "mitigation"]

DEPENDENCIES = {
    "threat_analyzer": [],
    "mitre_mapper": [],
    "risk": ["threat_analyzer", "mitre_mapper"],
    "mitigation": ["threat_analyzer", "mitre_mapper", "risk"],
}

LABELS = {
    "prepare_input": "Reading input",
    "planner": "Planner Agent",
    "retriever": "Retriever Agent",
    "threat_analyzer": "Threat Analyzer",
    "mitre_mapper": "MITRE Mapper",
    "risk": "Risk Assessment",
    "mitigation": "Mitigation",
    "report": "Report Generator",
}

PLAN_KEYWORDS = {
    "threat_analyzer": ("threat analyzer",),
    "mitre_mapper": ("mitre",),
    "risk": ("risk",),
    "mitigation": ("mitigation",),
}


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------

def _module(name):
    return importlib.import_module(name)


def parse_active_agents(plan_text):

    """Reads the 'AGENTS TO ACTIVATE' section of the Planner output."""

    match = re.search(
        r"AGENTS TO ACTIVATE\s*:?(.*?)(?:RETRIEVAL PLAN|DEPENDENCIES|\Z)",
        plan_text or "", re.S | re.I,
    )

    section = (match.group(1) if match else "").lower()

    return {
        agent for agent, words in PLAN_KEYWORDS.items()
        if any(w in section for w in words)
    }


def close_dependencies(agents):

    closed = set(agents)

    for agent in list(agents):
        closed.update(DEPENDENCIES.get(agent, []))

    return [a for a in ANALYSIS_ORDER if a in closed]


def planned_nodes(state):

    """Nodes that will run, in order (used by the UI for progress)."""

    nodes = ["prepare_input", "planner", "retriever"]
    nodes += state.get("active_agents") or ANALYSIS_ORDER
    return nodes + ["report"]


def _finish(state, node, started, detail="", status="ok", extra=None):

    update = dict(extra or {})

    seconds = round(time.time() - started, 2)

    events = list(state.get("events", []))
    events.append({"node": node, "label": LABELS[node], "status": status,
                   "seconds": seconds, "detail": detail})

    timings = dict(state.get("timings", {}))
    timings[node] = seconds

    update.update(events=events, timings=timings)

    return update


def _error(state, node, started, error, extra=None, status="error"):

    errors = list(state.get("errors", []))
    errors.append(f"{LABELS[node]}: {error}")

    update = _finish(state, node, started, str(error), status, extra)
    update["errors"] = errors

    return update


# ------------------------------------------------------------------
# nodes
# ------------------------------------------------------------------

def prepare_input(state):

    started = time.time()

    try:

        if state.get("pdf") is not None:

            doc = pdf_loader.load_report(
                state["pdf"],
                filename=state.get("filename"),
                max_chunks=state.get("max_chunks", 10),
            )

            info = {k: doc[k] for k in
                    ("filename", "pages", "characters", "warnings")}
            info["chunks"] = len(doc["chunks"])
            info["evidence_chunks"] = len(doc["evidence"])

            return _finish(
                state, "prepare_input", started,
                f"{doc['pages']} pages, {doc['characters']:,} characters, "
                f"{len(doc['chunks'])} chunks",
                extra={
                    "mode": "report",
                    "query": f"Analyze the uploaded threat report "
                             f"'{doc['filename']}'.",
                    "report_text": doc["text"],
                    "document_info": info,
                    "iocs": doc["iocs"],
                    "evidence": doc["evidence"],
                },
            )

        question = (state.get("question") or "").strip()

        if not question:
            raise ValueError("Provide a PDF report or a question.")

        return _finish(
            state, "prepare_input", started, "question mode",
            extra={"mode": "query", "query": question, "report_text": "",
                   "iocs": {}, "evidence": [], "document_info": {}},
        )

    except pdf_loader.PDFError as error:
        return _error(state, "prepare_input", started, error,
                      extra={"fatal_error": str(error)})
    except Exception as error:
        return _error(state, "prepare_input", started, error,
                      extra={"fatal_error": str(error)})


def planner(state):

    started = time.time()

    mode = state.get("mode")

    try:
        planner_agent = _module("planner1").planner_agent

        if mode == "report":
            excerpt = state["report_text"][:1500]
            question = ("Analyze this uploaded threat report and produce a "
                        "full cyber threat intelligence analysis.\n\n"
                        f"Report excerpt:\n{excerpt}")
        else:
            question = state["query"]

        plan = call_with_retry(lambda: planner_agent(question))

        requested = parse_active_agents(plan)

        if mode == "report" or not requested:
            active = list(ANALYSIS_ORDER)
        else:
            active = close_dependencies(requested)

        return _finish(state, "planner", started,
                       "agents: " + ", ".join(active),
                       extra={"plan": plan, "active_agents": active})

    except Exception as error:
        return _error(state, "planner", started, error,
                      extra={"plan": "", "active_agents": list(ANALYSIS_ORDER)})


def retriever(state):

    started = time.time()

    evidence = list(state.get("evidence", []))

    if not state.get("use_kb", True):
        return _finish(state, "retriever", started, "knowledge base off")

    try:
        common = _module("common")

        if not common.KB_AVAILABLE:
            raise RuntimeError(
                "knowledge base not available (run ingest.py): "
                + common.KB_ERROR
            )

        retriever_agent = _module("retriever").retriever_agent

        if state.get("mode") == "report":
            kb_query = state["report_text"][:300]
            kb = retriever_agent(kb_query, n_results=3)
        else:
            kb = retriever_agent(state["query"], n_results=5)

        for item in kb:
            item["origin"] = "knowledge_base"

        evidence.extend(kb)

        return _finish(state, "retriever", started,
                       f"{len(kb)} knowledge-base chunks",
                       extra={"evidence": evidence})

    except Exception as error:
        # not fatal: a report can still be built from the PDF alone
        return _error(state, "retriever", started, error,
                      extra={"evidence": evidence}, status="warning")


def threat_analyzer(state):

    started = time.time()

    try:
        agent = _module("threat_analyzer").threat_analyzer_agent

        analysis = call_with_retry(
            lambda: agent(state["query"], state["evidence"])
        )

        verified, unverified = verify_listed_iocs(
            analysis, state.get("report_text", "")
        ) if state.get("report_text") else ([], [])

        return _finish(state, "threat_analyzer", started,
                       f"{len(unverified)} unverified IOCs" if unverified else "ok",
                       extra={"threat_analysis": analysis,
                              "ioc_verification": {"verified": verified,
                                                   "unverified": unverified}})

    except Exception as error:
        return _error(state, "threat_analyzer", started, error,
                      extra={"threat_analysis": ""})


def mitre_mapper(state):

    started = time.time()

    try:
        result = _module("mitre_mapper").mitre_mapper_agent(state["evidence"])

        return _finish(state, "mitre_mapper", started,
                       f"{result.get('total_techniques', 0)} techniques",
                       extra={"mitre": result})

    except Exception as error:
        return _error(state, "mitre_mapper", started, error,
                      extra={"mitre": {"status": "error"}})


def _has_upstream(state):

    """True if the threat analysis or MITRE mapping produced anything."""

    mappings = (state.get("mitre") or {}).get("mappings")

    return bool((state.get("threat_analysis") or "").strip() or mappings)


def _skipped(state, node, started):

    return _finish(
        state, node, started, "skipped: no upstream analysis", "skipped",
        extra={("risk" if node == "risk" else "mitigation"): {
            "status": "error",
            "summary": "Skipped: the Threat Analyzer and MITRE Mapper "
                       "produced no results to assess.",
        }},
    )


def risk(state):

    started = time.time()

    if not _has_upstream(state):
        return _skipped(state, "risk", started)

    try:
        result = _module("risk_agent").risk_agent(
            state["query"], state.get("threat_analysis", ""),
            state.get("mitre"), state["evidence"]
        )

        return _finish(state, "risk", started, result.get("summary", ""),
                       status="ok" if result.get("status") != "error" else "error",
                       extra={"risk": result})

    except Exception as error:
        return _error(state, "risk", started, error,
                      extra={"risk": {"status": "error"}})


def mitigation(state):

    started = time.time()

    if not _has_upstream(state):
        return _skipped(state, "mitigation", started)

    try:
        result = _module("mitigation_agent").mitigation_agent(
            state["query"], state.get("threat_analysis", ""),
            state.get("mitre"), state.get("risk"), state["evidence"]
        )

        return _finish(state, "mitigation", started, result.get("summary", ""),
                       status="ok" if result.get("status") != "error" else "error",
                       extra={"mitigation": result})

    except Exception as error:
        return _error(state, "mitigation", started, error,
                      extra={"mitigation": {"status": "error"}})


def report(state):

    started = time.time()

    try:
        result = _module("report_generator").report_generator_agent(
            state["query"], state.get("threat_analysis", ""),
            state.get("mitre"), state.get("risk"), state.get("mitigation"),
            state.get("evidence"), state.get("plan"),
            output_dir=state.get("output_dir", "reports"),
            extracted_iocs=state.get("iocs"),
            ioc_verification=state.get("ioc_verification"),
            document_info=state.get("document_info"),
        )

        return _finish(state, "report", started,
                       ", ".join(result["files"]), extra={"report": result})

    except Exception as error:
        return _error(state, "report", started, error)


# ------------------------------------------------------------------
# routing + graph
# ------------------------------------------------------------------

def _next_after(current):

    """Router: next active analysis agent after `current`, else report."""

    def router(state):

        active = state.get("active_agents") or ANALYSIS_ORDER

        start = 0 if current is None else ANALYSIS_ORDER.index(current) + 1

        for name in ANALYSIS_ORDER[start:]:
            if name in active:
                return name

        return "report"

    return router


def _after_prepare(state):
    return END if state.get("fatal_error") else "planner"


def build_graph():

    graph = StateGraph(CTIState)

    for name, fn in [("prepare_input", prepare_input), ("planner", planner),
                     ("retriever", retriever), ("threat_analyzer", threat_analyzer),
                     ("mitre_mapper", mitre_mapper), ("risk", risk),
                     ("mitigation", mitigation), ("report", report)]:
        graph.add_node(name, fn)

    targets = {name: name for name in ANALYSIS_ORDER}
    targets["report"] = "report"

    graph.add_edge(START, "prepare_input")
    graph.add_conditional_edges("prepare_input", _after_prepare,
                                {"planner": "planner", END: END})
    graph.add_edge("planner", "retriever")
    graph.add_conditional_edges("retriever", _next_after(None), targets)

    for name in ANALYSIS_ORDER:
        graph.add_conditional_edges(name, _next_after(name), targets)

    graph.add_edge("report", END)

    return graph.compile()


_GRAPH = None


def get_graph():
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH


# ------------------------------------------------------------------
# public API
# ------------------------------------------------------------------

def stream_workflow(initial):

    """
    Yields (node_name, update, merged_state) after every node finishes.
    The final merged state is the last item's third element.
    """

    state = dict(initial)

    for chunk in get_graph().stream(state, stream_mode="updates"):
        for node, update in chunk.items():
            state.update(update or {})
            yield node, update, dict(state)


def run_workflow(initial, on_update=None):

    final = dict(initial)

    for node, update, merged in stream_workflow(initial):
        final = merged
        if on_update:
            on_update(node, update, merged)

    return final


def analyze_pdf(pdf, filename=None, use_kb=True, max_chunks=10,
                output_dir="reports", on_update=None):

    """Full CTI analysis of an unstructured PDF report."""

    return run_workflow({
        "pdf": pdf, "filename": filename, "use_kb": use_kb,
        "max_chunks": max_chunks, "output_dir": output_dir,
        "events": [], "errors": [], "timings": {},
    }, on_update)


def analyze_question(question, use_kb=True, output_dir="reports", on_update=None):

    """Knowledge-base question; the planner chooses the agents."""

    return run_workflow({
        "question": question, "use_kb": use_kb, "output_dir": output_dir,
        "events": [], "errors": [], "timings": {},
    }, on_update)
