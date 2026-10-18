"""Shared state passed through the LangGraph workflow."""

from typing import Any, Dict, List, Optional, TypedDict


class CTIState(TypedDict, total=False):

    # ---- inputs ----
    pdf: Any                       # path, bytes or file object (report mode)
    filename: str
    question: str                  # question mode (knowledge base only)
    mode: str                      # "report" or "query"
    use_kb: bool                   # add knowledge-base evidence
    max_chunks: int                # evidence chunks taken from the PDF
    output_dir: str

    # ---- prepared input ----
    query: str
    report_text: str
    document_info: Dict[str, Any]  # filename, pages, characters, warnings
    iocs: Dict[str, Any]           # deterministic IOC / CVE extraction
    evidence: List[Dict[str, Any]] # chunks given to the agents

    # ---- agent outputs ----
    plan: str
    active_agents: List[str]
    threat_analysis: str
    ioc_verification: Dict[str, List[str]]
    mitre: Dict[str, Any]
    risk: Dict[str, Any]
    mitigation: Dict[str, Any]
    report: Dict[str, Any]

    # ---- bookkeeping ----
    events: List[Dict[str, Any]]   # one entry per finished node
    errors: List[str]
    timings: Dict[str, float]
    fatal_error: Optional[str]
