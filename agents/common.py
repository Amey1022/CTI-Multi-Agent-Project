import sys
from pathlib import Path

# Same project-path pattern as the other agents
sys.path.append(
    str(Path(__file__).resolve().parent.parent)
)

try:
    from rag import retrieve
    KB_AVAILABLE = True
    KB_ERROR = ""
except Exception as error:          # knowledge base not built yet
    KB_AVAILABLE = False
    KB_ERROR = str(error)

    def retrieve(query, n_results=5):
        """Fallback: no knowledge base, so no extra evidence."""
        return []


# ==========================================
# SHARED HELPERS (used by Risk, Mitigation, ...)
# ==========================================

def format_mitre(mitre_result):

    """Turns the MITRE Mapper dict into readable text for an LLM."""

    if not mitre_result:
        return "Not provided."

    if isinstance(mitre_result, str):
        return mitre_result

    mappings = mitre_result.get("mappings", [])

    if not mappings:
        return "No MITRE ATT&CK techniques identified."

    lines = []

    for m in mappings:
        evidence = m.get("evidence") or ", ".join(
            m.get("matched_keywords", [])
        )
        lines.append(
            f"- {m['technique_id']} {m['technique_name']} "
            f"(Tactic: {m['tactic']}, "
            f"Confidence: {m.get('confidence', 'n/a')}) "
            f"Evidence: {evidence}"
        )

    flow = mitre_result.get("attack_flow", [])

    if flow:
        lines.append("Attack flow: " + " -> ".join(flow))

    return "\n".join(lines)


def build_context(results):

    """Formats retrieved chunks with source/page labels."""

    parts = []

    for r in results:
        parts.append(
            f"[Source: {r['source']} | Page: {r['page']}]\n{r['text']}"
        )

    return "\n\n".join(parts)


def gather_evidence(query, retrieved_results, n_results):

    """
    Merges evidence already retrieved by the Retriever Agent
    with a new, agent-specific retrieval, removing duplicates.
    """

    combined = list(retrieved_results or [])

    combined.extend(retrieve(query, n_results=n_results))

    seen = set()
    unique = []

    for r in combined:

        key = (r["source"], r["page"], r["text"][:80])

        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique
