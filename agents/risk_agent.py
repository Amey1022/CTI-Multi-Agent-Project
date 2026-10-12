import json
import os
import re

from dotenv import load_dotenv
from groq import Groq

from common import format_mitre, build_context, gather_evidence


# ==========================================
# CONFIGURATION
# ==========================================

load_dotenv()

GROQ_MODEL = "openai/gpt-oss-120b"

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise RuntimeError(
        "GROQ_API_KEY is not set. "
        "Please configure your Groq API key."
    )

llm_client = Groq(
    api_key=api_key
)

VALID_LIKELIHOODS = [
    "Very Likely",
    "Likely",
    "Possible",
    "Unlikely"
]

# The LLM may move the score at most this far from the
# rule-based baseline computed from the MITRE mapping.
MAX_LLM_DEVIATION = 2.0


# ==========================================
# SCORING HELPERS (deterministic grounding layer)
# ==========================================

def score_to_rating(score):

    """CVSS-style severity bands."""

    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


PRIORITY_BY_RATING = {
    "Critical": "P1 - Immediate",
    "High": "P2 - High",
    "Medium": "P3 - Medium",
    "Low": "P4 - Low"
}


def compute_baseline(mitre_result):

    """
    Rule-based baseline score derived from the MITRE Mapper
    output. Returns (score, reasons) or (None, []) when there
    is no MITRE data to ground on.
    """

    if not isinstance(mitre_result, dict):
        return None, []

    mappings = mitre_result.get("mappings", [])

    if not mappings:
        return None, []

    tactics = {m["tactic"] for m in mappings}
    technique_ids = {m["technique_id"] for m in mappings}

    score = 3.0
    reasons = ["base score 3.0"]

    breadth = min(len(tactics) * 0.5, 3.0)
    score += breadth
    reasons.append(
        f"+{breadth} for {len(tactics)} ATT&CK tactics covered"
    )

    if "Impact" in tactics:
        score += 2.0
        reasons.append("+2.0 Impact tactic present (data/system damage)")

    if technique_ids & {"T1486", "T1490"}:
        score += 0.5
        reasons.append("+0.5 ransomware-style impact technique")

    if "Credential Access" in tactics:
        score += 1.0
        reasons.append("+1.0 credential theft observed")

    if "Defense Evasion" in tactics:
        score += 0.5
        reasons.append("+0.5 defense evasion observed")

    if "T1190" in technique_ids:
        score += 0.5
        reasons.append("+0.5 internet-facing application exploited")

    return min(round(score, 1), 10.0), reasons


# ==========================================
# FORMATTING HELPERS
# ==========================================

def build_retrieval_query(threat_analysis, mitre_result):

    """
    Short, focused search query. (Long queries dilute the
    MiniLM embedding, so we use threat type + malware +
    technique names rather than the whole analysis.)
    """

    parts = []

    text = str(threat_analysis)

    for field in ("Threat Type", "Malware"):

        match = re.search(
            rf"{field}:\s*\n?\s*(.+)",
            text,
            re.IGNORECASE
        )

        if match and "not found" not in match.group(1).lower():
            parts.append(match.group(1).strip())

    if isinstance(mitre_result, dict):
        for m in mitre_result.get("mappings", [])[:3]:
            parts.append(m["technique_name"])

    parts.append("impact severity affected systems consequences")

    return " ".join(parts)


# ==========================================
# LLM RISK ANALYSIS
# ==========================================

def groq_risk_analysis(query, threat_analysis, mitre_text,
                       context, baseline, baseline_reasons):

    baseline_text = (
        f"{baseline} / 10  ({'; '.join(baseline_reasons)})"
        if baseline is not None
        else "Not available (no MITRE data)."
    )

    system_prompt = f"""
You are the Risk Assessment Agent of a multi-agent
cyber threat intelligence system.

Estimate the severity, likelihood and business impact
of the threat described by the other agents.

You DO NOT re-analyze the raw report and you DO NOT
write mitigations - other agents do that.

STRICT RULES:

1. Base every judgement on the Threat Analysis, the MITRE
   mapping and the Retrieved Evidence below.
2. Cite evidence ONLY using a source and page that appear
   in the Retrieved Evidence. NEVER invent a citation.
3. If a judgement is not directly supported by the evidence,
   list it under "assumptions" instead of presenting it as fact.
4. A rule-based baseline score is provided. You may adjust
   it by at most {MAX_LLM_DEVIATION} points and must explain
   any adjustment in the justification.
5. severity_score is a number from 0.0 to 10.0 (CVSS-style).
6. likelihood must be one of: {", ".join(VALID_LIKELIHOODS)}.
7. Return ONLY valid JSON.
"""

    user_prompt = f"""
USER QUERY:
{query}

THREAT ANALYSIS:
{threat_analysis}

MITRE ATT&CK MAPPING:
{mitre_text}

RULE-BASED BASELINE SCORE:
{baseline_text}

RETRIEVED EVIDENCE:
{context if context else "No evidence retrieved."}

Return exactly this JSON:

{{
    "severity_score": 7.5,
    "likelihood": "Likely",
    "business_impact": ["<impact>", "<impact>"],
    "affected_assets": ["<asset>", "<asset>"],
    "justification": "<2-4 sentences tying severity, likelihood and impact together>",
    "evidence_used": [
        {{"source": "<file name>", "page": 1, "supports": "<what it supports>"}}
    ],
    "assumptions": ["<anything not backed by evidence>"]
}}
"""

    response = llm_client.chat.completions.create(

        model=GROQ_MODEL,

        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],

        temperature=0,

        response_format={"type": "json_object"}
    )

    content = response.choices[0].message.content

    if not content:
        return {}

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        print("Warning: Groq returned invalid JSON.")
        return {}


# ==========================================
# VALIDATION (reject anything the LLM made up)
# ==========================================

def validate_output(raw, evidence, baseline):

    notes = []

    # ---- score ----
    try:
        score = float(raw.get("severity_score"))
    except (TypeError, ValueError):
        score = baseline if baseline is not None else 5.0
        notes.append("LLM score missing/invalid; used fallback score.")

    score = max(0.0, min(score, 10.0))

    if baseline is not None:

        low = baseline - MAX_LLM_DEVIATION
        high = baseline + MAX_LLM_DEVIATION

        if score < low or score > high:
            clamped = max(low, min(score, high))
            notes.append(
                f"LLM score {score} was outside +/-{MAX_LLM_DEVIATION} "
                f"of the baseline {baseline}; clamped to {round(clamped, 1)}."
            )
            score = clamped

    score = round(max(0.0, min(score, 10.0)), 1)

    # ---- likelihood ----
    likelihood = raw.get("likelihood")

    if likelihood not in VALID_LIKELIHOODS:
        likelihood = "Possible"
        notes.append("LLM likelihood invalid; defaulted to 'Possible'.")

    # ---- evidence: only real source/page pairs survive ----
    allowed = {(r["source"], r["page"]) for r in evidence}

    evidence_used = []

    for item in raw.get("evidence_used", []):

        if not isinstance(item, dict):
            continue

        key = (item.get("source"), item.get("page"))

        if key in allowed:
            evidence_used.append(item)
        else:
            print(f"Rejected unknown citation: {key}")

    rating = score_to_rating(score)

    return {
        "severity_score": score,
        "severity": rating,
        "likelihood": likelihood,
        "priority": PRIORITY_BY_RATING[rating],
        "business_impact": list(raw.get("business_impact", [])),
        "affected_assets": list(raw.get("affected_assets", [])),
        "justification": raw.get("justification", ""),
        "evidence_used": evidence_used,
        "assumptions": list(raw.get("assumptions", [])),
        "validation_notes": notes
    }


# ==========================================
# RISK AGENT
# ==========================================

def risk_agent(query, threat_analysis, mitre_result=None,
               retrieved_results=None, n_results=3):

    """
    Risk Assessment Agent.

    INPUT:
        query              : original user question / report text
        threat_analysis    : string from threat_analyzer_agent()
        mitre_result       : dict from mitre_mapper_agent()
        retrieved_results  : list from retriever_agent()
                             (a risk-focused retrieval is added)

    OUTPUT:
        Structured dict (severity, score, likelihood, priority,
        business impact, affected assets, justification,
        evidence, assumptions) for the Mitigation Agent,
        Report Generator and dashboard.
    """

    print("\n==========================================")
    print("RISK AGENT")
    print("==========================================")

    # ---- STEP 1: evidence ----
    print("\n[1/4] Gathering evidence...")

    search_query = build_retrieval_query(threat_analysis, mitre_result)

    evidence = gather_evidence(search_query, retrieved_results, n_results)

    print(f"Evidence chunks: {len(evidence)}")

    # ---- STEP 2: deterministic baseline ----
    print("\n[2/4] Computing rule-based baseline...")

    baseline, reasons = compute_baseline(mitre_result)

    print("Baseline:", baseline if baseline is not None else "n/a")

    # ---- STEP 3: LLM analysis ----
    print("\n[3/4] Running Groq risk analysis...")

    try:
        raw = groq_risk_analysis(
            query,
            threat_analysis,
            format_mitre(mitre_result),
            build_context(evidence),
            baseline,
            reasons
        )
        status = "success"

    except Exception as error:
        print("\nGroq API error:", error)
        raw = {}
        status = "fallback"

    # ---- STEP 4: validate ----
    print("\n[4/4] Validating output...")

    if not raw and baseline is None:

        return {
            "agent": "Risk Assessment",
            "status": "error",
            "summary": "No MITRE data and the LLM call failed; "
                       "cannot estimate risk."
        }

    if not raw:
        raw = {
            "severity_score": baseline,
            "likelihood": "Possible",
            "justification": "LLM unavailable; score is the rule-based "
                             "baseline from the MITRE mapping: "
                             + "; ".join(reasons)
        }

    result = validate_output(raw, evidence, baseline)

    result["agent"] = "Risk Assessment"
    result["status"] = status
    result["baseline_score"] = baseline
    result["baseline_reasons"] = reasons
    result["summary"] = (
        f"{result['severity']} ({result['severity_score']}/10), "
        f"likelihood {result['likelihood']}, {result['priority']}"
    )

    # ---- display ----
    print("\n==========================================")
    print("RISK ASSESSMENT")
    print("==========================================")

    print("Severity:  ", result["severity"], f"({result['severity_score']}/10)")
    print("Likelihood:", result["likelihood"])
    print("Priority:  ", result["priority"])

    print("\nBusiness impact:")
    for item in result["business_impact"]:
        print(" -", item)

    print("\nAffected assets:")
    for item in result["affected_assets"]:
        print(" -", item)

    print("\nJustification:\n", result["justification"])

    if result["evidence_used"]:
        print("\nEvidence:")
        for e in result["evidence_used"]:
            print(f" - {e['source']} p.{e['page']}: {e.get('supports', '')}")

    if result["assumptions"]:
        print("\nAssumptions:")
        for a in result["assumptions"]:
            print(" -", a)

    if result["validation_notes"]:
        print("\nValidation notes:")
        for n in result["validation_notes"]:
            print(" -", n)

    return result


# ==========================================
# TEST: FULL CHAIN  Retriever -> Threat Analyzer -> MITRE -> Risk
# ==========================================

if __name__ == "__main__":

    from retriever import retriever_agent
    from threat_analyzer import threat_analyzer_agent
    from mitre_mapper import mitre_mapper_agent

    question = input("\nAsk a cybersecurity question: ")

    retrieved = retriever_agent(question)

    analysis = threat_analyzer_agent(question, retrieved)

    mitre = mitre_mapper_agent(retrieved)

    risk = risk_agent(question, analysis, mitre, retrieved)

    print("\n==========================================")
    print("RISK AGENT COMPLETE")
    print("==========================================")