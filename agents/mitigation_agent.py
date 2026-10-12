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

CATEGORIES = [
    "immediate_actions",
    "prevention",
    "detection",
    "recovery"
]

MAX_ITEMS_PER_CATEGORY = 6


# ==========================================
# MITRE ATT&CK MITIGATION KNOWLEDGE (grounding layer)
#
# Hand-curated from the public ATT&CK mitigation catalogue
# for the techniques the MITRE Mapper can output.
# Spot-check IDs against attack.mitre.org before publishing.
# ==========================================

MITIGATION_NAMES = {
    "M1015": "Active Directory Configuration",
    "M1016": "Vulnerability Scanning",
    "M1017": "User Training",
    "M1018": "User Account Management",
    "M1021": "Restrict Web-Based Content",
    "M1022": "Restrict File and Directory Permissions",
    "M1024": "Restrict Registry Permissions",
    "M1025": "Privileged Process Integrity",
    "M1026": "Privileged Account Management",
    "M1027": "Password Policies",
    "M1028": "Operating System Configuration",
    "M1030": "Network Segmentation",
    "M1031": "Network Intrusion Prevention",
    "M1032": "Multi-factor Authentication",
    "M1038": "Execution Prevention",
    "M1040": "Behavior Prevention on Endpoint",
    "M1042": "Disable or Remove Feature or Program",
    "M1043": "Credential Access Protection",
    "M1045": "Code Signing",
    "M1047": "Audit",
    "M1048": "Application Isolation and Sandboxing",
    "M1049": "Antivirus/Antimalware",
    "M1050": "Exploit Protection",
    "M1051": "Update Software",
    "M1053": "Data Backup",
    "M1054": "Software Configuration"
}

_PHISHING = ["M1049", "M1031", "M1021", "M1054", "M1017"]

_PHISHING_DETECT = (
    "Alert on emails carrying macro-enabled or executable "
    "attachments and on Office applications spawning script "
    "interpreters."
)

TECHNIQUE_DEFENSES = {

    "T1566": {"mitigations": _PHISHING,
              "detection": _PHISHING_DETECT},
    "T1566.001": {"mitigations": _PHISHING,
                  "detection": _PHISHING_DETECT},
    "T1566.002": {"mitigations": _PHISHING,
                  "detection": "Inspect and detonate links in email; "
                               "alert on clicks to newly registered or "
                               "rare domains."},

    "T1190": {
        "mitigations": ["M1048", "M1050", "M1030", "M1026",
                        "M1051", "M1016"],
        "detection": "Monitor web and application logs and WAF alerts "
                     "for exploitation attempts and unexpected child "
                     "processes of internet-facing services."
    },

    "T1059": {
        "mitigations": ["M1049", "M1045", "M1042", "M1038", "M1026"],
        "detection": "Log script-interpreter execution with full "
                     "command-line arguments."
    },
    "T1059.001": {
        "mitigations": ["M1049", "M1045", "M1042", "M1038", "M1026",
                        "M1021"],
        "detection": "Enable PowerShell Script Block Logging "
                     "(Event ID 4104) and alert on encoded commands "
                     "or download cradles."
    },
    "T1059.003": {
        "mitigations": ["M1038"],
        "detection": "Monitor cmd.exe command lines, especially when "
                     "spawned by Office applications or browsers."
    },
    "T1059.004": {
        "mitigations": ["M1038"],
        "detection": "Monitor auditd and shell history for unusual "
                     "shell spawns from service accounts."
    },

    "T1053.005": {
        "mitigations": ["M1047", "M1028", "M1026", "M1018"],
        "detection": "Monitor scheduled-task creation (Security Event "
                     "ID 4698) and schtasks.exe usage."
    },

    "T1547.001": {
        "mitigations": ["M1038"],
        "detection": "Monitor changes to Run/RunOnce registry keys "
                     "and the Startup folder."
    },

    "T1078": {
        "mitigations": ["M1032", "M1027", "M1026", "M1018", "M1017"],
        "detection": "Alert on logins from unusual locations or times "
                     "and on use of dormant or privileged accounts."
    },

    "T1027": {
        "mitigations": ["M1049", "M1040"],
        "detection": "Flag high-entropy or encoded scripts and packed "
                     "binaries; scan decoded content with AV/EDR."
    },

    "T1055": {
        "mitigations": ["M1040", "M1026"],
        "detection": "Monitor cross-process memory writes and remote "
                     "thread creation (Sysmon Event IDs 8 and 10)."
    },

    "T1562.001": {
        "mitigations": ["M1022", "M1024", "M1018", "M1038", "M1047"],
        "detection": "Alert on security-tool service stops, Defender "
                     "configuration changes and tamper events."
    },

    "T1003": {
        "mitigations": ["M1026", "M1027", "M1015", "M1040"],
        "detection": "Monitor access to credential stores and use of "
                     "credential-dumping tools."
    },
    "T1003.001": {
        "mitigations": ["M1040", "M1043", "M1025", "M1026"],
        "detection": "Alert on non-system processes opening lsass.exe "
                     "(Sysmon Event ID 10) and on comsvcs.dll MiniDump "
                     "usage."
    },

    "T1082": {
        "mitigations": [],
        "detection": "Monitor bursts of discovery commands (systeminfo, "
                     "net view, dir /s) from one host or account. "
                     "Discovery is hard to prevent, so rely on detection."
    },
    "T1083": {
        "mitigations": [],
        "detection": "Monitor bursts of discovery commands (systeminfo, "
                     "net view, dir /s) from one host or account. "
                     "Discovery is hard to prevent, so rely on detection."
    },
    "T1018": {
        "mitigations": [],
        "detection": "Monitor bursts of discovery commands (systeminfo, "
                     "net view, dir /s) from one host or account. "
                     "Discovery is hard to prevent, so rely on detection."
    },
    "T1046": {
        "mitigations": ["M1031", "M1030", "M1042"],
        "detection": "Detect internal port-scan patterns, such as one "
                     "host contacting many hosts or ports."
    },

    "T1105": {
        "mitigations": ["M1031"],
        "detection": "Monitor file downloads by certutil, bitsadmin, "
                     "curl and PowerShell, and file creation from "
                     "unusual external sources."
    },
    "T1071.001": {
        "mitigations": ["M1031"],
        "detection": "Hunt for beaconing patterns, rare domains and "
                     "unusual user agents in proxy and DNS logs."
    },

    "T1486": {
        "mitigations": ["M1053", "M1040"],
        "detection": "Alert on mass file modification or renaming, new "
                     "file extensions and ransom notes; deploy canary "
                     "files."
    },
    "T1490": {
        "mitigations": ["M1053", "M1028", "M1038", "M1018"],
        "detection": "Alert on vssadmin, wmic and bcdedit commands that "
                     "delete shadow copies or disable recovery."
    }
}

URGENCY_BY_PRIORITY = {
    "P1": "Begin containment immediately (within hours).",
    "P2": "Act within 24 hours.",
    "P3": "Schedule within one week.",
    "P4": "Address in the next maintenance cycle."
}


# ==========================================
# GROUNDING HELPERS
# ==========================================

def get_urgency(risk_result):

    """Maps the Risk Agent's priority (P1..P4) to a time window."""

    if not isinstance(risk_result, dict):
        return "Urgency unknown (no risk assessment available)."

    priority = str(risk_result.get("priority", ""))

    return URGENCY_BY_PRIORITY.get(
        priority[:2],
        "Urgency unknown (no risk assessment available)."
    )


def lookup_technique_defenses(mitre_result):

    """
    Deterministic lookup of ATT&CK mitigations and detection
    hints for every technique the MITRE Mapper found.
    """

    if not isinstance(mitre_result, dict):
        return []

    defenses = []

    for m in mitre_result.get("mappings", []):

        entry = TECHNIQUE_DEFENSES.get(m["technique_id"])

        if not entry:
            continue

        defenses.append({
            "technique_id": m["technique_id"],
            "technique_name": m["technique_name"],
            "tactic": m["tactic"],
            "mitigations": [
                {"id": mid, "name": MITIGATION_NAMES[mid]}
                for mid in entry["mitigations"]
            ],
            "detection": entry["detection"]
        })

    return defenses


def format_defenses(defenses):

    if not defenses:
        return "No ATT&CK mitigation data available."

    lines = []

    for d in defenses:

        names = ", ".join(
            f"{x['id']} {x['name']}" for x in d["mitigations"]
        ) or "none (rely on detection)"

        lines.append(
            f"- {d['technique_id']} {d['technique_name']}: "
            f"mitigations: {names}. Detection: {d['detection']}"
        )

    return "\n".join(lines)


def format_risk(risk_result):

    if not isinstance(risk_result, dict) \
            or risk_result.get("status") == "error":
        return "Not provided."

    return (
        f"Severity: {risk_result.get('severity')} "
        f"({risk_result.get('severity_score')}/10); "
        f"Likelihood: {risk_result.get('likelihood')}; "
        f"Priority: {risk_result.get('priority')}\n"
        f"Business impact: {'; '.join(risk_result.get('business_impact', []))}\n"
        f"Affected assets: {'; '.join(risk_result.get('affected_assets', []))}"
    )


def build_retrieval_query(threat_analysis, mitre_result):

    """Short search query focused on defensive guidance."""

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

    parts.append("mitigation prevention detection recovery recommendations")

    return " ".join(parts)


# ==========================================
# FALLBACK PLAN (no LLM needed)
# ==========================================

def fallback_plan(mitre_result, defenses):

    """
    Rule-based plan used when the LLM is unavailable. Built only
    from the ATT&CK table and the tactics that were observed.
    """

    mappings = (
        mitre_result.get("mappings", [])
        if isinstance(mitre_result, dict) else []
    )

    tactics = {m["tactic"] for m in mappings}
    tids = {m["technique_id"] for m in mappings}

    immediate = [{
        "action": "Isolate affected hosts from the network and "
                  "preserve forensic evidence.",
        "rationale": "Standard containment for any confirmed intrusion.",
        "technique_ids": []
    }]

    recovery = [{
        "action": "Rebuild or restore affected systems from known-good "
                  "images after eradication.",
        "rationale": "Ensures no attacker persistence remains.",
        "technique_ids": []
    }]

    if "Credential Access" in tactics or "T1078" in tids:
        immediate.append({
            "action": "Reset credentials for affected and privileged "
                      "accounts and revoke active sessions.",
            "rationale": "Credential theft or misuse was observed.",
            "technique_ids": sorted(
                tids & {"T1003", "T1003.001", "T1078"}
            )
        })

    if tids & {"T1105", "T1071.001"}:
        immediate.append({
            "action": "Block identified malicious IPs and domains at "
                      "the firewall and proxy.",
            "rationale": "Command-and-control or tool download observed.",
            "technique_ids": sorted(tids & {"T1105", "T1071.001"})
        })

    if "Impact" in tactics:
        recovery.insert(0, {
            "action": "Verify backup integrity and restore data from "
                      "offline or immutable backups after containment.",
            "rationale": "Destructive or encrypting impact observed.",
            "technique_ids": sorted(tids & {"T1486", "T1490"})
        })

    prevention = []
    detection = []

    for d in defenses:

        if d["mitigations"]:
            names = ", ".join(
                f"{x['name']} ({x['id']})" for x in d["mitigations"][:3]
            )
            prevention.append({
                "action": f"Apply: {names}.",
                "rationale": f"ATT&CK mitigations for {d['technique_name']}.",
                "technique_ids": [d["technique_id"]]
            })

        detection.append({
            "action": d["detection"],
            "rationale": f"Detection guidance for {d['technique_name']}.",
            "technique_ids": [d["technique_id"]]
        })

    return {
        "immediate_actions": immediate,
        "prevention": prevention,
        "detection": detection,
        "recovery": recovery,
        "evidence_used": [],
        "assumptions": [
            "Rule-based plan: the LLM was unavailable, so recommendations "
            "come only from the ATT&CK mitigation table."
        ]
    }


# ==========================================
# LLM MITIGATION ANALYSIS
# ==========================================

def groq_mitigation_analysis(query, threat_analysis, mitre_text,
                             risk_text, defenses_text, context,
                             urgency):

    system_prompt = f"""
You are the Mitigation Agent of a multi-agent cyber threat
intelligence system.

Recommend defensive measures for the threat described by the
other agents. You DO NOT re-analyze the threat and you DO NOT
re-score the risk.

STRICT RULES:

1. Every recommendation must be specific, actionable and tied to
   the observed behavior - no generic advice such as "be careful".
2. Prefer the ATT&CK mitigations and detection guidance supplied
   below, and adapt them to this incident.
3. Do NOT invent product names, CVE numbers, IP addresses or
   domains that are not in the provided context.
4. Cite evidence ONLY using a source and page that appear in the
   Retrieved Evidence. NEVER invent a citation.
5. Anything not directly supported by the evidence belongs in
   "assumptions".
6. In "technique_ids", list only technique IDs from the MITRE
   mapping provided.
7. Maximum {MAX_ITEMS_PER_CATEGORY} items per category.
8. The response urgency is: {urgency}
   Order immediate_actions by what must happen first.
9. Return ONLY valid JSON.

Categories:
- immediate_actions: containment and eradication steps
- prevention: hardening to stop recurrence
- detection: monitoring and alerting to catch this behavior
- recovery: restoring operations safely
"""

    user_prompt = f"""
USER QUERY:
{query}

THREAT ANALYSIS:
{threat_analysis}

MITRE ATT&CK MAPPING:
{mitre_text}

RISK ASSESSMENT:
{risk_text}

ATT&CK MITIGATION AND DETECTION REFERENCE:
{defenses_text}

RETRIEVED EVIDENCE:
{context if context else "No evidence retrieved."}

Return exactly this JSON:

{{
    "immediate_actions": [
        {{"action": "<step>", "rationale": "<why>", "technique_ids": ["T1486"]}}
    ],
    "prevention": [
        {{"action": "<step>", "rationale": "<why>", "technique_ids": []}}
    ],
    "detection": [
        {{"action": "<step>", "rationale": "<why>", "technique_ids": []}}
    ],
    "recovery": [
        {{"action": "<step>", "rationale": "<why>", "technique_ids": []}}
    ],
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
# VALIDATION
# ==========================================

def clean_actions(items, valid_tids):

    cleaned = []
    seen = set()

    for item in items if isinstance(items, list) else []:

        if isinstance(item, str):
            item = {"action": item}

        if not isinstance(item, dict):
            continue

        action = str(item.get("action", "")).strip()

        if not action or action.lower() in seen:
            continue

        seen.add(action.lower())

        tids = [
            t for t in item.get("technique_ids", [])
            if t in valid_tids
        ]

        cleaned.append({
            "action": action,
            "rationale": str(item.get("rationale", "")).strip(),
            "technique_ids": tids
        })

        if len(cleaned) == MAX_ITEMS_PER_CATEGORY:
            break

    return cleaned


def validate_output(raw, evidence, valid_tids):

    result = {}

    for category in CATEGORIES:
        result[category] = clean_actions(
            raw.get(category, []), valid_tids
        )

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

    result["evidence_used"] = evidence_used
    result["assumptions"] = [
        str(a) for a in raw.get("assumptions", [])
    ]

    return result


# ==========================================
# MITIGATION AGENT
# ==========================================

def mitigation_agent(query, threat_analysis, mitre_result=None,
                     risk_result=None, retrieved_results=None,
                     n_results=3):

    """
    Mitigation Agent.

    INPUT:
        query              : original user question / report text
        threat_analysis    : string from threat_analyzer_agent()
        mitre_result       : dict from mitre_mapper_agent()
        risk_result        : dict from risk_agent()
        retrieved_results  : list from retriever_agent()

    OUTPUT:
        Structured dict with immediate_actions, prevention,
        detection, recovery, the ATT&CK mitigation table, urgency,
        evidence and assumptions - for the Report Generator.
    """

    print("\n==========================================")
    print("MITIGATION AGENT")
    print("==========================================")

    # ---- STEP 1: evidence ----
    print("\n[1/4] Gathering evidence...")

    search_query = build_retrieval_query(threat_analysis, mitre_result)

    evidence = gather_evidence(search_query, retrieved_results, n_results)

    print(f"Evidence chunks: {len(evidence)}")

    # ---- STEP 2: deterministic ATT&CK grounding ----
    print("\n[2/4] Looking up ATT&CK mitigations...")

    defenses = lookup_technique_defenses(mitre_result)

    valid_tids = {d["technique_id"] for d in defenses}

    urgency = get_urgency(risk_result)

    print(f"Techniques with defense data: {len(defenses)}")
    print("Urgency:", urgency)

    # ---- STEP 3: LLM analysis ----
    print("\n[3/4] Running Groq mitigation analysis...")

    try:
        raw = groq_mitigation_analysis(
            query,
            threat_analysis,
            format_mitre(mitre_result),
            format_risk(risk_result),
            format_defenses(defenses),
            build_context(evidence),
            urgency
        )
        status = "success"

    except Exception as error:
        print("\nGroq API error:", error)
        raw = {}
        status = "fallback"

    # ---- STEP 4: validate ----
    print("\n[4/4] Validating output...")

    if not raw and not defenses:

        return {
            "agent": "Mitigation",
            "status": "error",
            "summary": "No MITRE techniques and the LLM call failed; "
                       "cannot recommend mitigations."
        }

    result = validate_output(raw, evidence, valid_tids) if raw else None

    # LLM answered but produced nothing usable -> rule-based plan
    if not result or not any(result[c] for c in CATEGORIES):

        if raw:
            print("LLM returned no usable recommendations; using fallback.")

        result = fallback_plan(mitre_result, defenses)
        status = "fallback"

    result["agent"] = "Mitigation"
    result["status"] = status
    result["urgency"] = urgency
    result["attack_mitigations"] = defenses
    result["summary"] = (
        f"{len(result['immediate_actions'])} immediate, "
        f"{len(result['prevention'])} prevention, "
        f"{len(result['detection'])} detection, "
        f"{len(result['recovery'])} recovery actions. {urgency}"
    )

    # ---- display ----
    print("\n==========================================")
    print("MITIGATION PLAN")
    print("==========================================")

    print("Urgency:", urgency)

    titles = {
        "immediate_actions": "Immediate actions",
        "prevention": "Prevention",
        "detection": "Detection",
        "recovery": "Recovery"
    }

    for category in CATEGORIES:

        print(f"\n{titles[category]}:")

        for item in result[category]:

            tag = (
                f" [{', '.join(item['technique_ids'])}]"
                if item["technique_ids"] else ""
            )

            print(f" - {item['action']}{tag}")

    if result["evidence_used"]:
        print("\nEvidence:")
        for e in result["evidence_used"]:
            print(f" - {e['source']} p.{e['page']}: {e.get('supports', '')}")

    if result["assumptions"]:
        print("\nAssumptions:")
        for a in result["assumptions"]:
            print(" -", a)

    return result


# ==========================================
# TEST: FULL CHAIN
# ==========================================

if __name__ == "__main__":

    from retriever import retriever_agent
    from threat_analyzer import threat_analyzer_agent
    from mitre_mapper import mitre_mapper_agent
    from risk_agent import risk_agent

    question = input("\nAsk a cybersecurity question: ")

    retrieved = retriever_agent(question)

    analysis = threat_analyzer_agent(question, retrieved)

    mitre = mitre_mapper_agent(retrieved)

    risk = risk_agent(question, analysis, mitre, retrieved)

    mitigation = mitigation_agent(
        question, analysis, mitre, risk, retrieved
    )

    print("\n==========================================")
    print("MITIGATION AGENT COMPLETE")
    print("==========================================")