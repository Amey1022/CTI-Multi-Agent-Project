import html
import os
import re
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from dotenv import load_dotenv
from groq import Groq


# ==========================================
# CONFIGURATION
# ==========================================

load_dotenv()

GROQ_MODEL = "openai/gpt-oss-20b"

api_key = os.getenv("GROQ_API_KEY")

# The LLM only writes the executive summary, and a rule-based
# summary exists, so a missing key is a warning, not an error.
llm_client = Groq(api_key=api_key) if api_key else None

THREAT_HEADINGS = [
    "Threat Type",
    "Malware",
    "Attack Summary",
    "IOCs",
    "Affected Systems"
]

NOT_AVAILABLE = "Not available (the agent did not run or failed)."


# ==========================================
# PARSING HELPERS
# ==========================================

def parse_threat_analysis(text):

    """Splits the Threat Analyzer's text into its five sections."""

    sections = {h: "" for h in THREAT_HEADINGS}

    if not text:
        return sections

    pattern = re.compile(
        r"(?im)^\s*[*#]*\s*("
        + "|".join(THREAT_HEADINGS)
        + r")\s*[*]*\s*:\s*[*]*"
    )

    matches = list(pattern.finditer(text))

    for i, match in enumerate(matches):

        end = (
            matches[i + 1].start()
            if i + 1 < len(matches) else len(text)
        )

        heading = next(
            h for h in THREAT_HEADINGS
            if h.lower() == match.group(1).lower()
        )

        sections[heading] = text[match.end():end].strip()

    return sections


def to_list(text):

    items = []

    for line in str(text).splitlines():

        line = re.sub(r"^\s*[-*\u2022]+\s*", "", line).strip()

        if line:
            items.append(line)

    return items


def ok(result):

    """True when an agent result exists and did not fail."""

    return isinstance(result, dict) and result.get("status") != "error"


def format_actions(items):

    lines = []

    for item in items:

        line = item["action"]

        if item.get("rationale"):
            line += f" - {item['rationale']}"

        if item.get("technique_ids"):
            line += f" ({', '.join(item['technique_ids'])})"

        lines.append(line)

    return lines


# ==========================================
# EXECUTIVE SUMMARY
# ==========================================

def collect_facts(threat_sections, mitre_result, risk_result,
                  mitigation_result, extracted=None):

    facts = []

    if threat_sections["Threat Type"]:
        facts.append(f"Threat type: {threat_sections['Threat Type']}")

    if threat_sections["Malware"]:
        facts.append(f"Malware: {threat_sections['Malware']}")

    if threat_sections["Attack Summary"]:
        facts.append(f"Attack summary: {threat_sections['Attack Summary']}")

    if extracted and extracted.get("cves"):
        facts.append("CVEs referenced: " + ", ".join(extracted["cves"]))

    if ok(mitre_result) and mitre_result.get("mappings"):
        facts.append(
            "MITRE techniques: " + ", ".join(
                f"{m['technique_id']} {m['technique_name']}"
                for m in mitre_result["mappings"]
            )
        )

    if ok(risk_result):
        facts.append(
            f"Risk: {risk_result['severity']} "
            f"({risk_result['severity_score']}/10), "
            f"likelihood {risk_result['likelihood']}, "
            f"priority {risk_result['priority']}"
        )
        if risk_result.get("business_impact"):
            facts.append(
                "Business impact: "
                + "; ".join(risk_result["business_impact"])
            )

    if ok(mitigation_result):
        facts.append(f"Response urgency: {mitigation_result['urgency']}")
        top = format_actions(
            mitigation_result["immediate_actions"][:3]
        )
        if top:
            facts.append("Top immediate actions: " + "; ".join(top))

    return facts


def rule_based_summary(facts):

    if not facts:
        return ("No agent produced enough information to summarize "
                "this analysis.")

    return " ".join(
        fact if fact.endswith(".") else fact + "."
        for fact in facts
    )


def executive_summary(facts):

    if not facts or llm_client is None:
        return rule_based_summary(facts)

    prompt = (
        "Write an executive summary of 4 to 6 sentences for a "
        "non-technical manager, using ONLY the facts below. Do not "
        "add facts, numbers, names or recommendations that are not "
        "listed. Plain text only - no markdown, no bullet points.\n\n"
        "FACTS:\n" + "\n".join(f"- {f}" for f in facts)
    )

    try:

        response = llm_client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )

        text = (response.choices[0].message.content or "").strip()

        return text or rule_based_summary(facts)

    except Exception as error:
        print("Groq API error (executive summary):", error)
        return rule_based_summary(facts)


# ==========================================
# REPORT STRUCTURE
#
# The report is built once as a list of neutral blocks and then
# rendered to Markdown, HTML and PDF:
#   ("h1", text)  ("h2", text)  ("h3", text)  ("p", text)
#   ("ul", [str]) ("kv", [(key, value)])
#   ("table", [headers], [rows])  ("pre", text)  ("note", text)
# ==========================================

def extracted_blocks(extracted):

    """Indicators found by pattern matching in the source document."""

    if not extracted:
        return []

    groups = [
        ("IP addresses", extracted.get("ips", [])),
        ("Domains", extracted.get("domains", [])),
        ("URLs", extracted.get("urls", [])),
        ("Email addresses", extracted.get("emails", [])),
        ("MD5", extracted.get("hashes", {}).get("md5", [])),
        ("SHA-1", extracted.get("hashes", {}).get("sha1", [])),
        ("SHA-256", extracted.get("hashes", {}).get("sha256", [])),
        ("Files mentioned", extracted.get("files", [])),
    ]

    lines = [f"{label}: {', '.join(values)}"
             for label, values in groups if values]

    blocks = []

    if lines:
        blocks.append(("h3", "Indicators extracted from the document"))
        blocks.append(("ul", lines))
        blocks.append(("note",
            "Found by pattern matching, so each one appears in the source "
            "text. Reference sites and internal addresses are excluded."))

    if extracted.get("cves"):
        blocks.append(("h3", "CVEs referenced"))
        blocks.append(("ul", extracted["cves"]))

    return blocks


def build_blocks(query, plan, threat_analysis, mitre_result,
                 risk_result, mitigation_result, retrieved_results,
                 summary, extracted=None, verification=None,
                 document_info=None):

    sections = parse_threat_analysis(threat_analysis)

    blocks = []

    # ---- header ----
    blocks.append(("h1", "Cyber Threat Intelligence Report"))

    header = [
        ("Generated", datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Subject", query)
    ]

    if document_info:
        header.insert(1, ("Source document",
            f"{document_info.get('filename')} "
            f"({document_info.get('pages')} pages)"))

    if ok(risk_result):
        header.append(("Overall risk", risk_result["summary"]))

    blocks.append(("kv", header))

    # ---- 1. executive summary ----
    blocks.append(("h2", "1. Executive Summary"))
    blocks.append(("p", summary))

    # ---- 2. threat overview ----
    blocks.append(("h2", "2. Threat Overview"))

    if any(sections.values()):

        blocks.append(("kv", [
            ("Threat type", sections["Threat Type"] or "Not identified"),
            ("Malware", sections["Malware"] or "Not identified")
        ]))

        if sections["Attack Summary"]:
            blocks.append(("h3", "Attack summary"))
            blocks.append(("p", sections["Attack Summary"]))

        if sections["IOCs"]:
            unverified = {v.lower() for v in
                          (verification or {}).get("unverified", [])}
            iocs = [
                item + " [not found in the source document]"
                if any(u in item.lower() for u in unverified) else item
                for item in to_list(sections["IOCs"])
            ]
            blocks.append(("h3", "Indicators of compromise"))
            blocks.append(("ul", iocs))

        if sections["Affected Systems"]:
            blocks.append(("h3", "Affected systems"))
            blocks.append(("ul", to_list(sections["Affected Systems"])))

    elif threat_analysis:
        blocks.append(("p", str(threat_analysis)))

    else:
        blocks.append(("note", NOT_AVAILABLE))

    blocks.extend(extracted_blocks(extracted))

    # ---- 3. MITRE ----
    blocks.append(("h2", "3. MITRE ATT&CK Mapping"))

    if ok(mitre_result) and mitre_result.get("mappings"):

        flow = mitre_result.get("attack_flow", [])

        if flow:
            blocks.append(("p", "Attack flow: " + " -> ".join(flow)))

        blocks.append(("table",
            ["ID", "Technique", "Tactic", "Confidence"],
            [[m["technique_id"], m["technique_name"], m["tactic"],
              str(m.get("confidence", ""))]
             for m in mitre_result["mappings"]]
        ))

    elif ok(mitre_result):
        blocks.append(("note",
            "No MITRE ATT&CK techniques were identified."))

    else:
        blocks.append(("note", NOT_AVAILABLE))

    # ---- 4. risk ----
    blocks.append(("h2", "4. Risk Assessment"))

    if ok(risk_result):

        blocks.append(("kv", [
            ("Severity",
             f"{risk_result['severity']} "
             f"({risk_result['severity_score']}/10)"),
            ("Likelihood", risk_result["likelihood"]),
            ("Priority", risk_result["priority"])
        ]))

        if risk_result.get("business_impact"):
            blocks.append(("h3", "Business impact"))
            blocks.append(("ul", risk_result["business_impact"]))

        if risk_result.get("affected_assets"):
            blocks.append(("h3", "Affected assets"))
            blocks.append(("ul", risk_result["affected_assets"]))

        if risk_result.get("justification"):
            blocks.append(("h3", "Justification"))
            blocks.append(("p", risk_result["justification"]))

    else:
        blocks.append(("note", NOT_AVAILABLE))

    # ---- 5. mitigation ----
    blocks.append(("h2", "5. Mitigation Plan"))

    if ok(mitigation_result):

        blocks.append(("kv", [("Response urgency",
                               mitigation_result["urgency"])]))

        titles = [
            ("immediate_actions", "Immediate actions"),
            ("prevention", "Prevention"),
            ("detection", "Detection"),
            ("recovery", "Recovery")
        ]

        for key, title in titles:

            items = format_actions(mitigation_result.get(key, []))

            if items:
                blocks.append(("h3", title))
                blocks.append(("ul", items))

        attack = mitigation_result.get("attack_mitigations", [])

        if attack:

            blocks.append(("h3", "ATT&CK mitigation reference"))

            blocks.append(("table",
                ["Technique", "ATT&CK mitigations", "Detection guidance"],
                [[f"{d['technique_id']} {d['technique_name']}",
                  ", ".join(f"{x['id']} {x['name']}"
                            for x in d["mitigations"]) or "None",
                  d["detection"]]
                 for d in attack]
            ))

    else:
        blocks.append(("note", NOT_AVAILABLE))

    # ---- 6. evidence ----
    blocks.append(("h2", "6. Evidence and Sources"))

    cited = []
    cited_keys = set()

    for result in (risk_result, mitigation_result):

        if not ok(result):
            continue

        for e in result.get("evidence_used", []):

            key = (e["source"], e["page"])

            if key not in cited_keys:
                cited_keys.add(key)
                cited.append(
                    f"{e['source']}, page {e['page']}"
                    + (f" - {e['supports']}" if e.get("supports") else "")
                )

    if cited:
        blocks.append(("h3", "Cited by the agents"))
        blocks.append(("ul", cited))

    others = []
    seen = set(cited_keys)

    for r in retrieved_results or []:

        key = (r["source"], r["page"])

        if key not in seen:
            seen.add(key)
            others.append(f"{r['source']}, page {r['page']}")

    if others:
        blocks.append(("h3", "Other retrieved passages"))
        blocks.append(("ul", others))

    if not cited and not others:
        blocks.append(("note", "No knowledge-base evidence was used."))

    # ---- 7. limitations ----
    blocks.append(("h2", "7. Limitations and Assumptions"))

    limits = []

    for result in (risk_result, mitigation_result):

        if ok(result):
            limits.extend(result.get("assumptions", []))
            limits.extend(result.get("validation_notes", []))

    for name, result in (("MITRE Mapper", mitre_result),
                         ("Risk", risk_result),
                         ("Mitigation", mitigation_result)):

        if isinstance(result, dict) and result.get("status") == "fallback":
            limits.append(
                f"The {name} agent used its rule-based fallback because "
                f"the LLM was unavailable."
            )

    for warning in (document_info or {}).get("warnings", []):
        limits.append(warning)

    if verification and verification.get("unverified"):
        limits.append(
            "The Threat Analyzer listed indicators that were not found in "
            "the source document and should be treated as unverified: "
            + ", ".join(verification["unverified"]) + "."
        )

    limits.append(
        "This report was generated automatically. Findings should be "
        "reviewed by a security analyst before action is taken."
    )

    blocks.append(("ul", limits))

    # ---- appendices ----
    if plan:
        blocks.append(("h2", "Appendix A: Analysis Plan"))
        blocks.append(("pre", str(plan)))

    blocks.append(("h2", "Appendix B: Agent Execution Status"))

    blocks.append(("table", ["Agent", "Status"], [
        ["MITRE Mapper",
         mitre_result.get("status", "n/a")
         if isinstance(mitre_result, dict) else "not run"],
        ["Risk Assessment",
         risk_result.get("status", "n/a")
         if isinstance(risk_result, dict) else "not run"],
        ["Mitigation",
         mitigation_result.get("status", "n/a")
         if isinstance(mitigation_result, dict) else "not run"]
    ]))

    return blocks


# ==========================================
# RENDERERS
# ==========================================

def md_cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(blocks):

    out = []

    for block in blocks:

        kind = block[0]

        if kind == "h1":
            out.append(f"# {block[1]}\n")

        elif kind == "h2":
            out.append(f"\n## {block[1]}\n")

        elif kind == "h3":
            out.append(f"\n### {block[1]}\n")

        elif kind == "p":
            out.append(f"{block[1]}\n")

        elif kind == "note":
            out.append(f"> {block[1]}\n")

        elif kind == "ul":
            out.extend(f"- {item}" for item in block[1])
            out.append("")

        elif kind == "kv":
            out.extend(f"- **{k}:** {v}" for k, v in block[1])
            out.append("")

        elif kind == "table":
            out.append("| " + " | ".join(block[1]) + " |")
            out.append("|" + "---|" * len(block[1]))
            out.extend(
                "| " + " | ".join(md_cell(c) for c in row) + " |"
                for row in block[2]
            )
            out.append("")

        elif kind == "pre":
            out.append("```\n" + block[1] + "\n```\n")

    return "\n".join(out)


HTML_STYLE = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:900px;
margin:2rem auto;padding:0 1rem;color:#1f2933;line-height:1.5}
h1{border-bottom:3px solid #1f4e79;padding-bottom:.3rem;color:#1f4e79}
h2{color:#1f4e79;margin-top:2rem;border-bottom:1px solid #d0d7de}
h3{margin-bottom:.2rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;
vertical-align:top}
th{background:#eef3f8}
pre{background:#f6f8fa;padding:1rem;overflow-x:auto;font-size:.85rem}
.note{color:#6b7280;font-style:italic}
"""


def render_html(blocks):

    e = html.escape

    out = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Cyber Threat Intelligence Report</title>",
        f"<style>{HTML_STYLE}</style></head><body>"
    ]

    for block in blocks:

        kind = block[0]

        if kind in ("h1", "h2", "h3"):
            out.append(f"<{kind}>{e(block[1])}</{kind}>")

        elif kind == "p":
            out.append(f"<p>{e(block[1])}</p>")

        elif kind == "note":
            out.append(f"<p class='note'>{e(block[1])}</p>")

        elif kind == "ul":
            out.append("<ul>" + "".join(
                f"<li>{e(item)}</li>" for item in block[1]
            ) + "</ul>")

        elif kind == "kv":
            out.append("<ul>" + "".join(
                f"<li><strong>{e(k)}:</strong> {e(str(v))}</li>"
                for k, v in block[1]
            ) + "</ul>")

        elif kind == "table":
            head = "".join(f"<th>{e(h)}</th>" for h in block[1])
            rows = "".join(
                "<tr>" + "".join(
                    f"<td>{e(str(c))}</td>" for c in row
                ) + "</tr>"
                for row in block[2]
            )
            out.append(
                f"<table><tr>{head}</tr>{rows}</table>"
            )

        elif kind == "pre":
            out.append(f"<pre>{e(block[1])}</pre>")

    out.append("</body></html>")

    return "\n".join(out)


def pdf_safe(text):

    """ReportLab's built-in fonts only cover Windows-1252."""

    text = (str(text)
            .replace("\u2192", "->")
            .replace("\u2011", "-")
            .replace("\u2265", ">=")
            .replace("\u2264", "<=")
            .replace("\u00a0", " "))

    return text.encode("cp1252", "replace").decode("cp1252")


def render_pdf(blocks, path):

    """Writes the PDF. Returns False if reportlab is not installed."""

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )
    except ImportError:
        return False

    styles = getSampleStyleSheet()

    note_style = ParagraphStyle(
        "note", parent=styles["BodyText"],
        textColor=colors.grey, fontName="Helvetica-Oblique"
    )

    pre_style = ParagraphStyle(
        "pre", parent=styles["BodyText"],
        fontName="Courier", fontSize=7.5, leading=9
    )

    cell_style = ParagraphStyle(
        "cell", parent=styles["BodyText"], fontSize=8, leading=10
    )

    def para(text, style):
        return Paragraph(xml_escape(pdf_safe(text)), style)

    story = []

    for block in blocks:

        kind = block[0]

        if kind == "h1":
            story.append(para(block[1], styles["Title"]))

        elif kind == "h2":
            story.append(Spacer(1, 8))
            story.append(para(block[1], styles["Heading2"]))

        elif kind == "h3":
            story.append(para(block[1], styles["Heading4"]))

        elif kind == "p":
            story.append(para(block[1], styles["BodyText"]))

        elif kind == "note":
            story.append(para(block[1], note_style))

        elif kind == "ul":
            for item in block[1]:
                story.append(Paragraph(
                    "&bull; " + xml_escape(pdf_safe(item)),
                    styles["BodyText"]
                ))

        elif kind == "kv":
            for k, v in block[1]:
                story.append(Paragraph(
                    f"<b>{xml_escape(pdf_safe(k))}:</b> "
                    f"{xml_escape(pdf_safe(v))}",
                    styles["BodyText"]
                ))

        elif kind == "table":

            data = [[para(h, cell_style) for h in block[1]]]

            data.extend(
                [para(c, cell_style) for c in row]
                for row in block[2]
            )

            table = Table(data, repeatRows=1)

            table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3f8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP")
            ]))

            story.append(table)

        elif kind == "pre":
            story.append(Paragraph(
                xml_escape(pdf_safe(block[1])).replace("\n", "<br/>"),
                pre_style
            ))

        if kind in ("ul", "kv", "table", "p", "pre"):
            story.append(Spacer(1, 4))

    SimpleDocTemplate(
        str(path), pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=18 * mm, bottomMargin=18 * mm,
        title="Cyber Threat Intelligence Report"
    ).build(story)

    return True


# ==========================================
# REPORT GENERATOR AGENT
# ==========================================

def report_generator_agent(query, threat_analysis, mitre_result=None,
                           risk_result=None, mitigation_result=None,
                           retrieved_results=None, plan=None,
                           output_dir="reports",
                           formats=("md", "html", "pdf"),
                           extracted_iocs=None, ioc_verification=None,
                           document_info=None):

    """
    Report Generator Agent.

    INPUT:
        every earlier agent's output (any may be missing or failed)

    OUTPUT:
        dict with the report as Markdown plus the paths of the files
        written. Sections whose agent failed say so instead of
        being silently dropped.
    """

    print("\n==========================================")
    print("REPORT GENERATOR")
    print("==========================================")

    # ---- STEP 1: executive summary ----
    print("\n[1/3] Writing executive summary...")

    facts = collect_facts(
        parse_threat_analysis(threat_analysis),
        mitre_result, risk_result, mitigation_result, extracted_iocs
    )

    summary = executive_summary(facts)

    # ---- STEP 2: assemble ----
    print("\n[2/3] Assembling report...")

    blocks = build_blocks(
        query, plan, threat_analysis, mitre_result, risk_result,
        mitigation_result, retrieved_results, summary,
        extracted_iocs, ioc_verification, document_info
    )

    markdown = render_markdown(blocks)

    # ---- STEP 3: write files ----
    print("\n[3/3] Writing files...")

    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)

    stem = "CTI_Report_" + datetime.now().strftime("%Y%m%d_%H%M%S")

    counter = 1

    while any((folder / f"{stem}.{ext}").exists()
              for ext in ("md", "html", "pdf")):
        counter += 1
        stem = ("CTI_Report_" + datetime.now().strftime("%Y%m%d_%H%M%S")
                + f"_{counter}")

    files = {}

    if "md" in formats:
        path = folder / f"{stem}.md"
        path.write_text(markdown, encoding="utf-8")
        files["markdown"] = str(path)

    if "html" in formats:
        path = folder / f"{stem}.html"
        path.write_text(render_html(blocks), encoding="utf-8")
        files["html"] = str(path)

    if "pdf" in formats:
        path = folder / f"{stem}.pdf"
        if render_pdf(blocks, path):
            files["pdf"] = str(path)
        else:
            print("reportlab is not installed - skipping PDF "
                  "(pip install reportlab).")

    print("\n==========================================")
    print("REPORT READY")
    print("==========================================")

    for kind, path in files.items():
        print(f"{kind:9}: {path}")

    return {
        "agent": "Report Generator",
        "status": "success",
        "executive_summary": summary,
        "markdown": markdown,
        "files": files
    }


# ==========================================
# TEST: FULL CHAIN
# ==========================================

if __name__ == "__main__":

    from planner1 import planner_agent
    from retriever import retriever_agent
    from threat_analyzer import threat_analyzer_agent
    from mitre_mapper import mitre_mapper_agent
    from risk_agent import risk_agent
    from mitigation_agent import mitigation_agent

    question = input("\nAsk a cybersecurity question: ")

    plan = planner_agent(question)

    retrieved = retriever_agent(question)

    analysis = threat_analyzer_agent(question, retrieved)

    mitre = mitre_mapper_agent(retrieved)

    risk = risk_agent(question, analysis, mitre, retrieved)

    mitigation = mitigation_agent(
        question, analysis, mitre, risk, retrieved
    )

    report_generator_agent(
        question, analysis, mitre, risk, mitigation, retrieved, plan
    )
