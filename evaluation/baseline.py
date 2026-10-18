"""
Single-agent RAG baseline: ONE LLM call sees the same evidence the
multi-agent system sees and must produce the whole analysis at once.
Used in Phase 6 to compare against the multi-agent workflow.
"""

import json
import os
import time

from dotenv import load_dotenv
from groq import Groq

load_dotenv()

BASELINE_MODEL = "openai/gpt-oss-120b"


def single_agent_baseline(query, evidence, model=BASELINE_MODEL):

    """Returns (result_dict, seconds). result_dict follows the schema below."""

    client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    context = "\n\n".join(
        f"[Source: {e['source']} | Page: {e['page']}]\n{e['text']}"
        for e in evidence
    )

    prompt = f"""
You are the single-agent baseline of a cyber threat intelligence system.
Using ONLY the context below, produce the complete analysis in one pass.

Context:
{context}

Task: {query}

Return ONLY JSON with exactly these keys:
{{
  "threat_type": "<string>",
  "malware": "<string>",
  "attack_summary": "<string>",
  "iocs": ["<indicator>"],
  "cves": ["CVE-YYYY-NNNN"],
  "techniques": [{{"id": "T1059.001", "name": "<name>"}}],
  "severity": "Critical|High|Medium|Low",
  "likelihood": "Very Likely|Likely|Possible|Unlikely",
  "business_impact": ["<impact>"],
  "mitigations": ["<recommendation>"],
  "executive_summary": "<4-6 sentences>"
}}
"""

    started = time.time()

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        response_format={"type": "json_object"},
    )

    seconds = round(time.time() - started, 2)

    try:
        result = json.loads(response.choices[0].message.content or "{}")
    except json.JSONDecodeError:
        result = {}

    return result, seconds
