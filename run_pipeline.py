"""
Temporary manual runner for the CTI multi-agent pipeline.

Chains every agent that exists today:
    Planner -> Retriever -> Threat Analyzer -> MITRE Mapper -> Risk
    -> Mitigation -> Report Generator

This is a stand-in for the LangGraph workflow (Task 4.9).
Run from the project root:  python run_pipeline.py
"""

import sys
from pathlib import Path

sys.path.append(
    str(Path(__file__).resolve().parent / "agents"
))

from planner1 import planner_agent
from retriever import retriever_agent
from threat_analyzer import threat_analyzer_agent
from mitre_mapper import mitre_mapper_agent
from risk_agent import risk_agent
from mitigation_agent import mitigation_agent
from report_generator import report_generator_agent


# ==========================================
# SAMPLE REPORT (fictitious) - lets you exercise MITRE and
# Risk even though the knowledge base has no threat reports yet
# ==========================================

SAMPLE_REPORT = [
    {
        "source": "sample_threat_report.pdf",
        "page": 1,
        "distance": 0.0,
        "text": (
            "Incident summary: the attacker sent a phishing email with a "
            "malicious attachment to finance staff. Opening the document "
            "ran powershell.exe, which downloaded payload files from "
            "203.0.113.45 (evil-updates.example.com). The actor used "
            "stolen credentials, ran a credential dump of LSASS memory "
            "and used a command to disable defender on the host. "
            "Before encryption, the shadow copies deleted to block "
            "recovery. Ransomware encryption then hit the file servers "
            "and encrypted files across the domain, halting billing "
            "for four days."
        ),
    }
]


def main():

    print("\n=========== CTI PIPELINE ===========")
    print("1) Ask a question against the knowledge base")
    print("2) Analyze the built-in sample ransomware report")

    choice = input("\nChoose 1 or 2: ").strip()

    # --------------------------------------
    # Planner (always first)
    # --------------------------------------

    if choice == "2":
        question = "Analyze the ransomware incident in the sample report."
    else:
        question = input("\nAsk a cybersecurity question: ")

    plan = planner_agent(question)

    print("\n========== PLANNER OUTPUT ==========\n")
    print(plan)

    # --------------------------------------
    # Retriever
    # --------------------------------------

    if choice == "2":
        retrieved = SAMPLE_REPORT
    else:
        retrieved = retriever_agent(question)

    # --------------------------------------
    # Threat Analyzer -> MITRE Mapper -> Risk -> Mitigation
    # --------------------------------------

    analysis = threat_analyzer_agent(question, retrieved)

    mitre = mitre_mapper_agent(retrieved)

    risk = risk_agent(question, analysis, mitre, retrieved)

    mitigation = mitigation_agent(
        question, analysis, mitre, risk, retrieved
    )

    # --------------------------------------
    # Report Generator
    # --------------------------------------

    report = report_generator_agent(
        question, analysis, mitre, risk, mitigation, retrieved, plan
    )

    # --------------------------------------
    # Final summary
    # --------------------------------------

    print("\n==========================================")
    print("PIPELINE SUMMARY")
    print("==========================================")
    print("MITRE techniques:", mitre.get("total_techniques", 0))
    print("Attack flow     :", " -> ".join(mitre.get("attack_flow", [])) or "n/a")
    print("Risk            :", risk.get("summary"))
    print("Mitigation      :", mitigation.get("summary"))
    print("Report files    :", ", ".join(report["files"].values()))


if __name__ == "__main__":
    main()