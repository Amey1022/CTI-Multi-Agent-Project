"""
Command-line runner for the CTI multi-agent workflow.

    python run_pipeline.py path/to/report.pdf
    python run_pipeline.py --question "How does ransomware spread?"
    python run_pipeline.py                      (prompts for either)

Run from the project root. Needs GROQ_API_KEY in .env.
"""

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

import workflow                                                  # noqa: E402


def main():

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pdf", nargs="?", help="threat report PDF to analyze")
    parser.add_argument("--question", "-q", help="ask the knowledge base instead")
    parser.add_argument("--no-kb", action="store_true",
                        help="do not use the knowledge base")
    parser.add_argument("--max-chunks", type=int, default=10,
                        help="evidence chunks taken from the PDF (default 10)")
    parser.add_argument("--output-dir", default="reports")

    args = parser.parse_args()

    if not args.pdf and not args.question:

        path = input("Path to a PDF report (Enter to ask a question instead): ")
        path = path.strip().strip('"').strip("'")

        if path:
            args.pdf = path
        else:
            args.question = input("Question: ").strip()

    if args.pdf:

        if not Path(args.pdf).is_file():
            sys.exit(f"File not found: {args.pdf}")

        state = workflow.analyze_pdf(
            args.pdf, use_kb=not args.no_kb, max_chunks=args.max_chunks,
            output_dir=args.output_dir)

    elif args.question:

        state = workflow.analyze_question(
            args.question, use_kb=not args.no_kb, output_dir=args.output_dir)

    else:
        sys.exit("Nothing to analyze.")

    # ---- summary ----
    print("\n==========================================")
    print("PIPELINE SUMMARY")
    print("==========================================")

    if state.get("fatal_error"):
        print("FAILED:", state["fatal_error"])
        sys.exit(1)

    for e in state["events"]:
        print(f"{e['status']:8} {e['label']:18} {e['seconds']:>6}s  {e['detail']}")

    mitre = state.get("mitre") or {}
    print("\nMITRE techniques:", mitre.get("total_techniques", 0))
    print("Attack flow     :", " -> ".join(mitre.get("attack_flow", [])) or "n/a")
    print("Risk            :", (state.get("risk") or {}).get("summary", "n/a"))
    print("Mitigation      :", (state.get("mitigation") or {}).get("summary", "n/a"))

    for kind, path in (state.get("report") or {}).get("files", {}).items():
        print(f"Report ({kind:8}):", path)

    if state["errors"]:
        print("\nWarnings/errors:")
        for message in state["errors"]:
            print(" -", message)


if __name__ == "__main__":
    main()
