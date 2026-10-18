"""
Compares the multi-agent workflow with a single-agent RAG baseline.

    python evaluation/run_eval.py evaluation/cases.json

cases.json: a list of {id, pdf, expected:{threat_type_keywords,
techniques, iocs, cves}} - copy cases_template.json and fill in the
analyst-checked answers for each report. Run from the project root.
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

for p in (ROOT, ROOT / 'agents', ROOT / 'evaluation'):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from dotenv import load_dotenv

load_dotenv()

import metrics as M                                    # noqa: E402
import pdf_loader                                      # noqa: E402
import workflow                                        # noqa: E402
from baseline import single_agent_baseline            # noqa: E402
from ioc_extractor import extract_iocs, indicator_values   # noqa: E402

ROWS = [
    ('technique_f1_strict', 'Technique F1 (exact ID)'),
    ('technique_f1_lenient', 'Technique F1 (parent technique)'),
    ('ioc_f1', 'IOC F1 (LLM-extracted)'),
    ('ioc_f1_system', 'IOC F1 (system, incl. pattern matching)'),
    ('cve_f1', 'CVE F1'),
    ('threat_type', 'Threat-type match'),
    ('completeness', 'Completeness'),
    ('ioc_hallucination', 'IOC hallucination rate (lower is better)'),
    ('citations', 'Validated citations'),
    ('latency', 'Latency (s)'),
]


def ioc_section(analysis):
    import re
    m = re.search(r'(?is)IOCs\s*:\s*(.*?)(?:\n\s*[*#]*\s*Affected Systems|\Z)', analysis or '')
    return m.group(1) if m else ''


def score_multi(state, expected, doc_text, seconds):

    mitre = (state.get('mitre') or {}).get('mappings', [])
    techniques = [m['technique_id'] for m in mitre]

    llm_iocs = indicator_values(extract_iocs(ioc_section(state.get('threat_analysis'))))
    system_iocs = llm_iocs | indicator_values(state.get('iocs') or {})

    cves = set((state.get('iocs') or {}).get('cves', []))

    risk = state.get('risk') or {}
    mit = state.get('mitigation') or {}

    fields = {
        'threat_type': bool((state.get('threat_analysis') or '').strip()),
        'iocs': bool(system_iocs),
        'techniques': bool(techniques),
        'risk': risk.get('status') not in (None, 'error'),
        'mitigation': mit.get('status') not in (None, 'error'),
        'summary': bool((state.get('report') or {}).get('executive_summary')),
    }

    strict, lenient = M.technique_scores(techniques, expected.get('techniques', []))
    exp_iocs = {i.lower() for i in expected.get('iocs', [])}

    return {
        'technique_f1_strict': strict,
        'technique_f1_lenient': lenient,
        'ioc_f1': M.f1_of(M.prf(llm_iocs, exp_iocs)),
        'ioc_f1_system': M.f1_of(M.prf(system_iocs, exp_iocs)),
        'cve_f1': M.f1_of(M.prf({c.upper() for c in cves},
                                {c.upper() for c in expected.get('cves', [])})),
        'threat_type': M.threat_type_match(state.get('threat_analysis'),
                                           expected.get('threat_type_keywords')),
        'completeness': M.completeness(fields),
        'ioc_hallucination': M.ioc_hallucination_rate(system_iocs, doc_text),
        'citations': len(risk.get('evidence_used', [])) + len(mit.get('evidence_used', [])),
        'latency': seconds,
    }


def score_baseline(result, expected, doc_text, seconds):

    techniques = [t.get('id', '') if isinstance(t, dict) else str(t)
                  for t in result.get('techniques', [])]

    iocs = M.ioc_values(result.get('iocs', []))

    fields = {
        'threat_type': bool(result.get('threat_type')),
        'iocs': bool(iocs),
        'techniques': bool(techniques),
        'risk': bool(result.get('severity')),
        'mitigation': bool(result.get('mitigations')),
        'summary': bool(result.get('executive_summary')),
    }

    strict, lenient = M.technique_scores(techniques, expected.get('techniques', []))
    exp_iocs = {i.lower() for i in expected.get('iocs', [])}

    return {
        'technique_f1_strict': strict,
        'technique_f1_lenient': lenient,
        'ioc_f1': M.f1_of(M.prf(iocs, exp_iocs)),
        'ioc_f1_system': None,
        'cve_f1': M.f1_of(M.prf({c.upper() for c in result.get('cves', [])},
                                {c.upper() for c in expected.get('cves', [])})),
        'threat_type': M.threat_type_match(result.get('threat_type'),
                                           expected.get('threat_type_keywords')),
        'completeness': M.completeness(fields),
        'ioc_hallucination': M.ioc_hallucination_rate(iocs, doc_text),
        'citations': 0,
        'latency': seconds,
    }


def main():

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('cases')
    parser.add_argument('--no-kb', action='store_true')
    parser.add_argument('--max-chunks', type=int, default=10)
    parser.add_argument('--out', default=str(ROOT / 'evaluation' / 'results'))
    args = parser.parse_args()

    cases = json.loads(Path(args.cases).read_text(encoding='utf8'))

    results = []

    for case in cases:

        pdf = ROOT / case['pdf']
        print(f"\n=== {case['id']} ({pdf.name})")

        doc = pdf_loader.load_report(str(pdf), max_chunks=args.max_chunks)

        started = time.time()
        state = workflow.analyze_pdf(str(pdf), use_kb=not args.no_kb,
                                     max_chunks=args.max_chunks,
                                     output_dir=str(Path(args.out) / 'reports'))
        multi_seconds = round(time.time() - started, 2)

        if state.get('fatal_error'):
            print('  multi-agent failed:', state['fatal_error'])
            continue

        multi = score_multi(state, case['expected'], doc['text'], multi_seconds)

        try:
            result, seconds = single_agent_baseline(
                f"Analyze the threat report '{pdf.name}'.", doc['evidence'])
            base = score_baseline(result, case['expected'], doc['text'], seconds)
        except Exception as error:
            print('  baseline failed:', error)
            base = {k: None for k, _ in ROWS}

        results.append({'id': case['id'], 'multi_agent': multi, 'baseline': base})

    if not results:
        sys.exit('No cases were evaluated.')

    # ---- write results ----
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    (out / f'eval_{stamp}.json').write_text(json.dumps(results, indent=2), encoding='utf8')

    lines = [f'# Evaluation results ({stamp})', '',
             f'Cases: {len(results)}. Scores are averages over cases; '
             'blank = not applicable (no gold answer, or not produced).', '',
             '| Metric | Multi-agent | Single-agent baseline |', '|---|---|---|']

    for key, label in ROWS:
        a = M.mean([r['multi_agent'][key] for r in results])
        b = M.mean([r['baseline'][key] for r in results])
        lines.append(f'| {label} | {"" if a is None else a} | {"" if b is None else b} |')

    (out / f'eval_{stamp}.md').write_text('\n'.join(lines), encoding='utf8')

    print('\n' + '\n'.join(lines))
    print(f'\nSaved to {out}')


if __name__ == '__main__':
    main()
