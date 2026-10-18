"""Metrics for comparing the multi-agent system with the baseline."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ioc_extractor import extract_iocs, indicator_values, refang   # noqa: E402

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)


def prf(predicted, gold):

    """Precision, recall, F1 of two sets (empty gold -> None)."""

    predicted, gold = set(predicted), set(gold)

    if not gold:
        return None

    hit = len(predicted & gold)

    precision = hit / len(predicted) if predicted else 0.0
    recall = hit / len(gold)
    f1 = (2 * precision * recall / (precision + recall)
          if precision + recall else 0.0)

    return round(precision, 3), round(recall, 3), round(f1, 3)


def f1_of(scores):
    return None if scores is None else scores[2]


def norm_techniques(ids):
    return {t.upper() for i in ids for t in TECH_RE.findall(str(i))}


def parents(ids):
    return {t.split(".")[0] for t in ids}


def technique_scores(predicted, gold):

    """Strict (exact ID) and lenient (parent technique) F1."""

    p, g = norm_techniques(predicted), norm_techniques(gold)

    return f1_of(prf(p, g)), f1_of(prf(parents(p), parents(g)))


def ioc_values(items):

    """Indicator values (lower-case) found in a list of strings."""

    return indicator_values(extract_iocs("\n".join(map(str, items))))


def ioc_hallucination_rate(predicted_values, document_text):

    """Share of predicted indicators that never occur in the document."""

    if not predicted_values:
        return 0.0

    doc = refang(document_text or "").lower()

    missing = [v for v in predicted_values if v not in doc]

    return round(len(missing) / len(predicted_values), 3)


def threat_type_match(predicted_text, keywords):

    if not keywords:
        return None

    text = (predicted_text or "").lower()

    return 1.0 if any(k.lower() in text for k in keywords) else 0.0


def completeness(fields):

    """Share of the expected analysis fields that are non-empty."""

    present = sum(1 for v in fields.values() if v)

    return round(present / len(fields), 3)


def mean(values):

    values = [v for v in values if v is not None]

    return round(sum(values) / len(values), 3) if values else None
