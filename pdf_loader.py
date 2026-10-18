"""
Turns an unstructured PDF threat report into clean text, chunks,
indicators and a compact set of evidence chunks for the agents.

Pipeline:  extract -> clean -> chunk -> extract IOCs -> select evidence
"""

import io
import re
import unicodedata
from collections import Counter
from pathlib import Path

import numpy as np
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from ioc_extractor import extract_iocs, count as ioc_count


class PDFError(Exception):
    """Raised when a PDF cannot be turned into usable text."""


CHUNK_SIZE = 1000          # same settings as ingest.py
CHUNK_OVERLAP = 200
MIN_TEXT_CHARS = 200       # below this we treat the PDF as scanned/empty

# Queries describing what a CTI analyst looks for. Chunks similar to
# any of them are preferred when the report is too long for the LLMs.
CTI_QUERIES = [
    "threat actor malware ransomware campaign attack summary",
    "indicators of compromise IP address domain file hash",
    "initial access phishing exploited vulnerability CVE",
    "execution persistence privilege escalation credential access lateral movement",
    "command and control exfiltration data encryption impact",
    "affected systems victims organizations business impact",
    "mitigation remediation recommendations detection patching",
]

CTI_KEYWORDS = [
    "malware", "ransomware", "phishing", "exploit", "vulnerab", "cve-",
    "payload", "backdoor", "credential", "persistence", "lateral",
    "exfiltrat", "encrypt", "command and control", "c2", "threat actor",
    "apt", "campaign", "ioc", "indicator", "hash", "powershell", "trojan",
    "botnet", "remote access", "privilege", "mitigat", "patch", "detect",
]

_embedder = None
_embedder_tried = False


def get_embedder():

    """Embedding model for evidence selection, or None (keyword fallback)."""

    global _embedder, _embedder_tried

    if _embedder_tried:
        return _embedder

    _embedder_tried = True

    try:
        from rag import embedding_model          # already loaded by the KB
        _embedder = embedding_model
    except Exception:
        try:
            from sentence_transformers import SentenceTransformer
            _embedder = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception:
            _embedder = None

    return _embedder


# ------------------------------------------------------------------
# 1. Extraction
# ------------------------------------------------------------------

def extract_pages(source):

    """
    source: file path, bytes, or a binary file object.
    Returns [{"page": n, "text": raw_text}, ...].
    """

    try:
        if isinstance(source, (bytes, bytearray)):
            reader = PdfReader(io.BytesIO(source))
        elif hasattr(source, "read"):
            reader = PdfReader(source)
        else:
            reader = PdfReader(str(source))
    except Exception as error:
        raise PDFError(f"Could not open the PDF: {error}")

    if reader.is_encrypted:
        try:
            ok = reader.decrypt("")
        except Exception:
            ok = 0
        if not ok:
            raise PDFError("The PDF is password-protected.")

    pages = []

    for number, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        pages.append({"page": number, "text": text})

    total = sum(len(p["text"].strip()) for p in pages)

    if total < MIN_TEXT_CHARS:
        raise PDFError(
            "No readable text found. The PDF looks scanned (image-only); "
            "OCR is not supported yet - please upload a text-based PDF."
        )

    return pages


# ------------------------------------------------------------------
# 2. Cleaning
# ------------------------------------------------------------------

_PAGE_NUMBER = re.compile(
    r"^\s*(?:page\s*)?\d{1,4}(?:\s*(?:of|/)\s*\d{1,4})?\s*$", re.I
)


def _norm_edge(line):
    return re.sub(r"\d+", "#", line.strip().lower())


def _dehyphenate(text):

    """
    Joins words split at a line end ("manu-\\nfacturing") but leaves
    URLs, domains and e-mail addresses alone, because a hyphen wrap
    inside "update-\\ncheck[.]xyz" must not delete the hyphen.
    """

    def join(match):
        head, tail = match.group(1), match.group(2)
        core = tail.rstrip(".,;:)")
        if re.search(r"://|/|@", head) or re.search(r"[./\[@]", core):
            return f"{head}-{tail}"
        return head + tail

    return re.sub(r"(\S*\w)-\n([a-z]\S*)", join, text)


def clean_pages(pages):

    """Removes repeated headers/footers, page numbers and hyphenation."""

    cleaned = []

    for p in pages:
        text = unicodedata.normalize("NFKC", p["text"])
        text = text.replace("\u00ad", "").replace("\u200b", "")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        cleaned.append({"page": p["page"], "lines": text.split("\n")})

    # repeated header/footer lines (first/last 2 non-empty lines per page)
    if len(cleaned) >= 4:

        counter = Counter()

        for p in cleaned:
            non_empty = [l for l in p["lines"] if l.strip()]
            edges = set(_norm_edge(l) for l in non_empty[:2] + non_empty[-2:])
            counter.update(e for e in edges if 2 < len(e) < 120)

        threshold = max(3, int(0.4 * len(cleaned)))
        repeated = {e for e, c in counter.items() if c >= threshold}

        for p in cleaned:
            p["lines"] = [
                l for l in p["lines"]
                if not (l.strip() and _norm_edge(l) in repeated)
            ]

    out = []

    for p in cleaned:

        lines = [l.rstrip() for l in p["lines"] if not _PAGE_NUMBER.match(l)]

        text = "\n".join(lines)
        text = _dehyphenate(text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()

        if text:
            out.append({"page": p["page"], "text": text})

    return out


# ------------------------------------------------------------------
# 3. Chunking
# ------------------------------------------------------------------

def chunk_pages(pages, source):

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
    )

    chunks = []

    for p in pages:
        for piece in splitter.split_text(p["text"]):
            chunks.append({
                "text": piece,
                "source": source,
                "page": p["page"],
                "chunk_id": len(chunks),
                "origin": "uploaded",
            })

    return chunks


# ------------------------------------------------------------------
# 4. Evidence selection
# ------------------------------------------------------------------

def _keyword_score(text):
    low = text.lower()
    return min(sum(1 for k in CTI_KEYWORDS if k in low), 6) / 6.0


def select_evidence(chunks, max_chunks=10, max_chars=12000, embedder="auto"):

    """
    Picks the chunks that matter most so long reports fit the LLM
    token limits. Always keeps the opening chunk (usually the
    summary). Returns chunks in document order with a `distance`
    field (lower = more relevant) like the knowledge-base results.
    """

    if not chunks:
        return []

    if len(chunks) <= max_chunks and sum(len(c["text"]) for c in chunks) <= max_chars:
        return [dict(c, distance=0.0) for c in chunks]

    if embedder == "auto":
        embedder = get_embedder()

    sims = np.zeros(len(chunks))

    if embedder is not None:
        try:
            chunk_vecs = np.asarray(embedder.encode([c["text"] for c in chunks]))
            query_vecs = np.asarray(embedder.encode(CTI_QUERIES))
            chunk_vecs = chunk_vecs / (np.linalg.norm(chunk_vecs, axis=1, keepdims=True) + 1e-9)
            query_vecs = query_vecs / (np.linalg.norm(query_vecs, axis=1, keepdims=True) + 1e-9)
            sims = (chunk_vecs @ query_vecs.T).max(axis=1)
        except Exception:
            sims = np.zeros(len(chunks))

    scores = []

    for i, c in enumerate(chunks):
        has_ioc = ioc_count(extract_iocs(c["text"])) > 0
        scores.append(sims[i] + 0.10 * has_ioc + 0.15 * _keyword_score(c["text"]))

    order = sorted(range(len(chunks)), key=lambda i: scores[i], reverse=True)

    picked, used = [0], len(chunks[0]["text"])

    for i in order:
        if i == 0 or len(picked) >= max_chunks:
            continue
        if used + len(chunks[i]["text"]) > max_chars:
            continue
        picked.append(i)
        used += len(chunks[i]["text"])

    top = max(scores) or 1.0

    return [
        dict(chunks[i], distance=round(float(1.0 - scores[i] / top), 4))
        for i in sorted(picked)
    ]


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------

def load_report(source, filename=None, max_chunks=10, max_chars=12000):

    """
    Reads an unstructured PDF and returns:
      filename, pages, text (cleaned full text), chunks (all),
      evidence (selected chunks for the agents), iocs, warnings
    Raises PDFError if the file cannot be read.
    """

    if filename is None:
        filename = Path(str(source)).name if isinstance(source, (str, Path)) else "uploaded_report.pdf"

    raw_pages = extract_pages(source)
    pages = clean_pages(raw_pages)

    if not pages:
        raise PDFError("The PDF contained no usable text after cleaning.")

    text = "\n\n".join(p["text"] for p in pages)
    chunks = chunk_pages(pages, filename)
    evidence = select_evidence(chunks, max_chunks=max_chunks, max_chars=max_chars)
    iocs = extract_iocs(text)

    warnings = []

    empty_pages = len(raw_pages) - len(pages)

    if empty_pages > 0:
        warnings.append(
            f"{empty_pages} page(s) had no extractable text (images or blank)."
        )

    if len(evidence) < len(chunks):
        warnings.append(
            f"Long report: {len(evidence)} of {len(chunks)} text chunks were "
            "selected as evidence to fit model limits."
        )

    return {
        "filename": filename,
        "pages": len(raw_pages),
        "characters": len(text),
        "text": text,
        "chunks": chunks,
        "evidence": evidence,
        "iocs": iocs,
        "warnings": warnings,
    }
