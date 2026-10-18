"""
Deterministic IOC / CVE extraction (pattern matching, no LLM).

Used to ground the Threat Analyzer: every indicator found here is
literally present in the document text, so it cannot be hallucinated.
Handles "defanged" indicators such as hxxp://evil[.]com.
"""

import ipaddress
import re

# ------------------------------------------------------------------
# Defanging
# ------------------------------------------------------------------

_DEFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*at\s*\]|\(\s*at\s*\)", re.I), "@"),
]


def refang(text):
    for pattern, repl in _DEFANG:
        text = pattern.sub(repl, text)
    return text


# ------------------------------------------------------------------
# Patterns
# ------------------------------------------------------------------

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.?\d)"
)

HASH_RES = {
    "sha256": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])"),
    "sha1": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"),
    "md5": re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
}

URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]\}]+", re.I)

EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

# A whitelist of TLDs keeps file names such as powershell.exe or
# index.html out of the domain list.
TLDS = (
    "com|net|org|info|biz|io|ru|cn|xyz|top|cc|tk|ml|ga|cf|gq|pw|su|ws|to|me|"
    "co|us|uk|de|fr|nl|in|br|ir|kp|kr|jp|ua|by|kz|site|online|club|live|shop|"
    "app|dev|cloud|tech|pro|link|click|support|email|vip|work|world|today|"
    "space|store|website|icu|buzz|sbs|cyou|ltd|one|page|digital|network"
)

DOMAIN_RE = re.compile(
    r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + TLDS + r")\b",
    re.I,
)

FILE_RE = re.compile(
    r"\b[\w.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|vbe|js|jse|docm|xlsm|lnk|iso|"
    r"scr|msi|jar|hta|sys)\b",
    re.I,
)

# Reference / vendor domains that appear in report bibliographies.
BENIGN_DOMAIN_SUFFIXES = (
    "mitre.org", "cisa.gov", "nist.gov", "microsoft.com", "google.com",
    "github.com", "wikipedia.org", "w3.org", "apache.org", "python.org",
    "virustotal.com", "twitter.com", "linkedin.com", "youtube.com",
    "cve.org", "first.org", "sans.org", "us-cert.gov", "ic3.gov",
)

LOOPBACK_PREFIXES = ("0.", "127.", "255.")


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _is_benign(domain):
    d = domain.lower()
    return any(d == s or d.endswith("." + s) for s in BENIGN_DOMAIN_SUFFIXES)


def _is_hash(value):
    return (any(c.isdigit() for c in value)
            and any(c.isalpha() for c in value)
            and len(set(value.lower())) >= 6)


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def extract_iocs(text):

    """
    Returns a dict of indicators found in the text:
    cves, ips, domains, urls, emails, hashes{md5,sha1,sha256}, files.
    """

    text = refang(text or "")

    cves = _dedupe([m.upper() for m in CVE_RE.findall(text)])

    all_ips = _dedupe([
        ip for ip in IPV4_RE.findall(text)
        if not ip.startswith(LOOPBACK_PREFIXES)
    ])

    # private addresses are usually victim assets, not indicators
    internal_ips = [ip for ip in all_ips if ipaddress.ip_address(ip).is_private
                    and not ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))]
    ips = [ip for ip in all_ips if ip not in internal_ips]

    urls = _dedupe([
        u.rstrip(".,;:") for u in URL_RE.findall(text)
        if not _is_benign(re.sub(r"^https?://", "", u, flags=re.I)
                          .split("/")[0].split(":")[0])
    ])

    emails = _dedupe(EMAIL_RE.findall(text))

    domains = []

    for d in DOMAIN_RE.findall(text):
        d = d.lower().rstrip(".")
        if _is_benign(d) or IPV4_RE.fullmatch(d):
            continue
        domains.append(d)

    # domains inside URLs are already reported through the URL
    domains = _dedupe(domains)

    hashes = {}
    consumed = set()

    for kind in ("sha256", "sha1", "md5"):
        found = []
        for h in HASH_RES[kind].findall(text):
            if _is_hash(h) and h.lower() not in consumed:
                found.append(h.lower())
        hashes[kind] = _dedupe(found)
        consumed.update(hashes[kind])

    files = _dedupe(FILE_RE.findall(text))

    return {
        "cves": cves,
        "ips": ips,
        "internal_ips": internal_ips,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "hashes": hashes,
        "files": files,
    }


def flatten(iocs):

    """[(type, value), ...] for display / evaluation."""

    rows = []

    labels = [
        ("cves", "CVE"), ("ips", "IP address"), ("domains", "Domain"),
        ("urls", "URL"), ("emails", "Email"), ("files", "File name"),
    ]

    for key, label in labels:
        rows.extend((label, v) for v in iocs.get(key, []))

    for kind, values in iocs.get("hashes", {}).items():
        rows.extend((kind.upper(), v) for v in values)

    return rows


def count(iocs):
    return len(flatten(iocs))


def indicator_values(iocs, include_files=False):

    """Flat set of lower-cased indicator values (no CVEs, no file names)."""

    values = set()

    for label, v in flatten(iocs):
        if label == "CVE" or (label == "File name" and not include_files):
            continue
        values.add(v.lower())

    return values


def verify_listed_iocs(analysis_text, document_text):

    """
    Cross-checks the IOCs the Threat Analyzer LLM listed against the
    document. Returns (verified, unverified) lists of indicator strings.
    Only indicators that pattern-match as IOCs are checked.
    """

    section = analysis_text or ""

    match = re.search(
        r"(?is)IOCs\s*:\s*(.*?)(?:\n\s*[*#]*\s*Affected Systems\s*[*]*\s*:|\Z)",
        section,
    )

    if match:
        section = match.group(1)

    listed = indicator_values(extract_iocs(section))

    doc = refang(document_text or "").lower()

    verified, unverified = [], []

    for value in sorted(listed):
        (verified if value in doc else unverified).append(value)

    return verified, unverified
