"""Detect two phishing tells:

1. **Executive impersonation** — From: display-name claims an executive title
   (CEO, CFO, etc.) but the From: domain isn't on the org's allowlist.
2. **Lookalike domains** — domains that target a protected brand via
   homoglyph substitution, Levenshtein-near typos, or a swapped TLD.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

import tldextract  # type: ignore[import-untyped]
from rapidfuzz import distance  # type: ignore[import-untyped]


_DATA_DIR = Path(__file__).parent / "data"

# Match titles either as a standalone word or followed by punctuation.
# Captures common variations seen in real BEC samples.
_EXEC_TITLES = re.compile(
    r"\b(?:"
    r"CEO|CFO|COO|CTO|CIO|CISO|CMO|"
    r"President|Vice\s*President|VP|"
    r"Director|Managing\s*Director|"
    r"Head\s+of(?:\s+\w+)+|"
    r"Chief\s+\w+(?:\s+Officer)?|"
    r"Chairman|Chairwoman|Chairperson|"
    r"Owner|Founder|Co-?Founder|"
    r"General\s*Counsel"
    r")\b",
    re.IGNORECASE,
)

# Common homoglyph swaps used in lookalike domains.
# Each pair is (cheat_char, real_char) — e.g. '0' is often used in place of 'o'.
_HOMOGLYPHS: list[tuple[str, str]] = [
    ("0", "o"),
    ("1", "l"),
    ("1", "i"),
    ("3", "e"),
    ("4", "a"),
    ("5", "s"),
    ("rn", "m"),
    ("vv", "w"),
    ("nn", "m"),
    ("cl", "d"),
]

# TLDs that show up disproportionately in phishing kits.
_SUSPICIOUS_TLDS = {"top", "xyz", "click", "zip", "mov", "tk", "ml", "ga", "cf", "gq", "rest", "country", "kim"}


@dataclass
class SpoofFinding:
    kind: str            # "exec_impersonation" | "lookalike_domain" | "lookalike_in_url"
    domain: str
    detail: str
    target_brand: str = ""
    score: float = 0.0   # for lookalike: lower distance = higher confidence
    location: str = ""   # for url findings: "host" | "subdomain" | "path"
    source_url: str = ""


@dataclass
class SpoofReport:
    findings: list[SpoofFinding] = field(default_factory=list)


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.append(line)
    return out


def _registrable(domain: str) -> str:
    """Return the registrable portion of a domain (e.g. mail.foo.co.uk -> foo.co.uk)."""
    if not domain:
        return ""
    ext = tldextract.extract(domain)
    if not ext.domain or not ext.suffix:
        return domain.lower()
    return f"{ext.domain}.{ext.suffix}".lower()


def detect_exec_impersonation(
    display_name: str,
    from_domain: str,
    known_domains: list[str] | None = None,
) -> list[SpoofFinding]:
    if not display_name or not from_domain:
        return []
    if known_domains is None:
        known_domains = load_lines(_DATA_DIR / "known_domains.txt")
    title_match = _EXEC_TITLES.search(display_name)
    if not title_match:
        return []
    if _registrable(from_domain) in {_registrable(d) for d in known_domains}:
        return []
    return [
        SpoofFinding(
            kind="exec_impersonation",
            domain=from_domain,
            detail=f'Display name claims executive title "{title_match.group(0)}" but domain {from_domain} is not on the known-domains allowlist',
        )
    ]


_DISPLAY_TOKEN_RE = re.compile(r"[a-z0-9]+")


def detect_display_name_brand_spoof(
    display_name: str,
    from_domain: str,
    brands: list[str] | None = None,
) -> list[SpoofFinding]:
    """Catch the classic 'From: DocuSign <random@gmail.com>' pattern.

    Fires when the display-name contains a protected-brand label as a complete
    token (or when whitespace-stripped display-name == brand label) AND the
    from-domain isn't the brand's actual domain. Brand label must be >= 4
    characters to keep false positives down on common 3-letter words.
    """
    if not display_name or not from_domain:
        return []
    if brands is None:
        brands = load_lines(_DATA_DIR / "protected_brands.txt")

    name_lower = display_name.lower()
    tokens = set(_DISPLAY_TOKEN_RE.findall(name_lower))
    joined = "".join(_DISPLAY_TOKEN_RE.findall(name_lower))  # "omaha steaks" -> "omahasteaks"

    from_reg = _registrable(from_domain)
    findings: list[SpoofFinding] = []
    seen: set[str] = set()

    for brand in brands:
        b_ext = tldextract.extract(brand)
        b_label = b_ext.domain.lower()
        if not b_label or len(b_label) < 4:
            continue
        # Match condition: brand label appears as a complete token, OR the
        # whitespace-stripped display name *equals* the brand label.
        is_match = (b_label in tokens) or (b_label == joined)
        if not is_match:
            continue
        if _registrable(brand) == from_reg:
            continue  # legit — display name matches its own domain
        if b_label in seen:
            continue
        seen.add(b_label)
        findings.append(SpoofFinding(
            kind="display_name_brand_spoof",
            domain=from_domain,
            target_brand=brand,
            detail=f'Display name "{display_name}" claims brand "{b_label}" but from-domain is {from_domain}',
        ))
    return findings


def _homoglyph_normalize(label: str) -> str:
    out = label
    for cheat, real in _HOMOGLYPHS:
        out = out.replace(cheat, real)
    return out


def detect_lookalike(
    domain: str,
    brands: list[str] | None = None,
    *,
    max_distance: int = 2,
) -> list[SpoofFinding]:
    if not domain:
        return []
    if brands is None:
        brands = load_lines(_DATA_DIR / "protected_brands.txt")

    reg = _registrable(domain)
    if reg in {_registrable(b) for b in brands}:
        return []  # exact match — not a lookalike, it's the real thing

    ext = tldextract.extract(domain)
    label = ext.domain.lower()
    tld = ext.suffix.lower()
    findings: list[SpoofFinding] = []

    for brand in brands:
        b_ext = tldextract.extract(brand)
        b_label = b_ext.domain.lower()
        b_tld = b_ext.suffix.lower()
        if not b_label:
            continue

        # 1. Homoglyph: normalize both labels and check exact match
        if _homoglyph_normalize(label) == _homoglyph_normalize(b_label) and label != b_label:
            findings.append(
                SpoofFinding(
                    kind="lookalike_domain",
                    domain=domain,
                    target_brand=brand,
                    detail=f"Homoglyph match: {label} ~= {b_label}",
                    score=0.0,
                )
            )
            continue

        # 2. Levenshtein distance on the registrable label
        d = distance.Levenshtein.distance(label, b_label)
        if 0 < d <= max_distance:
            findings.append(
                SpoofFinding(
                    kind="lookalike_domain",
                    domain=domain,
                    target_brand=brand,
                    detail=f"Levenshtein distance {d} from {b_label} (label='{label}')",
                    score=float(d),
                )
            )
            continue

        # 3. Same label but suspicious TLD swap
        if label == b_label and tld != b_tld and tld in _SUSPICIOUS_TLDS:
            findings.append(
                SpoofFinding(
                    kind="lookalike_domain",
                    domain=domain,
                    target_brand=brand,
                    detail=f"TLD swap: brand='{brand}' but observed TLD '.{tld}' (suspicious)",
                    score=0.0,
                )
            )

    return findings


# Path-segment splitter: keep alphanumeric runs only.
_SEGMENT_RE = re.compile(r"[a-zA-Z0-9]+")


def _url_candidates(url: str) -> list[tuple[str, str]]:
    """Pull (token, location_label) candidates from a URL: registrable label,
    each subdomain label, and each alphanumeric path segment. Used to find
    brand lookalikes that hide in subdomains or paths (e.g. office356 in
    `storage.googleapis.com/office356/work.html`)."""
    out: list[tuple[str, str]] = []
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return out
    host = (parsed.hostname or "").lower()
    if host:
        ext = tldextract.extract(host)
        if ext.domain:
            out.append((ext.domain.lower(), "host"))
        if ext.subdomain:
            for sub in ext.subdomain.lower().split("."):
                if sub:
                    out.append((sub, "subdomain"))
    for seg in _SEGMENT_RE.findall(parsed.path or ""):
        seg = seg.lower()
        if 5 <= len(seg) <= 30:  # too-short segments produce false-positive Levenshtein hits
            out.append((seg, "path"))
    return out


def detect_lookalike_in_urls(
    urls: list[str],
    brands: list[str] | None = None,
    *,
    max_distance: int = 2,
) -> list[SpoofFinding]:
    """Find brand-lookalike substrings *anywhere* in a URL — host, subdomain, or path.

    A phisher hosting `office356` content on a legitimate cloud bucket
    (`storage.googleapis.com/office356/...`) doesn't trip the from-domain check
    but is identical-intent: brand spoofing via near-typo. We flag it here.
    """
    if not urls:
        return []
    if brands is None:
        brands = load_lines(_DATA_DIR / "protected_brands.txt")

    brand_labels: list[tuple[str, str]] = []
    for b in brands:
        b_ext = tldextract.extract(b)
        if b_ext.domain:
            brand_labels.append((b_ext.domain.lower(), b))

    findings: list[SpoofFinding] = []
    seen: set[tuple[str, str, str]] = set()  # dedupe on (token, brand, location)

    for url in urls:
        for token, location in _url_candidates(url):
            for b_label, brand in brand_labels:
                if token == b_label:
                    continue  # exact match isn't a lookalike

                # 1. Homoglyph (any brand length)
                if _homoglyph_normalize(token) == _homoglyph_normalize(b_label):
                    key = (token, brand, location)
                    if key not in seen:
                        seen.add(key)
                        findings.append(SpoofFinding(
                            kind="lookalike_in_url",
                            domain=token,
                            target_brand=brand,
                            detail=f"Homoglyph match in URL {location}: '{token}' ~= '{b_label}'",
                            score=0.0,
                            location=location,
                            source_url=url,
                        ))
                    continue

                # 2. Levenshtein — only for brand labels >= 5 chars to avoid FPs on short brands.
                if len(b_label) < 5 or len(token) < 5:
                    continue
                d = distance.Levenshtein.distance(token, b_label)
                if 0 < d <= max_distance:
                    key = (token, brand, location)
                    if key not in seen:
                        seen.add(key)
                        findings.append(SpoofFinding(
                            kind="lookalike_in_url",
                            domain=token,
                            target_brand=brand,
                            detail=f"Levenshtein {d} from '{b_label}' in URL {location} (token='{token}')",
                            score=float(d),
                            location=location,
                            source_url=url,
                        ))
    return findings


def analyze(display_name: str, from_domain: str, urls: list[str] | None = None) -> SpoofReport:
    rep = SpoofReport()
    rep.findings.extend(detect_exec_impersonation(display_name, from_domain))
    rep.findings.extend(detect_display_name_brand_spoof(display_name, from_domain))
    rep.findings.extend(detect_lookalike(from_domain))
    if urls:
        rep.findings.extend(detect_lookalike_in_urls(urls))
    return rep
