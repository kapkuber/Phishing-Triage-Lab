"""Extract IOCs from email body and attachment bytes.

- URLs: handles standard `https://`, obfuscated `hxxps://`, dot-bracketing `[.]`,
  whitespace-padded forms, and href= attributes in HTML.
- Base64 blobs: ≥40-char runs of base64 alphabet, decode and sniff magic bytes.
- IPs: literal IPv4 and IPv6 addresses in the body.
- Email addresses: useful for Reply-To capture and analyst pivoting.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Optional


_URL_RE = re.compile(
    r"""
    (?P<scheme>h[tx]{2}ps?)        # http, https, hxxp, hxxps
    [:\s]*//                       # ':// ' or sometimes ':<space>//'
    (?P<host>[^\s'"<>)\]}]+?)      # host + path, until whitespace or quote
    (?=[\s'"<>)\]}]|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


_MAGIC = [
    (b"MZ", "PE executable (.exe / .dll)"),
    (b"PK\x03\x04", "Zip / Office Open XML (.zip / .docx / .xlsx)"),
    (b"%PDF", "PDF document"),
    (b"\x7fELF", "ELF binary"),
    (b"\xd0\xcf\x11\xe0", "Legacy Office (.doc / .xls)"),
    (b"<!DOCTYPE html", "HTML document"),
    (b"<html", "HTML document"),
    (b"<?xml", "XML document"),
    (b"\x1f\x8b", "gzip stream"),
    (b"Rar!", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"BZh", "bzip2 stream"),
]


@dataclass
class Base64Hit:
    snippet: str           # truncated original blob (first 60 chars)
    decoded_size: int
    magic_label: Optional[str]
    sha256_decoded: str = ""


@dataclass
class IocReport:
    urls: list[str] = field(default_factory=list)
    obfuscated_urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    base64_hits: list[Base64Hit] = field(default_factory=list)


def _normalize_obfuscation(s: str) -> str:
    """Convert hxxp -> http and [.] -> . so downstream tools accept the URL."""
    return (
        s.replace("hxxps", "https")
         .replace("hxxp", "http")
         .replace("HXXPS", "https")
         .replace("HXXP", "http")
         .replace("[.]", ".")
         .replace("(.)", ".")
         .replace("[dot]", ".")
         .replace("{.}", ".")
    )


def _sniff_magic(data: bytes) -> Optional[str]:
    head = data[:16]
    for sig, label in _MAGIC:
        if head.startswith(sig) or sig in data[: max(64, len(sig))]:
            return label
    return None


_OBF_MARKER_RE = re.compile(r"hxxps?://|\[\.\]|\(\.\)|\[dot\]|\{\.\}", re.IGNORECASE)


def extract_urls(text: str) -> tuple[list[str], list[str]]:
    """Return (deobfuscated_urls, original_obfuscated_urls).

    We deobfuscate the *entire text* before URL matching so dot-bracketing and
    hxxp prefixes don't trip the regex. We separately track which input regions
    originally contained obfuscation markers so we can report them back.
    """
    if not text:
        return [], []

    had_obfuscation = bool(_OBF_MARKER_RE.search(text))
    normalized_text = _normalize_obfuscation(text)

    deobf: list[str] = []
    obf_originals: list[str] = []
    seen: set[str] = set()

    for m in _URL_RE.finditer(normalized_text):
        url = m.group(0).strip().rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            deobf.append(url)

    for m in _HREF_RE.finditer(normalized_text):
        href = m.group(1).strip()
        if href.lower().startswith(("http://", "https://")) and href not in seen:
            seen.add(href)
            deobf.append(href)

    if had_obfuscation:
        # Capture the original-form snippets so the report can show what the analyst saw on the wire.
        for m in _OBF_MARKER_RE.finditer(text):
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 60)
            obf_originals.append(text[start:end].strip())

    return deobf, obf_originals


def extract_emails(text: str) -> list[str]:
    if not text:
        return []
    return sorted({m.group(0) for m in _EMAIL_RE.finditer(text)})


def extract_ips(text: str) -> list[str]:
    if not text:
        return []
    return sorted({m.group(0) for m in _IPV4_RE.finditer(text)})


def find_base64_blobs(text: str, *, min_decoded_size: int = 32) -> list[Base64Hit]:
    """Locate long base64-alphabet runs, attempt to decode, sniff magic bytes."""
    import hashlib

    if not text:
        return []
    hits: list[Base64Hit] = []
    for m in _BASE64_RE.finditer(text):
        blob = m.group(0)
        try:
            decoded = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < min_decoded_size:
            continue
        hits.append(
            Base64Hit(
                snippet=blob[:60] + ("..." if len(blob) > 60 else ""),
                decoded_size=len(decoded),
                magic_label=_sniff_magic(decoded),
                sha256_decoded=hashlib.sha256(decoded).hexdigest(),
            )
        )
    return hits


def extract_iocs(body_text: str = "", body_html: str = "", attachments_bytes: list[bytes] | None = None) -> IocReport:
    rep = IocReport()
    combined = (body_text or "") + "\n" + (body_html or "")

    urls, obf = extract_urls(combined)
    rep.urls = urls
    rep.obfuscated_urls = obf
    rep.emails = extract_emails(combined)
    rep.ips = extract_ips(combined)
    rep.base64_hits = find_base64_blobs(combined)

    # Also sniff magic on raw attachment bytes (already-decoded MIME parts)
    if attachments_bytes:
        import hashlib
        for raw in attachments_bytes:
            label = _sniff_magic(raw)
            if label:
                rep.base64_hits.append(
                    Base64Hit(
                        snippet="(attachment)",
                        decoded_size=len(raw),
                        magic_label=label,
                        sha256_decoded=hashlib.sha256(raw).hexdigest(),
                    )
                )
    return rep
