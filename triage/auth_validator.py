"""SPF / DKIM / DMARC validation.

Two modes:
1. Header-based: parse the Authentication-Results header the receiving MTA already filled in.
2. Live DNS (--live-dns): fresh TXT lookups for SPF and DMARC against the From-domain,
   to compare claims-in-headers against current published policy.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.message import Message
from typing import Optional

import dns.resolver  # type: ignore[import-untyped]


# Authentication-Results format (RFC 8601):
#   Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=foo.com;
#       dkim=fail header.d=foo.com; dmarc=pass header.from=foo.com
_RESULT_RE = re.compile(
    r"\b(?P<method>spf|dkim|dmarc|arc|dkim-atps|iprev|auth)\s*=\s*"
    r"(?P<verdict>pass|fail|softfail|neutral|policy|none|temperror|permerror)",
    re.IGNORECASE,
)


@dataclass
class AuthReport:
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    raw_results: list[str] = field(default_factory=list)
    live_spf_record: Optional[str] = None
    live_dmarc_record: Optional[str] = None
    live_notes: list[str] = field(default_factory=list)


def parse_auth_results(msg: Message) -> AuthReport:
    """Pull the SPF/DKIM/DMARC verdicts from the Authentication-Results header(s)."""
    rep = AuthReport()
    headers = msg.get_all("Authentication-Results", [])
    rep.raw_results = [h.strip() for h in headers]
    for header in headers:
        for match in _RESULT_RE.finditer(header):
            method = match.group("method").lower()
            verdict = match.group("verdict").lower()
            if method == "spf" and rep.spf is None:
                rep.spf = verdict
            elif method == "dkim" and rep.dkim is None:
                rep.dkim = verdict
            elif method == "dmarc" and rep.dmarc is None:
                rep.dmarc = verdict
    return rep


def _txt_lookup(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5.0)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    out: list[str] = []
    for rdata in answers:
        # dnspython returns each TXT record as a list of bytes-strings, joined per record.
        joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
        out.append(joined)
    return out


def live_dns_check(domain: str) -> tuple[Optional[str], Optional[str], list[str]]:
    """Fresh SPF + DMARC TXT lookup. Returns (spf_record, dmarc_record, notes)."""
    notes: list[str] = []
    if not domain:
        return None, None, ["empty domain — skipped live DNS"]

    spf_records = [r for r in _txt_lookup(domain) if r.lower().startswith("v=spf1")]
    spf_record = spf_records[0] if spf_records else None
    if not spf_record:
        notes.append(f"no v=spf1 TXT record on {domain}")

    dmarc_records = [r for r in _txt_lookup(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    dmarc_record = dmarc_records[0] if dmarc_records else None
    if not dmarc_record:
        notes.append(f"no v=DMARC1 TXT record on _dmarc.{domain}")

    return spf_record, dmarc_record, notes


def validate(msg: Message, *, live_dns: bool = False, from_domain: str = "") -> AuthReport:
    rep = parse_auth_results(msg)
    if live_dns:
        spf, dmarc, notes = live_dns_check(from_domain)
        rep.live_spf_record = spf
        rep.live_dmarc_record = dmarc
        rep.live_notes = notes
    return rep
