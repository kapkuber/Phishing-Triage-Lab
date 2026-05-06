"""SMTP header dissection: Received-chain walk, originating IP extraction, address divergence."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Optional

# Captures both IPv4 and IPv6 addresses from a Received header.
# Received headers don't have a fixed format, but the IP almost always sits inside
# square brackets or parentheses near the "from" host token.
_IP_RE = re.compile(
    r"\[?"
    r"(?P<ip>"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"(?:[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+)"
    r")"
    r"\]?"
)


@dataclass
class Hop:
    index: int
    raw: str
    ip: Optional[str] = None
    is_private: bool = False
    is_loopback: bool = False
    is_global: bool = False


@dataclass
class HeaderReport:
    from_addr: str = ""
    from_display: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_chain: list[Hop] = field(default_factory=list)
    originating_ip: Optional[str] = None
    divergence_flags: list[str] = field(default_factory=list)


def _classify_ip(ip_str: str) -> tuple[bool, bool, bool]:
    """Returns (is_private, is_loopback, is_global). is_global=True only for
    globally-routable addresses — excludes RFC 1918, loopback, link-local,
    multicast, and the RFC 5737 documentation ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, False, False
    return ip.is_private, ip.is_loopback, ip.is_global


def parse_received_chain(msg: Message) -> list[Hop]:
    """Walk Received headers in chronological order (last header = first hop = most recent).

    Email convention: each MTA prepends its Received header, so the *bottom* of the list
    is the originating sender. We reverse the header list so index 0 == origin.
    """
    raw_headers = msg.get_all("Received", [])
    hops: list[Hop] = []
    for i, raw in enumerate(reversed(raw_headers)):
        ip = None
        for match in _IP_RE.finditer(raw):
            candidate = match.group("ip")
            try:
                ipaddress.ip_address(candidate)
                ip = candidate
                break
            except ValueError:
                continue
        priv, loop, glob = _classify_ip(ip) if ip else (False, False, False)
        hops.append(Hop(index=i, raw=raw.strip(), ip=ip, is_private=priv, is_loopback=loop, is_global=glob))
    return hops


def find_originating_ip(hops: list[Hop]) -> Optional[str]:
    """First globally-routable IP encountered walking from origin towards recipient."""
    for hop in hops:
        if hop.ip and hop.is_global:
            return hop.ip
    return None


def _domain_of(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower().strip(">")


def detect_address_divergence(msg: Message) -> tuple[list[str], dict[str, str]]:
    """Compare From/Reply-To/Return-Path. Mismatches are a classic phishing tell."""
    from_name, from_addr = parseaddr(msg.get("From", ""))
    reply_to_addr = parseaddr(msg.get("Reply-To", ""))[1]
    return_path_addr = parseaddr(msg.get("Return-Path", ""))[1]

    flags: list[str] = []
    from_dom = _domain_of(from_addr)
    if reply_to_addr:
        reply_dom = _domain_of(reply_to_addr)
        if reply_dom and reply_dom != from_dom:
            flags.append(f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom})")
    if return_path_addr:
        rp_dom = _domain_of(return_path_addr)
        if rp_dom and rp_dom != from_dom:
            flags.append(f"Return-Path domain ({rp_dom}) differs from From domain ({from_dom})")

    addrs = {
        "from": from_addr,
        "from_display": from_name,
        "from_domain": from_dom,
        "reply_to": reply_to_addr,
        "return_path": return_path_addr,
    }
    return flags, addrs


def parse_headers(msg: Message) -> HeaderReport:
    hops = parse_received_chain(msg)
    flags, addrs = detect_address_divergence(msg)
    return HeaderReport(
        from_addr=addrs["from"],
        from_display=addrs["from_display"],
        from_domain=addrs["from_domain"],
        reply_to=addrs["reply_to"],
        return_path=addrs["return_path"],
        subject=msg.get("Subject", "").strip(),
        date=msg.get("Date", "").strip(),
        message_id=msg.get("Message-ID", "").strip(),
        received_chain=hops,
        originating_ip=find_originating_ip(hops),
        divergence_flags=flags,
    )
