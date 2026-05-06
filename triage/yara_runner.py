"""Compile rules/*.yar and run them across the raw .eml + each MIME body + each decoded attachment."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yara  # type: ignore[import-untyped]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    target: str           # e.g. "raw_eml", "body_text", "body_html", "attachment:invoice.bin"
    matched_strings: list[str] = field(default_factory=list)
    meta: dict[str, object] = field(default_factory=dict)


@dataclass
class YaraReport:
    matches: list[YaraMatch] = field(default_factory=list)
    rules_compiled: int = 0
    compile_errors: list[str] = field(default_factory=list)


def compile_rules(rules_dir: Path = DEFAULT_RULES_DIR) -> tuple[Optional["yara.Rules"], list[str], int]:
    """Return (compiled, errors, count). One bad rule shouldn't break the rest —
    compile each file independently and merge."""
    yar_files = sorted(rules_dir.glob("*.yar"))
    sources: dict[str, str] = {}
    errors: list[str] = []
    for path in yar_files:
        try:
            text = path.read_text(encoding="utf-8")
            # Compile in isolation to surface a useful error if syntax is broken.
            yara.compile(source=text)
        except yara.SyntaxError as e:
            errors.append(f"{path.name}: {e}")
            continue
        sources[path.stem] = text

    if not sources:
        return None, errors, 0
    try:
        compiled = yara.compile(sources=sources)
    except yara.SyntaxError as e:
        errors.append(f"merged compile failed: {e}")
        return None, errors, 0
    return compiled, errors, len(sources)


def _collect_strings(match: "yara.Match") -> list[str]:
    """yara-python's API for retrieving matched strings differs by version."""
    out: list[str] = []
    raw = getattr(match, "strings", []) or []
    for s in raw:
        # newer yara-python: StringMatch with .identifier and .instances[].matched_data
        if hasattr(s, "instances"):
            for inst in s.instances:
                data = getattr(inst, "matched_data", b"") or b""
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="replace")
                out.append(f"{s.identifier} -> {data[:80]}")
        else:
            # older yara-python: 3-tuple (offset, identifier, data)
            try:
                _, ident, data = s
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="replace")
                out.append(f"{ident} -> {data[:80]}")
            except Exception:
                out.append(str(s))
    return out


def _scan_buffer(rules: "yara.Rules", buf: bytes, target_label: str) -> list[YaraMatch]:
    if not buf:
        return []
    try:
        ms = rules.match(data=buf, timeout=10)
    except yara.Error:
        return []
    out: list[YaraMatch] = []
    for m in ms:
        out.append(
            YaraMatch(
                rule=m.rule,
                namespace=getattr(m, "namespace", ""),
                target=target_label,
                matched_strings=_collect_strings(m),
                meta=dict(getattr(m, "meta", {})),
            )
        )
    return out


def run_rules(
    raw_eml: bytes,
    body_text: str,
    body_html: str,
    attachments: Iterable[tuple[str, bytes]],
    rules_dir: Path = DEFAULT_RULES_DIR,
) -> YaraReport:
    rep = YaraReport()
    compiled, errors, count = compile_rules(rules_dir)
    rep.compile_errors = errors
    rep.rules_compiled = count
    if compiled is None:
        return rep

    rep.matches.extend(_scan_buffer(compiled, raw_eml, "raw_eml"))
    if body_text:
        rep.matches.extend(_scan_buffer(compiled, body_text.encode("utf-8", errors="replace"), "body_text"))
    if body_html:
        rep.matches.extend(_scan_buffer(compiled, body_html.encode("utf-8", errors="replace"), "body_html"))
    for name, payload in attachments:
        rep.matches.extend(_scan_buffer(compiled, payload, f"attachment:{name or 'unnamed'}"))
    return rep
