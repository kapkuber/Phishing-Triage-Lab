"""Recursive MIME walker. Returns one Part per leaf node in the MIME tree."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email.message import Message
from typing import Optional


@dataclass
class Part:
    path: str
    content_type: str
    charset: Optional[str]
    filename: Optional[str]
    is_attachment: bool
    size: int
    sha256: str
    payload: bytes = b""
    decoded_text: Optional[str] = None


@dataclass
class MimeReport:
    parts: list[Part] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    attachments: list[Part] = field(default_factory=list)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_text(raw: bytes, charset: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    encodings = [charset, "utf-8", "latin-1"] if charset else ["utf-8", "latin-1"]
    for enc in encodings:
        if not enc:
            continue
        try:
            return raw.decode(enc, errors="replace")
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def walk(msg: Message) -> MimeReport:
    report = MimeReport()
    # Walk the tree using the email package's iter_parts / walk; we want LEAF parts.
    counter = 0

    def visit(part: Message, path: str) -> None:
        nonlocal counter
        if part.is_multipart():
            for i, sub in enumerate(part.iter_parts()):
                visit(sub, f"{path}.{i}" if path else str(i))
            return

        ctype = part.get_content_type() or "application/octet-stream"
        charset = part.get_content_charset()
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        is_attachment = disposition == "attachment" or bool(filename)

        try:
            payload_bytes = part.get_payload(decode=True) or b""
        except Exception:
            payload_bytes = b""

        decoded_text = None
        if ctype.startswith("text/"):
            decoded_text = _decode_text(payload_bytes, charset)

        p = Part(
            path=path or "0",
            content_type=ctype,
            charset=charset,
            filename=filename,
            is_attachment=is_attachment,
            size=len(payload_bytes),
            sha256=_digest(payload_bytes),
            payload=payload_bytes,
            decoded_text=decoded_text,
        )
        report.parts.append(p)
        counter += 1

        if is_attachment:
            report.attachments.append(p)
        elif ctype == "text/plain" and not report.body_text and decoded_text:
            report.body_text = decoded_text
        elif ctype == "text/html" and not report.body_html and decoded_text:
            report.body_html = decoded_text

    visit(msg, "")
    return report
