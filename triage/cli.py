"""Phishing-triage CLI.

Usage:
    python -m triage <path/to/sample.eml> [--live-dns] [--phishtank] [--urlscan] [--yara] [--report-md]
"""
from __future__ import annotations

import argparse
import io
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Optional

# On Windows, default stdout is cp1252 which chokes on rich's unicode box-drawing.
# Reconfigure to UTF-8 before rich initializes its console.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, io.UnsupportedOperation):
        pass

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from triage.auth_validator import validate as auth_validate
from triage.header_parser import HeaderReport, parse_headers
from triage.mime_walker import walk
from triage.payload_extractor import extract_iocs
from triage.phishtank_client import PhishtankClient, PhishtankLookup
from triage.spoof_detector import analyze as spoof_analyze
from triage.urlscan_client import UrlscanClient, UrlscanResult
from triage.yara_runner import run_rules

console = Console()


def _load_msg(path: Path):
    with path.open("rb") as f:
        return BytesParser(policy=policy.default).parse(f), path.read_bytes()


def _verdict_color(v: Optional[str]) -> str:
    return {
        "pass": "green",
        "fail": "red",
        "softfail": "yellow",
        "neutral": "yellow",
        "none": "yellow",
        None: "dim",
    }.get(v, "white")


def render_terminal(
    sample: Path,
    headers: HeaderReport,
    auth,
    mime,
    spoof,
    iocs,
    yara_rep=None,
    phishtank_results: Optional[list[PhishtankLookup]] = None,
    urlscan_results: Optional[list[UrlscanResult]] = None,
) -> None:
    console.rule(f"[bold]Phishing Triage[/] — {sample.name}")

    # Headers
    t = Table(show_header=False, box=None, pad_edge=False)
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column()
    t.add_row("From", f"{headers.from_display} <{headers.from_addr}>")
    t.add_row("Reply-To", headers.reply_to or "[dim]—[/dim]")
    t.add_row("Return-Path", headers.return_path or "[dim]—[/dim]")
    t.add_row("Subject", headers.subject or "[dim]—[/dim]")
    t.add_row("Date", headers.date or "[dim]—[/dim]")
    t.add_row("Message-ID", headers.message_id or "[dim]—[/dim]")
    t.add_row("Originating IP", f"[bold red]{headers.originating_ip}[/]" if headers.originating_ip else "[dim]not found[/dim]")
    console.print(Panel(t, title="Headers", border_style="cyan"))

    if headers.divergence_flags:
        console.print(Panel("\n".join(f"• {f}" for f in headers.divergence_flags), title="Address Divergence", border_style="yellow"))

    # Received chain
    rt = Table(title="Received chain (origin -> recipient)", show_lines=False)
    rt.add_column("#")
    rt.add_column("IP")
    rt.add_column("Class")
    for hop in headers.received_chain:
        cls = "global" if hop.is_global else ("private" if hop.is_private else ("loopback" if hop.is_loopback else "?"))
        cls_color = "red" if cls == "global" else "dim"
        rt.add_row(str(hop.index), hop.ip or "[dim]—[/dim]", f"[{cls_color}]{cls}[/]")
    console.print(rt)

    # Auth
    at = Table(title="Authentication", show_header=True)
    at.add_column("Method")
    at.add_column("Header verdict")
    for method, val in [("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)]:
        at.add_row(method, Text(val or "—", style=_verdict_color(val)))
    console.print(at)
    if auth.live_spf_record or auth.live_dmarc_record or auth.live_notes:
        live_lines = []
        if auth.live_spf_record:
            live_lines.append(f"[green]SPF[/]: {auth.live_spf_record}")
        if auth.live_dmarc_record:
            live_lines.append(f"[green]DMARC[/]: {auth.live_dmarc_record}")
        for n in auth.live_notes:
            live_lines.append(f"[yellow]note[/]: {n}")
        console.print(Panel("\n".join(live_lines), title="Live DNS lookup", border_style="green"))

    # MIME tree
    mt = Table(title="MIME parts")
    mt.add_column("Path")
    mt.add_column("Content-Type")
    mt.add_column("Filename")
    mt.add_column("Size")
    mt.add_column("SHA-256 (12)")
    for p in mime.parts:
        mt.add_row(p.path, p.content_type, p.filename or "—", str(p.size), p.sha256[:12])
    console.print(mt)

    # Spoof findings
    if spoof.findings:
        st = Table(title="Spoof / impersonation findings")
        st.add_column("Kind")
        st.add_column("Token / domain")
        st.add_column("Brand")
        st.add_column("Detail")
        st.add_column("Source URL")
        for f in spoof.findings:
            st.add_row(f.kind, f.domain, f.target_brand or "—", f.detail, f.source_url or "—")
        console.print(st)

    # IOCs
    ioc_lines = []
    if iocs.urls:
        ioc_lines.append("[bold]URLs:[/]")
        ioc_lines.extend(f"  • {u}" for u in iocs.urls)
    if iocs.obfuscated_urls:
        ioc_lines.append("[bold yellow]Obfuscation observed in source[/]")
    if iocs.emails:
        ioc_lines.append(f"[bold]Email addresses:[/] {', '.join(iocs.emails)}")
    if iocs.ips:
        ioc_lines.append(f"[bold]IPs in body:[/] {', '.join(iocs.ips)}")
    if iocs.base64_hits:
        ioc_lines.append("[bold]Base64 / payload hits:[/]")
        for h in iocs.base64_hits:
            ioc_lines.append(f"  • {h.magic_label or 'unknown magic'} — decoded {h.decoded_size}B — sha256={h.sha256_decoded[:12]}")
    if ioc_lines:
        console.print(Panel("\n".join(ioc_lines), title="IOCs", border_style="magenta"))

    # YARA
    if yara_rep:
        if yara_rep.compile_errors:
            console.print(Panel("\n".join(yara_rep.compile_errors), title="[red]YARA compile errors", border_style="red"))
        yt = Table(title=f"YARA matches ({yara_rep.rules_compiled} rules loaded)")
        yt.add_column("Rule")
        yt.add_column("Severity")
        yt.add_column("Target")
        yt.add_column("Strings")
        for m in yara_rep.matches:
            sev = str(m.meta.get("severity", "—"))
            yt.add_row(m.rule, sev, m.target, "; ".join(m.matched_strings[:3]))
        console.print(yt)

    # PhishTank
    if phishtank_results:
        pt = Table(title="PhishTank cross-reference (via public mirror)")
        pt.add_column("URL")
        pt.add_column("Known phish?")
        pt.add_column("Source")
        for r in phishtank_results:
            pt.add_row(r.url, "[red]yes[/]" if r.known_phish else "[dim]no[/]", r.source_file or "—")
        console.print(pt)

    # urlscan
    if urlscan_results:
        ut = Table(title="urlscan.io submissions")
        ut.add_column("URL")
        ut.add_column("Verdict")
        ut.add_column("Score")
        ut.add_column("Result page")
        for r in urlscan_results:
            ut.add_row(
                r.url,
                Text(r.verdict or "—", style="red" if r.verdict == "malicious" else ("yellow" if r.verdict == "suspicious" else "white")),
                str(r.score) if r.score is not None else "—",
                r.page_url or (r.error or "—"),
            )
        console.print(ut)


def render_markdown(
    sample: Path,
    headers: HeaderReport,
    auth,
    mime,
    spoof,
    iocs,
    yara_rep=None,
    phishtank_results: Optional[list[PhishtankLookup]] = None,
    urlscan_results: Optional[list[UrlscanResult]] = None,
) -> str:
    out: list[str] = []
    out.append(f"# Phishing Triage Report — `{sample.name}`\n")
    out.append("## Headers\n")
    out.append("| Field | Value |")
    out.append("|---|---|")
    out.append(f"| From | `{headers.from_display}` <{headers.from_addr}> |")
    out.append(f"| Reply-To | `{headers.reply_to or '—'}` |")
    out.append(f"| Return-Path | `{headers.return_path or '—'}` |")
    out.append(f"| Subject | {headers.subject or '—'} |")
    out.append(f"| Date | {headers.date or '—'} |")
    out.append(f"| Message-ID | `{headers.message_id or '—'}` |")
    out.append(f"| Originating IP | **{headers.originating_ip or 'not found'}** |")
    out.append("")

    if headers.divergence_flags:
        out.append("### Address divergence\n")
        for f in headers.divergence_flags:
            out.append(f"- {f}")
        out.append("")

    out.append("### Received chain\n")
    out.append("| # | IP | Class |")
    out.append("|---|---|---|")
    for hop in headers.received_chain:
        cls = "global" if hop.is_global else ("private" if hop.is_private else ("loopback" if hop.is_loopback else "?"))
        out.append(f"| {hop.index} | `{hop.ip or '—'}` | {cls} |")
    out.append("")

    out.append("## Authentication\n")
    out.append(f"- **SPF:** `{auth.spf or '—'}`")
    out.append(f"- **DKIM:** `{auth.dkim or '—'}`")
    out.append(f"- **DMARC:** `{auth.dmarc or '—'}`")
    if auth.live_spf_record or auth.live_dmarc_record or auth.live_notes:
        out.append("\n### Live DNS\n")
        if auth.live_spf_record:
            out.append(f"- SPF record: `{auth.live_spf_record}`")
        if auth.live_dmarc_record:
            out.append(f"- DMARC record: `{auth.live_dmarc_record}`")
        for n in auth.live_notes:
            out.append(f"- _Note: {n}_")
    out.append("")

    out.append("## MIME structure\n")
    out.append("| Path | Content-Type | Filename | Size | SHA-256 |")
    out.append("|---|---|---|---|---|")
    for p in mime.parts:
        out.append(f"| {p.path} | `{p.content_type}` | `{p.filename or '—'}` | {p.size} | `{p.sha256}` |")
    out.append("")

    if spoof.findings:
        out.append("## Spoof / impersonation findings\n")
        for f in spoof.findings:
            line = f"- **{f.kind}** — `{f.domain}` (target: `{f.target_brand or '—'}`) — {f.detail}"
            if f.source_url:
                line += f" — source URL: `{f.source_url}`"
            out.append(line)
        out.append("")

    out.append("## IOCs\n")
    if iocs.urls:
        out.append("**URLs:**")
        for u in iocs.urls:
            out.append(f"- `{u}`")
    if iocs.obfuscated_urls:
        out.append("\n_Obfuscated URLs were observed in source (e.g. `hxxp`, `[.]`)._")
    if iocs.emails:
        out.append(f"\n**Email addresses:** {', '.join(f'`{e}`' for e in iocs.emails)}")
    if iocs.ips:
        out.append(f"\n**IPs in body:** {', '.join(f'`{i}`' for i in iocs.ips)}")
    if iocs.base64_hits:
        out.append("\n**Payload / base64 hits:**")
        for h in iocs.base64_hits:
            out.append(f"- {h.magic_label or 'unknown magic'} — decoded {h.decoded_size} bytes — sha256 `{h.sha256_decoded}`")
    out.append("")

    if yara_rep is not None:
        out.append(f"## YARA matches ({yara_rep.rules_compiled} rules loaded)\n")
        if yara_rep.compile_errors:
            out.append("> ⚠ Compile errors:")
            for e in yara_rep.compile_errors:
                out.append(f"> - {e}")
        if yara_rep.matches:
            out.append("| Rule | Severity | Target | Matched strings |")
            out.append("|---|---|---|---|")
            for m in yara_rep.matches:
                sev = str(m.meta.get("severity", "—"))
                strs = "; ".join(s.replace("|", "\\|") for s in m.matched_strings[:3])
                out.append(f"| `{m.rule}` | {sev} | `{m.target}` | {strs} |")
        else:
            out.append("_No YARA hits._")
        out.append("")

    if phishtank_results:
        out.append("## PhishTank cross-reference (Phishing.Database mirror)\n")
        out.append("| URL | Known phish? |")
        out.append("|---|---|")
        for r in phishtank_results:
            out.append(f"| `{r.url}` | {'**yes**' if r.known_phish else 'no'} |")
        out.append("")
        out.append("_Manual phishtank.org/phish_search.php lookup result:_ TODO: paste link + screenshot reference here.\n")

    if urlscan_results:
        out.append("## urlscan.io\n")
        out.append("| URL | Verdict | Score | Result |")
        out.append("|---|---|---|---|")
        for r in urlscan_results:
            out.append(f"| `{r.url}` | {r.verdict or '—'} | {r.score if r.score is not None else '—'} | {r.page_url or r.error or '—'} |")
        out.append("")

    out.append("## CyberChef Analysis\n")
    out.append("TODO: paste at least one CyberChef recipe URL used during analysis. See `docs/CYBERCHEF_RECIPES.md` for reusable starters.\n")

    out.append("## Analyst commentary\n")
    out.append("TODO: 1-2 paragraphs on what this sample is, who it impersonates, what the kill-chain looks like, and what the most reliable detection signal would be in production.\n")

    return "\n".join(out)


def main(argv: Optional[list[str]] = None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Triage a phishing email sample (.eml)")
    parser.add_argument("sample", type=Path, help="path to .eml file")
    parser.add_argument("--live-dns", action="store_true", help="fresh SPF/DMARC TXT lookup")
    parser.add_argument("--phishtank", action="store_true", help="cross-reference URLs against PhishTank mirror")
    parser.add_argument("--urlscan", action="store_true", help="submit URLs to urlscan.io")
    parser.add_argument("--yara", action="store_true", help="apply rules/*.yar")
    parser.add_argument("--report-md", action="store_true", help="emit markdown to stdout instead of pretty terminal")
    args = parser.parse_args(argv)

    if not args.sample.exists():
        console.print(f"[red]not found:[/] {args.sample}")
        return 2

    msg, raw = _load_msg(args.sample)
    headers = parse_headers(msg)
    auth = auth_validate(msg, live_dns=args.live_dns, from_domain=headers.from_domain)
    mime = walk(msg)
    iocs = extract_iocs(
        body_text=mime.body_text,
        body_html=mime.body_html,
        attachments_bytes=[a.payload for a in mime.attachments],
    )
    spoof = spoof_analyze(headers.from_display, headers.from_domain, urls=iocs.urls)

    yara_rep = None
    if args.yara:
        yara_rep = run_rules(
            raw_eml=raw,
            body_text=mime.body_text,
            body_html=mime.body_html,
            attachments=[(a.filename or "", a.payload) for a in mime.attachments],
        )

    phishtank_results: list[PhishtankLookup] = []
    if args.phishtank and iocs.urls:
        client = PhishtankClient()
        ok, err = client.refresh()
        if not ok:
            console.print(f"[yellow]PhishTank refresh failed:[/] {err}")
        for u in iocs.urls:
            phishtank_results.append(client.lookup(u))

    urlscan_results: list[UrlscanResult] = []
    if args.urlscan and iocs.urls:
        uc = UrlscanClient()
        for u in iocs.urls[:5]:  # cap at 5 per email to stay polite
            urlscan_results.append(uc.submit_and_fetch(u))

    if args.report_md:
        print(render_markdown(args.sample, headers, auth, mime, spoof, iocs, yara_rep, phishtank_results, urlscan_results))
    else:
        render_terminal(args.sample, headers, auth, mime, spoof, iocs, yara_rep, phishtank_results, urlscan_results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
