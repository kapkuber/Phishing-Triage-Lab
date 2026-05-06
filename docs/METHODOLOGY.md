# Methodology

The triage workflow this project implements, end-to-end. Each step maps to a module under `triage/` and to a section of the per-sample report.

## 1. Acquire the sample

`samples/emails/` is populated by `python scripts/fetch_samples.py --count <N>`, which shallow-clones [`rf-peixoto/phishing_pot`](https://github.com/rf-peixoto/phishing_pot) into a temp directory and copies a randomized subset (seeded for reproducibility) of `.eml` files in. The corpus is MIT-licensed; we don't redistribute it.

For deep-dive reports, samples are hand-picked to cover diverse phishing categories (BEC / exec impersonation, credential phish, lookalike-domain, base64 payload, broken auth).

## 2. Parse SMTP headers

[`triage/header_parser.py`](../triage/header_parser.py) does three things:

- **Received-chain walk.** Email convention: each MTA *prepends* its own `Received:` header, so the bottom-most header is the first hop. We reverse the header list so index 0 == origin and index N == final delivery.
- **Originating-IP extraction.** For each hop we extract the IP, classify it (`is_global` vs private vs loopback) using stdlib `ipaddress`, and pick the first globally-routable IP encountered walking from origin towards recipient. RFC 5737 documentation ranges (198.51.100/24, 203.0.113/24) are intentionally classified as non-global so synthetic test addresses aren't mistaken for routable origins.
- **Address divergence.** Compare `From`, `Reply-To`, and `Return-Path`. Domain-level divergence is one of the highest-precision phishing signals — legitimate senders almost never split these.

## 3. Validate authentication

[`triage/auth_validator.py`](../triage/auth_validator.py) supports two modes:

- **Header-based** (default): parse the `Authentication-Results` header the receiving MTA filled in. Returns the SPF / DKIM / DMARC verdict per RFC 8601.
- **Live DNS** (`--live-dns`): pull the current SPF and DMARC TXT records for the From-domain via `dnspython` and compare against what the headers claimed. This catches "cousin domains" — a phisher's from-domain that has its own validly-aligned SPF/DMARC, which is `pass` in headers but obviously suspicious when you see it has no MX history and was registered last week.

## 4. Walk MIME structure

[`triage/mime_walker.py`](../triage/mime_walker.py) does a depth-first walk of the message tree, returning a `Part` per leaf with content-type, charset, filename, size, SHA-256, and decoded payload bytes. `text/plain` and `text/html` body parts are pulled out separately; everything with a `Content-Disposition: attachment` (or any filename) is treated as an attachment.

## 5. Extract IOCs

[`triage/payload_extractor.py`](../triage/payload_extractor.py) produces a per-sample IOC report:

- **URLs** — including obfuscated forms. Before regex matching we deobfuscate the entire body: `hxxp` → `http`, `[.]` → `.`, `[dot]` → `.`, etc. We also extract `href=` URLs from HTML, because URLs in `<a>` tags often differ from the visible text.
- **Email addresses** — for Reply-To capture and pivoting.
- **Embedded IPs** — uncommon in legit mail, common in phishing kits that hardcode their callback infra.
- **Base64 payloads** — any ≥40-char base64-alphabet run is decoded and the first bytes are sniffed against a magic-byte table (MZ, PK, %PDF, etc.). Same sniffer also runs on already-decoded MIME attachment bytes.

## 6. Spoof / impersonation detection

[`triage/spoof_detector.py`](../triage/spoof_detector.py):

- **Executive impersonation** — regex over the From `display-name` for a list of executive titles (CEO, CFO, COO, CTO, CISO, President, VP, Director, Head of …, Chief … Officer, Chairman, Owner, Founder, General Counsel). If a title matches and the From-domain isn't on the org's `triage/data/known_domains.txt` allowlist, we flag it.
- **Lookalike domains** — three checks against `triage/data/protected_brands.txt`, applied to both the From-domain *and* every URL extracted from the body:
  1. **Homoglyph** — substitute `0`↔`o`, `1`↔`l`, `rn`↔`m`, etc. and check exact match. Catches `micros0ft.com`, `paypa1.com`, `rnicrosoft.com`.
  2. **Levenshtein distance** ≤ 2 via `rapidfuzz`. Catches `paypall.com`, `microoft.com`, `dropbx.com`.
  3. **TLD swap** on suspicious TLDs — same registrable label but the TLD has been swapped for one over-represented in phishing (`.tk`, `.top`, `.xyz`, `.click`, `.zip`, `.mov`, `.ml`, …).
- **Lookalike-in-URL** — same homoglyph + Levenshtein logic, applied to every URL's host registrable label, every subdomain label, and every alphanumeric path segment of length 5-30. Catches the case where a phisher hosts brand-typosquat content on a *legitimate* cloud bucket — e.g. `storage.googleapis.com/office356/work.html` (real sample, sample-3026 in the corpus). The from-domain check would miss this; the URL check flags it as a Levenshtein-2 hit on the path token `office356` against `office365`.

## 7. YARA rules

Five rule files in `rules/`:

| File | Targets | Notes |
|---|---|---|
| `exec_impersonation.yar` | body language | Worked example with annotated structure |
| `lookalike_domains.yar` | raw `.eml` body | Literal-string rule; extend with patterns from real samples |
| `base64_payloads.yar` | body + raw `.eml` | Hits base64-encoded magic-byte prefixes (PE, ZIP, PDF) without decoding |
| `credential_phish.yar` | body + body HTML | Login/auth lure language paired with brand keywords |
| `suspicious_attachments.yar` | raw `.eml` | Filename + double-extension patterns in `Content-Disposition` |

Rules are scanned against four buffers per sample (raw `.eml`, body text, body HTML, each decoded attachment) so a rule can target whichever surface makes sense for it.

## 8. Enrichment

- **PhishTank** (`--phishtank`) — see [PHISHTANK_NOTE.md](PHISHTANK_NOTE.md). Programmatic lookup against the Phishing.Database public mirror; manual lookup at `phishtank.org/phish_search.php` for the deep-dive cases.
- **urlscan.io** (`--urlscan`) — submit each extracted URL with `visibility=unlisted`, poll the result endpoint, capture verdict + score + screenshot URL + result page URL. Cached on disk by URL hash so re-runs don't re-submit.

## 9. CyberChef

For each deep-dive, at least one [CyberChef](https://gchq.github.io/CyberChef/) recipe URL is captured in the report. See [CYBERCHEF_RECIPES.md](CYBERCHEF_RECIPES.md) for the reusable starters.

## 10. Report

`python -m triage <sample> --report-md > reports/sample_NN_<title>.md` produces a markdown report following [`reports/_template.md`](../reports/_template.md). The CyberChef recipe URL, the manual phishtank.org lookup link/screenshot, and the analyst commentary are then hand-edited in.

## What this tool deliberately doesn't do

- **No active payload detonation.** Base64 blobs are decoded only enough to sniff magic bytes; nothing is executed.
- **No sandbox / VirusTotal hash submission.** Could be added, but out of scope for the resume bullet.
- **No mailbox integration.** Triage is per-file; a real production deployment would wire this into IMAP / Microsoft Graph / Gmail API.
- **No ML.** Detection is rule- and regex-based — interview-defensible, deterministic, and easy to tune. ML on phishing is a separate, much larger problem.
