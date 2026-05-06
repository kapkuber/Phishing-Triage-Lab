# Sample 03 — Bitcoin "mining transaction" scam with weaponised PDF

**Source file:** `samples/emails/sample-182.eml`
**Category:** crypto scam, attachment-based attack (PDF lure)
**Captured:** 2022-12-25

---

## Headers

| Field | Value |
|---|---|
| From | `Kristle Harutunian` <rasezvah@gmail.com> |
| Reply-To | _(none)_ |
| Return-Path | `rasezvah@gmail.com` |
| Subject | `Mining_transaction_0.7495_BTC` |
| Date | Sun, 25 Dec 2022 14:05:05 -0800 |
| Message-ID | `<CAP_x_icBC3NCC3n=-5E9WPAgXDUL_RoPc+ornXJkSVwQQge7NA@mail.gmail.com>` |
| Originating IP | **209.85.167.46** _(Google LLC, mail-oi1)_ |

### Received chain

| # | IP | Class |
|---|---|---|
| 0 | `2002:a05:6504:16d6:b0:203:671c:d426` | private (6to4 relay) |
| 1 | _(internal)_ | ? |
| 2 | `209.85.167.46` | global |
| 3 | `2603:10b6:5:3af:cafe::36` | global |
| 4 | `2603:10b6:5:3af::21` | global |
| 5 | _(final delivery, no IP)_ | ? |

## Authentication

- **SPF:** `pass`
- **DKIM:** `pass`
- **DMARC:** `pass`

### Live DNS comparison

- SPF record: `v=spf1 redirect=_spf.google.com`
- DMARC record: `v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com`

> **Analyst note.** Same authentication-passes-but-content-is-malicious pattern as sample 01: a real Gmail account sending a real DMARC-aligned email. Trust signals from the auth layer are useless here.

## MIME structure

| Path | Content-Type | Filename | Size | SHA-256 |
|---|---|---|---|---|
| 0 | `text/plain` | _(none)_ | 73 | `687dd4c94410ae1d0d65da2a2ef24c7622ad3630019ddd4ef632f5a0c6ecd2ee` |
| 1 | `application/pdf` | `Your_transaction_0.7495_Bitcoin_4zpOPPJ9Dk.pdf` | 84,543 | `91f9e6d3dee91a57b25f85c54bbfd76d89f7616837ed82e2e0e557a78326481a` |

The 73-byte body is just a one-liner; the entire attack lives in the PDF.

## Spoof / impersonation findings

_None._ No display-name spoofing, no lookalike domain — the social-engineering vector is entirely the subject + filename "look like a real BTC transaction confirmation."

## IOCs

**URLs (in body):** _none._
**Email addresses:** _(only the sender's own)_
**Payload / base64 hits:**
- PDF document — decoded **84,543 bytes** — sha256 `91f9e6d3dee91a57b25f85c54bbfd76d89f7616837ed82e2e0e557a78326481a`

The PDF is the entire IOC surface. A defender's downstream pipeline would extract URLs, JavaScript actions, and embedded objects from the PDF body — out of scope for header/MIME triage but the natural next step.

## YARA matches

| Rule | Severity | Target | Strings |
|---|---|---|---|
| `crypto_payout_lure` | high | `raw_eml` | `$mining_transaction -> Mining_transaction` |
| `pdf_with_finance_lure` | medium | `raw_eml` | `$pdf_bitcoin -> filename="Your_transaction_0.7495_Bitcoin_4zpOPPJ9Dk.pdf"`; `$pdf_transaction -> filename="…transaction…pdf"` |
| `base64_pdf_document` | medium | `raw_eml` | `$b64_pdf -> JVBERi` |

Three rules fire from three orthogonal angles: subject keyword (`crypto_payout_lure`), attachment filename pattern (`pdf_with_finance_lure`), and detection of the `%PDF` magic-byte sequence in the base64-encoded MIME part (`base64_pdf_document`). High signal redundancy.

## PhishTank cross-reference

**Programmatic (Phishing.Database mirror):** no URLs to look up.

**Manual phishtank.org lookup:** N/A — no URLs. PhishTank doesn't index attachments.

For attachment-based threats, the equivalent enrichment is VirusTotal hash lookup. Hash to query: [`91f9e6d3dee91a57b25f85c54bbfd76d89f7616837ed82e2e0e557a78326481a`](https://www.virustotal.com/gui/file/91f9e6d3dee91a57b25f85c54bbfd76d89f7616837ed82e2e0e557a78326481a). _(Manual step — VirusTotal integration is out of scope for this project.)_

## urlscan.io

_(N/A — no URLs in body.)_

## CyberChef Analysis

**Recipe:** [Magic byte detection](https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''))

**Input:** the first 256 bytes of the decoded attachment payload (already a `%PDF-1.x` header in our pipeline).

**What it told us.** Confirms the file actually is a PDF (not a renamed PE/Office doc). The triage tool already sniffed this via the magic-byte table; CyberChef's Magic operation cross-validates and would also catch nested formats (e.g. PDF wrapping an embedded executable via JavaScript).

A second useful recipe for PDF-themed phishing: [Extract URLs](https://gchq.github.io/CyberChef/#recipe=Extract_URLs(true)) run over the decoded PDF stream contents would surface any callback URLs the PDF triggers when opened. _(Not run live — analysing PDF object streams is a deeper step than this triage tool covers.)_

## Analyst commentary

**What this is.** A "you have a Bitcoin transaction waiting" scam, sent from a real Gmail account, with the entire payload delivered as a PDF. The PDF's filename and the email subject both encode a specific BTC amount (`0.7495`) — high enough to seem real but low enough that a recipient might believe a stranger casually sent it. Inside the PDF (out of scope for this header-and-MIME tool but worth noting) the typical kit pattern is: text claiming a wallet address has been credited, a "Continue" button, and a JavaScript or annotation action that opens a credential-harvest URL when the button is clicked.

**Kill chain.** Recipient sees subject `Mining_transaction_0.7495_BTC`, opens the PDF expecting a wallet receipt, clicks an embedded action → external URL fires → wallet credentials or seed-phrase entry. The PDF wrapper exists specifically because mail-gateway URL filters can't see inside PDFs without object-stream parsing.

**Most reliable production detection signal.** For this category, three signals stack:
1. **Attachment filename keyword regex.** `pdf_with_finance_lure` catches `bitcoin|btc|transaction|invoice|wire` + `.pdf`. High precision — legit financial PDFs come with attachment-name conventions specific to the issuing bank/processor, not these generic words.
2. **Free-mailbox sender + financial subject line.** Same shape as sample 01: gmail.com + "Mining_transaction" subject = high confidence even before the PDF is opened.
3. **PDF size class + zero body URLs.** A standalone-PDF phish almost always has a near-empty text body. Combine with #1 and #2 for a strong rule.

**What the tool missed.** Nothing in scope. The PDF payload itself is not analyzed — that's a downstream sandbox / static-analysis job (e.g. `peepdf`, `pdfid.py`) and is the obvious next step.
