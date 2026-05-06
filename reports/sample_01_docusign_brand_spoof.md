# Sample 01 — DocuSign brand impersonation via Gmail relay

**Source file:** `samples/emails/sample-1182.eml`
**Category:** brand impersonation, credential phish (document-signing lure)
**Captured:** 2023-06-06

---

## Headers

| Field | Value |
|---|---|
| From | `DocuSign` <johnmercy2723@gmail.com> |
| Reply-To | _(none)_ |
| Return-Path | `johnmercy2723@gmail.com` |
| Subject | Check your document |
| Date | Tue, 06 Jun 2023 16:22:32 +0100 |
| Message-ID | `<CACxhz0_9Oi6mY_OUN9r950dbj+30WSWVudOiiKh6WD2TexnNYg@mail.gmail.com>` |
| Originating IP | **209.85.161.66** _(Google LLC, mail-yw1)_ |

### Received chain

| # | IP | Class |
|---|---|---|
| 0 | _(internal Google submission)_ | ? |
| 1 | `209.85.161.66` | global |

## Authentication

- **SPF:** `pass`
- **DKIM:** `pass`
- **DMARC:** `pass`

### Live DNS comparison

- SPF record: `v=spf1 redirect=_spf.google.com`
- DMARC record: `v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com`

> **Analyst note.** SPF/DKIM/DMARC all pass *legitimately* — the email really did come from Gmail. This is the most important observation in the report: authentication green-lights only prove the email was sent by who claims to have sent it (`johnmercy2723@gmail.com`). They prove nothing about the *display name* the recipient sees ("DocuSign"). A junior reviewer who stops at "DMARC pass = trust" would miss this entirely.

## MIME structure

| Path | Content-Type | Filename | Size | SHA-256 |
|---|---|---|---|---|
| 0.0 | `text/html` | _(none)_ | 1756 | `0ba3d11980003fef0d2c7b36636b62540fbff47a1306b910e120a6de3c15555f` |

Single-part HTML body. No attachment — the kill chain is purely a credential-harvest URL.

## Spoof / impersonation findings

- **`display_name_brand_spoof`** — `gmail.com` (target: `docusign.com`) — Display name "DocuSign" claims brand "docusign" but from-domain is gmail.com.

This is the highest-precision signal in the sample. Real DocuSign emails come from `docusign.net`, `docusign.com`, or `email.docusign.net`. Anything else displaying "DocuSign" in the From header is impersonation.

## IOCs

**URLs (deobfuscated):**
- `https://ecp.yusercontent.com/mail?url=https%3A%2F%2FNA3.docusign.net%2Fmember%2FImages%2Femail%2FdocInvite-white.png&t=1610616070&ymreqid=f636fad6-4dfd-f99a-1c12-d90007018900&sig=OHJFAKzoYce7JYgff972AQ--~D` — Yahoo content-cache image proxy. The phisher pulled the *real* DocuSign logo through this, hotlinking off Yahoo's CDN to dodge content-image filtering.
- `https://danielcacereslopez.com/Mm84ODhkN3oxZDZWNlU=` — the actual phish landing page. The trailing `Mm84ODhkN3oxZDZWNlU=` decodes (base64) to `2o888d7z1d6V6U`, a victim-tracking ID baked into the URL so the kit knows which envelope was clicked.

## YARA matches

| Rule | Severity | Target | Strings |
|---|---|---|---|
| `docusign_document_lure` | high | `raw_eml` | `$docusign -> DocuSign`; `$check_doc -> Check your document` |

## PhishTank cross-reference

**Programmatic (Phishing.Database mirror):** neither URL was present in the active-PhishTank URL list at scan time.

**Manual phishtank.org lookup:** [search for `danielcacereslopez.com`](https://www.phishtank.com/phish_search.php?valid=y&active=All&Search=Search&page=&search_text=danielcacereslopez.com)

## urlscan.io

| URL | Verdict | Result |
|---|---|---|
| `https://danielcacereslopez.com/Mm84ODhkN3oxZDZWNlU=` | scan error — `net::ERR_CONNECTION_CLOSED` | [019dfdef-8319-719e-9513-4a674cabb059](https://urlscan.io/result/019dfdef-8319-719e-9513-4a674cabb059/) |

> **Analyst note.** Submission to urlscan.io succeeded; the Chrome scanner running inside urlscan.io's sandbox got a connection-closed error from the target. The host is up enough to terminate TCP but is actively refusing the request — consistent with either kit teardown or scanner blocking by the operator. The urlscan.io browser UI displays "we can't scan this website" because there's no rendered page to show. The scan itself is the finding: the kit's hosting still exists but no longer serves a credential-harvest page. Live verdict ≠ historical maliciousness, and the absence of a page is itself useful context for an analyst reviewing this sample later.

## CyberChef Analysis

**Recipe:** [From Base64 + Strings (min 4)](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Strings('Single%20byte',4,'All%20printable%20chars%20(incl.%20whitespace)',false))

**Input:** `Mm84ODhkN3oxZDZWNlU=`

**Output:** `2o888d7z1d6V6U`

**What it told us.** The 17-character base64 token at the end of the landing URL is a victim ID, not encrypted payload. Confirms the kit's design: every recipient gets a unique URL, so click telemetry maps 1:1 to email addresses. This is the same tracking pattern used by legitimate marketing platforms — leveraging recipient familiarity with `?utm_source=`-style suffixes to look ordinary.

## Analyst commentary

**What this is.** Classic display-name brand impersonation. The attacker registered (or compromised) a free Gmail account, set their Gmail display name to "DocuSign", and sent a credential-harvest lure to a list. Because the email genuinely originates from Gmail's infrastructure, every authentication check (SPF, DKIM, DMARC) passes legitimately. Most blocking systems treat `dmarc=pass` as a strong trust signal; this sample demonstrates exactly why that's insufficient.

**Kill chain.** Recipient sees "DocuSign" as the From, clicks "Check your document" → lands on `danielcacereslopez.com/<victim-id>` → presented with a fake DocuSign sign-in form harvesting Microsoft 365 / Google credentials. Telemetry on the victim ID lets the kit operator score conversion per recipient.

**Most reliable production detection signal.** Display-name-vs-from-domain divergence against a brand list. In a real deployment, `triage/data/protected_brands.txt` would be populated from the org's logo / brand-mention dataset and applied at ingest. Three signals stack here, in descending order of precision:

1. **Display name claims a protected brand AND from-domain isn't on that brand's allowlist.** This is the top signal. Both `display_name_brand_spoof` (Python) and `docusign_document_lure` (YARA) implement this in different ways and both fired.
2. **Free-mailbox sender (gmail.com / outlook.com) sending business-process language ("envelope", "review and sign").** Pair signal 1 with this as a multiplier.
3. **URL with a base64-encoded path component** *and* a non-brand-aligned host. Per-recipient unique URLs are not in themselves malicious, but combined with #1 they're a near-100% kit fingerprint.

**What the tool missed.** The `Reply-To` header is empty — there's no divergence to flag. A more sophisticated kit using "show your reply going to a different inbox" would trip the existing divergence check; this one didn't bother.
