# Findings summary — 5 deep-dive samples

Aggregate observations across the 5 hand-picked samples. Each row in the tables maps directly to one of the per-sample reports in this directory.

## Sample composition

| # | File | Captured | Category | Brand impersonated |
|---|---|---|---|---|
| 1 | [`sample-1182.eml`](sample_01_docusign_brand_spoof.md) | 2023-06 | Display-name brand spoof + credential phish | DocuSign |
| 2 | [`sample-3026.eml`](sample_02_office365_path_squat.md) | 2024-03 | URL-path typosquat + cloud-bucket phish + Unicode subject obfuscation | Microsoft Office 365 |
| 3 | [`sample-182.eml`](sample_03_btc_mining_pdf.md) | 2022-12 | Crypto-scam + weaponised-PDF lure | None (subject lure only) |
| 4 | [`sample-5714.eml`](sample_04_aave_defi_rewards.md) | 2025-05 | DeFi credential phish, display-name spoof | Aave |
| 5 | [`sample-6467.eml`](sample_05_omaha_steaks_typosquat.md) | 2025-12 | Brand-prefix typosquat + Azure tenant abuse + suspicious-TLD infra | Omaha Steaks |

Variety covers four distinct attack categories: brand impersonation via display name, URL-path/host typosquat, attachment-based lure, and free-cloud-tenant authentication laundering. Each sample illustrates a different evasion technique that breaks at least one common naive defense.

## Header / authentication

- **Originating-IP hosting providers:** Google LLC (samples 1, 3), Microsoft Exchange Online (sample 2), Hetzner DE (sample 4), Hostkey EU (sample 5).
- **All 5 samples passed SPF at the receiving MTA** despite 4 of 5 being clearly malicious. Authentication-passes-but-content-is-malicious is the single most important class-level finding.
- **DKIM:** 3/5 pass, 1/5 fail (sample 2), 1/5 absent (sample 5).
- **DMARC:** 3/5 pass, 1/5 absent (sample 2), 1/5 absent (sample 5).
- **Address divergence (`From` ≠ `Reply-To` / `Return-Path`):** 1/5 (sample 5 — Return-Path on free Azure tenant `*.onmicrosoft.com`).
- **Live-DNS verification surfaced contradictions in 2/5 samples:** sample 2 and sample 5 both got `spf=pass` despite their displayed sending domains having no published SPF record at all — the canonical fingerprint of authentication laundering through a free cloud tenant.

## Spoof / impersonation signals

| Detector | Hits | Samples |
|---|---|---|
| `display_name_brand_spoof` | 3/5 | 1 (DocuSign), 4 (Aave), 5 (Omaha Steaks) |
| `lookalike_in_url` | 1/5 | 2 (`office356` in path, Levenshtein 2 from `office365`) |
| `lookalike_domain` (from-domain) | 0/5 | None — no observed sample's from-domain registrable label was within Levenshtein-2 of a protected brand |
| `exec_impersonation` (CEO/CFO titles) | 0/5 | None — corpus didn't include BEC-style samples |

**Key takeaway:** display-name brand spoofing dominates the corpus (3/5 samples). From-domain Levenshtein lookalikes — the textbook "fake domain" attack — were 0/5 in this set. Modern phishing increasingly uses *generic* sender domains and impersonates via display name, banking on recipients ignoring the address.

## Payload categories

| Vector | Samples |
|---|---|
| URL-only credential phish (HTML body, link to landing) | 1, 4, 5 |
| Cloud-bucket-hosted landing (Google Cloud Storage, etc.) | 2 |
| Weaponised PDF attachment (no body URLs) | 3 |
| Free Azure tenant SMTP origination | 2, 5 |

## YARA rule contribution

| Rule | Hits | Samples that fired |
|---|---|---|
| `crypto_payout_lure` | 2/5 | 3 (Bitcoin transaction), 4 (Aave rewards) |
| `lookalike_domain_strings` | 2/5 | 2 (`office356`), 5 (`omahasteaksgry`) |
| `freetier_cloud_origin` | 2/5 | 2 (GCS bucket), 5 (`*.onmicrosoft.com` Return-Path) |
| `docusign_document_lure` | 1/5 | 1 |
| `pdf_with_finance_lure` | 1/5 | 3 |
| `base64_pdf_document` | 1/5 | 3 |
| `retail_order_lure` | 1/5 | 5 |
| `credential_harvest_login_lure` | 0/5 | (would fire on Microsoft 365 sign-in clones; none of the samples included raw login HTML in the body) |
| `exec_impersonation_keywords` | 0/5 | (no BEC samples in this set) |
| `suspicious_attachment_extensions` | 0/5 | (only attachments seen were a PDF and a PNG logo — no `.iso/.lnk/.html` payloads) |
| `double_extension_attachment` | 0/5 | (corpus didn't include any) |

**Coverage observation:** every sample fires at least one YARA rule. 4/5 samples fire 2+ rules (sample 4 hits `crypto_payout_lure` 3× across raw_eml / body_text / body_html). No false-positive cross-fires observed.

## PhishTank cross-reference

- **URLs cross-referenced via the public Phishing.Database mirror:** 14 unique URLs across the 5 samples; 0 found in the active-PhishTank URL list at scan time.
- **Why the 0% hit rate is expected:** PhishTank's active list focuses on currently-live phish. Samples 1, 2, 3 are 2-3 years old and their kit infrastructure is taken down. Sample 5's `silzenmura.click` no longer resolves at all (DNS NX). Sample 4's URL is sanitized to `phishing@pot` by the corpus.
- **Manual phishtank.org lookup performed for each deep-dive** (links in each report's PhishTank section).

## urlscan.io

| Sample | URL submitted | Result | UUID |
|---|---|---|---|
| 1 | `danielcacereslopez.com/Mm84ODhk…=` | scan error — `net::ERR_CONNECTION_CLOSED` (host actively closing connections) | `019dfdef-8319-719e-9513-4a674cabb059` |
| 2 | `storage.googleapis.com/office356/work.html` | HTTP 404 — bucket emptied | `019dfdf0-3d63-72d5-b3c7-cafcd8b1216d` |
| 3 | _(no URLs in body — PDF-only attack)_ | — | — |
| 4 | _(corpus-sanitized URL — `phishing@pot` placeholder)_ | — | — |
| 5 | `silzenmura.click/track/...` | DNS NXDOMAIN — domain no longer resolves | (submission rejected) |
| live demo | `native-turquoise-ks9ecs1jsm-ps78uzp417.edgeone.app/` | **HTTP 200 — kit fully rendered** | `019dfe0a-73f1-7737-9946-2c89ae997baa` |

**Observation: URL takedown rates are very high for samples >6 months old.** Of 3 actually-submittable URLs from the historical samples, all 3 returned takedown evidence (one DNS-dead, one connection-closed, one HTTP 404). This is consistent with the older sample dates and is itself a useful finding — *the absence of a live kit is evidence of a kit lifecycle*, not a false negative.

The live-demo run against a fresh URL discovered via urlscan.io's own search demonstrates that the toolchain produces a fully-rendered enrichment when given a kit that hasn't been taken down yet (see [`live_demo_edgeone_files_collection.md`](live_demo_edgeone_files_collection.md)).

## What surprised me / what the tool got wrong

- **SPF/DKIM/DMARC pass rate (4/5) was higher than expected.** I went into this expecting most phish to fail at least one auth check; instead the bigger pattern was kits *engineering* themselves to pass authentication, either by relaying through a real free mailbox (samples 1, 3 via Gmail) or laundering through a free Azure tenant (samples 2, 5). Auth verdicts are not by themselves a useful filter.
- **`lookalike_domain` (from-domain Levenshtein) was 0/5.** Surprising — I'd assumed typosquats would dominate. They didn't. Modern phishing prefers generic sender domains + display-name spoof.
- **`freetier_cloud_origin` is too broad.** The current rule fires on *any* `storage.googleapis.com/` URL, which is a plain false positive against legitimate GCS-hosted content. In production it needs an `AND` with brand-keyword path tokens before alerting.
- **The `phishing_pot` corpus sanitises some attacker URLs to `phishing@pot`** (sample 4). This is good for safety but means we lose the IOC for that sample. A real production deployment would have the unsanitized URL.
- **Tool missed nothing critical for 4/5 samples.** For sample 3 (PDF-only), the natural next step — parsing the PDF object stream for embedded URLs and JavaScript actions — is out of scope; the tool correctly flags the attachment magic-byte pattern and the suspicious filename, but PDF internals are a downstream sandbox / `peepdf` job.

## What I'd add next

- **Subject-line Unicode-block diversity check.** Sample 2's subject was 100% Mathematical Sans-Serif Bold characters — a near-perfect phishing signal that the tool currently doesn't surface (it only renders the rendered text). A per-character Unicode-block frequency table would catch this in one line of Python.
- **PDF object-stream URL extraction.** For sample 3 specifically — parse the decoded PDF and pull URLs from `/URI`, `/A`, `/JS` actions. `pdfminer.six` would do this in a separate module without breaking the current architecture.
- **Real-time SPF / DMARC capture.** Currently `--live-dns` looks up records *now*; for older samples the records may have been removed since. Capturing a snapshot from a passive-DNS provider (e.g., DNSDB, Farsight) at the email's date would let analyst observations like "received SPF=pass against a domain that had no SPF record" be made retrospectively.
- **VirusTotal hash lookup for attachments.** Trivial to bolt on, fills the obvious gap left by sample 3.
- **Brand-list per-deployment tuning.** `triage/data/protected_brands.txt` is currently a generic top-25 list. In a real deployment the org's own legitimate marketing-mail registry, plus the top brands recipients click on, would be the brand list — this is an operations job, not a code one.
