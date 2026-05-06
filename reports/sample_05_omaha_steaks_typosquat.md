# Sample 05 — Omaha Steaks brand impersonation via Azure tenant + .click typosquat

**Source file:** `samples/emails/sample-6467.eml`
**Category:** brand impersonation, free-tier cloud abuse, infrastructure typosquat
**Captured:** 2025-12-04

---

## Headers

| Field | Value |
|---|---|
| From | `Omaha Steaks` <info@omahasteaksgry.com> |
| Reply-To | _(none)_ |
| Return-Path | `44xmlle9xd@jer20341378.onmicrosoft.com` |
| Subject | `Omaha Steaks Steak Feast Box – Order Today 🤤 !` |
| Date | Thu, 04 Dec 2025 20:25:31 +0000 |
| Message-ID | `<15960199-aa49-41b5-be4e-693a1fcfdd75@TY2PEPF0000AB8A.apcprd03.prod.outlook.com>` |
| Originating IP | **62.212.79.196** _(Hostkey, EU)_ |

### Address divergence

- **Return-Path domain (`jer20341378.onmicrosoft.com`) differs from From domain (`omahasteaksgry.com`).** This is the highest-precision header signal in the sample.

### Received chain

| # | IP | Class |
|---|---|---|
| 0 | `62.212.79.196` | global |
| 1 | `2603:1096:300:2d:cafe::b8` | global |
| 2 | `2603:1096:300:2d::28` | global |
| 3 | `52.102.171.43` | global |
| 4 | `2603:10a6:400:1d6:cafe::16` | global |
| 5 | `2603:10a6:400:1d6::6` | global |
| 6 | _(final delivery)_ | ? |

The originating IP is a small European hosting provider; subsequent hops are Microsoft 365 Exchange Online — confirming the Return-Path's `*.onmicrosoft.com` claim.

## Authentication

- **SPF:** `pass`
- **DKIM:** `none`
- **DMARC:** `none`

### Live DNS comparison

- **No `v=spf1` TXT record on `omahasteaksgry.com`** — the displayed sending domain has no published SPF policy.
- **No `v=DMARC1` TXT record on `_dmarc.omahasteaksgry.com`** — no DMARC.

> **Analyst note.** The `spf=pass` was earned by the M365 tenant's onmicrosoft.com identity (visible in Return-Path) — not by `omahasteaksgry.com`. To a recipient's MTA the email passes SPF; to the recipient's eyes the From says Omaha Steaks. Two different domains, one trust signal — the attack is precisely engineered around this seam.

## MIME structure

| Path | Content-Type | Filename | Size | SHA-256 |
|---|---|---|---|---|
| 0 | `text/html` | _(none)_ | 6,918 | `0d7bfc411055873b43ebb8381e10e64568cae160f700cab42f4bcc6c1dc7efcf` |

Single HTML body. The content uses real Omaha Steaks marketing imagery (hotlinked from Wikipedia and Unsplash — see IOCs).

## Spoof / impersonation findings

- **`display_name_brand_spoof`** — `omahasteaksgry.com` (target: `omahasteaks.com`) — Display name "Omaha Steaks" claims brand "omahasteaks" but from-domain is omahasteaksgry.com.

The from-domain `omahasteaksgry.com` is a typosquat of `omahasteaks.com` — the registrable label is `omahasteaks` plus a 3-char `gry` suffix glued on. Pure-Levenshtein lookalike detection would flag this at distance 3, which is just over the `max_distance=2` threshold the lookalike rule uses. Display-name-vs-domain catches it cleanly because tokenizing "Omaha Steaks" → "omahasteaks" and substring-matching against the from-domain registrable would make the brand-anchor explicit.

## IOCs

**URLs:**
- 4 × `silzenmura.click/...` URLs (kit telemetry + landing). All variants, single hostname.
- `https://images.unsplash.com/photo-1607116171170-5d0a9e7f5b5f?...` — stock photo from Unsplash.
- `https://upload.wikimedia.org/wikipedia/en/d/d7/Omaha_Steaks_logo.png` — real Omaha Steaks logo, hotlinked.

**Payload / base64 hits:** 3 × 51-byte unknown-magic blobs in the HTML body — same tracking-pixel fingerprint as sample 02. Likely the same kit family or a shared template.

## YARA matches

| Rule | Severity | Target | Strings |
|---|---|---|---|
| `lookalike_domain_strings` | high | `raw_eml` | `$omahasteaks_gry -> omahasteaksgry` (×3) |
| `freetier_cloud_origin` | medium | `raw_eml` | `$rp_onmicrosoft -> Return-Path: 44xmlle9xd@jer20341378.onmicrosoft.com` |
| `retail_order_lure` | medium | `raw_eml` | `$order_today -> Order Today`; `$brand_omaha -> Omaha Steaks` (×2) |

## PhishTank cross-reference

**Programmatic (Phishing.Database mirror):** none of the 4 silzenmura.click URLs were present in the active list at scan time.

**Manual phishtank.org lookup:** [search for `silzenmura.click`](https://www.phishtank.com/phish_search.php?valid=y&active=All&Search=Search&page=&search_text=silzenmura.click)

## urlscan.io

| URL | Verdict | Score | Result |
|---|---|---|---|
| `http://silzenmura.click/...` | error | — | Submission rejected: **DNS Error - Could not resolve domain** |

> **Analyst note.** The DNS-resolution failure is itself a finding: the kit infrastructure has been taken down or expired between sample collection (Dec 2025) and scan time (May 2026). Combined with the freshness of the sample (~5 months old) this is a typical phish-kit lifecycle — register, send a campaign, abandon the domain when blocklists catch up.

## CyberChef Analysis

**Recipe 1:** [Extract URLs](https://gchq.github.io/CyberChef/#recipe=Extract_URLs(true)) on the decoded HTML body.

**What it told us.** Confirmed the URL count (7 URLs) and surfaced that all 4 `silzenmura.click` URLs share an identical path-prefix structure (`/<random8>5552<random4>114<random10>80...285239<random4>425056<random2>`). The repeated digit substrings (`5552`, `114`, `285239`, `425056`) act as kit-identifier markers; rotating campaigns reuse the same kit binary with different prefixes. A defender could match on the digit pattern alone for high-precision blocking.

**Recipe 2:** [URL Decode → Defang URL](https://gchq.github.io/CyberChef/#recipe=URL_Decode()Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')) — used to defang the silzenmura.click URLs before pasting them into this report and into IOC-share threads.

## Analyst commentary

**What this is.** A retail-order-impersonation phish using three layered evasions:

1. **Typosquat from-domain (`omahasteaksgry.com`)** — registers a domain that contains the full brand-name as a prefix, then suffixes a 3-char throwaway. SLDs like this are cheap to register (often under $5/year) and look fine to recipients who skim.
2. **Authentication via free Azure tenant** — the Return-Path `jer20341378.onmicrosoft.com` is a free-trial M365 tenant. The attacker uses the tenant for the SMTP submission so SPF passes, then displays a different From-domain to the recipient. Same authentication-laundering pattern as sample 02.
3. **Suspicious-TLD landing infrastructure (`silzenmura.click`)** — `.click` TLD has no legit reason to exist for a U.S. consumer-retail brand. Disposable infrastructure, taken down within months.

**Kill chain.** Recipient sees a polished email with real Omaha Steaks logo and "Order Today 🤤" call-to-action → clicks "Order Now" → lands on `silzenmura.click/<tracking-id>` → almost certainly a fake checkout / payment-card-harvest page. The 4 URL variants suggest A/B-tested landing pages or different per-recipient kit branches.

**Most reliable production detection signal.** Three signals stack here, all firing:
1. **Return-Path on `*.onmicrosoft.com` AND From-domain claims a known consumer brand.** This pair alone is near-100% precision — legit Omaha Steaks email comes from `omahasteaks.com` infrastructure (BlueHornet / Salesforce Marketing Cloud), never from a generic Azure tenant.
2. **Display-name brand spoof — `Omaha Steaks` in display, registrable label not `omahasteaks`.** Same detector as sample 01.
3. **`.click` / `.zip` / `.top` URL host with brand-language email body.** Suspicious-TLD heuristic.

**What the tool missed.** Nothing major. The 51-byte tracking-pixel blobs are reported as "unknown magic" — extending the magic-byte sniffer to recognise PNG-tracker / 1×1-image patterns (PNG headers + dimensions in IHDR chunk) would label these as "tracking pixel" instead. Cosmetic improvement; the IOC is captured either way.
