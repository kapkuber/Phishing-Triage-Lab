# Sample 02 — Microsoft 365 lure with cloud-bucket-hosted phish + path-segment typosquat

**Source file:** `samples/emails/sample-3026.eml`
**Category:** brand impersonation, cloud-infrastructure abuse, lookalike-via-URL-path
**Captured:** 2024-03-16

---

## Headers

| Field | Value |
|---|---|
| From | `Miracle Team` <For_You_61921@barry.rubiyo.xyz> |
| Reply-To | _(none)_ |
| Return-Path | `For_You_61921@barry.rubiyo.xyz` |
| Subject | `𝗢𝗽𝗲𝗻 𝗡𝗼𝘄 𝗠𝗶𝗿𝗮𝗰𝗹𝗲 𝗦𝗵𝗲𝗲𝘁𝘀 𝟮𝟬𝟮𝟰` (Mathematical Sans-Serif Bold — see commentary) |
| Date | Sat, 16 Mar 2024 02:34:27 +0000 |
| Message-ID | `<…@…dcccd.edu>` _(spoofed Message-ID domain — Dallas County Community College)_ |
| Originating IP | **2603:10b6:510:167::20** _(Microsoft, US)_ |

### Received chain

| # | IP | Class |
|---|---|---|
| 0 | `fe80::49a0:8d2d:26c0:fe16` | private (link-local IPv6) |
| 1 | `2603:10b6:510:167::20` | global |
| 2 | `52.100.165.239` | global |
| 3 | `2603:10b6:408:107:cafe::6` | global |
| 4 | `2603:10b6:408:107::29` | global |
| 5 | `2603:10b6:408:1e1::17` | global |

All 5 public hops are inside Microsoft's Exchange Online IPv6 ranges. The phisher used a free or compromised M365 tenant; legit Microsoft mail flow looks identical at the network layer, which is exactly why this stage of the analysis can't classify alone.

## Authentication

- **SPF:** `pass` _(against the M365 tenant's authorisation, not against `barry.rubiyo.xyz`)_
- **DKIM:** `fail`
- **DMARC:** `—` _(not present)_

### Live DNS comparison

- **No `v=spf1` TXT record on `barry.rubiyo.xyz`** — the sender domain has no published SPF policy. SPF "pass" therefore came from a different `mfrom` (likely the M365 tenant's onmicrosoft.com domain after a header rewrite).
- **No `v=DMARC1` TXT record on `_dmarc.barry.rubiyo.xyz`** — no DMARC at all.

> **Analyst note.** A domain with neither SPF nor DMARC published, sending mail with a "pass" SPF header, is the canonical fingerprint of authentication-context laundering through a free cloud tenant. Real organisations publish *both* records.

## MIME structure

| Path | Content-Type | Filename | Size | SHA-256 |
|---|---|---|---|---|
| 0 | `text/html` | _(none)_ | 1172 | `23a63769ba3a2f205172d83d97075678eb4b42c14536ecd3eaec914b8610113b` |

## Spoof / impersonation findings

- **`lookalike_in_url`** — `office356` (target: `office365.com`) — Levenshtein 2 from `office365` in URL **path** (token=`office356`). Source URL: `https://storage.googleapis.com/office356/work.html#…`

The from-domain (`barry.rubiyo.xyz`) doesn't itself impersonate Microsoft — Levenshtein distance from `microsoft` is too large. The brand spoof lives entirely inside the path component of the cloud-storage URL. Detecting this required walking *every* URL's host labels and path segments, not just the From-domain (see `triage/spoof_detector.py::detect_lookalike_in_urls`).

## IOCs

**URLs:**
- `http://104.219.248.205/track/3jfJoH2045WOit5ppbjdqwoiw257WORDHOOLKNMZLTY28AGRK896656R12` — IP-as-host tracker. Click-telemetry callback.
- `https://storage.googleapis.com/office356/work.html#4LIUrc2045ZpwS5vkgvcbgnyz257DAJQAMHJJGCDTRW28NMFY896656r12` — phishing landing page on a public Google Cloud Storage bucket named `office356`.
- `https://storage.googleapis.com/office356/work.html#5JawLE…` — second variant of the same landing.
- `https://pbs.twimg.com/media/GHSpGOhWcAA-uHp?format=jpg&name=900x900` — image hotlinked off Twitter's CDN.

**IPs in body:** `104.219.248.205` _(literal IP-as-host suggests the kit operator's own infra)_

**Payload / base64 hits:**
- 2 × 51-byte unknown-magic chunks. Almost certainly tracking-pixel or victim-fingerprint payloads embedded in the HTML body.

## YARA matches

| Rule | Severity | Target | Strings |
|---|---|---|---|
| `lookalike_domain_strings` | high | `raw_eml`, `body_html` | `$office356 -> office356` (×3) |
| `freetier_cloud_origin` | medium | `raw_eml`, `body_html` | `$gcs_bucket -> storage.googleapis.com/` (×2) |

## PhishTank cross-reference

**Programmatic (Phishing.Database mirror):** none of the 4 URLs were present in the active list at scan time. Likely already taken down by the time of the snapshot.

**Manual phishtank.org lookup:** [search for `storage.googleapis.com/office356`](https://www.phishtank.com/phish_search.php?valid=y&active=All&Search=Search&page=&search_text=office356)

## urlscan.io

| URL | Verdict | Result |
|---|---|---|
| `https://storage.googleapis.com/office356/work.html` | HTTP 404 — bucket emptied | [019dfdf0-3d63-72d5-b3c7-cafcd8b1216d](https://urlscan.io/result/019dfdf0-3d63-72d5-b3c7-cafcd8b1216d/) |

The bucket has been emptied since the sample was sent (March 2024). The scan returned a clean 404 — the kit content is gone but the bucket name `office356` is still claimed by Google. urlscan.io's browser UI says "we can't scan this website" because the rendered page is just Google's 404 placeholder with no analyzable content. The takedown itself is the finding: anti-abuse actioned the bucket, the typosquat-name remains parked.

## CyberChef Analysis

**Recipe:** [Unicode Normalize (NFKC)](https://gchq.github.io/CyberChef/#recipe=Unicode_Text_Format()Normalise_Unicode('NFKC'))

**Input (subject line):** `𝗢𝗽𝗲𝗻 𝗡𝗼𝘄 𝗠𝗶𝗿𝗮𝗰𝗹𝗲 𝗦𝗵𝗲𝗲𝘁𝘀 𝟮𝟬𝟮𝟰`

**Output:** `Open Now Miracle Sheets 2024`

**What it told us.** Every character in the subject is Unicode block "Mathematical Sans-Serif Bold" (U+1D5D4–U+1D607 plus the matching digit range). They render as bold text, but to a regex / keyword filter looking for "Miracle Sheets" the bytes never match. This is a deliberate evasion technique — and a good reason any production-grade subject-keyword filter must Unicode-normalize before pattern matching.

## Analyst commentary

**What this is.** A Microsoft 365 / "free productivity tools" themed lure that uses three layered evasions:

1. **Authentication laundering through a free M365 tenant** — the `barry.rubiyo.xyz` domain has no published SPF/DMARC, but the email gets `spf=pass` because Exchange Online rewrote the envelope from with the tenant's own onmicrosoft.com identity.
2. **Brand impersonation in a URL path, not the host** — `storage.googleapis.com/office356/work.html` looks like Google to URL-host-only filters but the path segment `office356` is where the brand spoof lives (Levenshtein 2 from `office365`).
3. **Unicode subject obfuscation** — Mathematical Sans-Serif Bold characters defeat naive keyword filters on the subject line.

**Kill chain.** Recipient opens email, sees a "Miracle Sheets 2024" call-to-action, clicks the `storage.googleapis.com/office356/work.html` link → Google's TLS cert validates → the page is whatever the kit operator uploaded to the bucket (likely a Microsoft 365 sign-in clone). The IP-as-host URL `104.219.248.205/track/...` is a parallel telemetry callback that the page or an embedded image fires for click attribution.

**Most reliable production detection signal.** Three stack here:
1. URL path-segment Levenshtein against a protected-brand list. The signal is high-precision (`office356` is not a real word).
2. `Return-Path` on a domain with neither SPF nor DMARC published, but receiving SPF=pass — the auth-laundering fingerprint.
3. Subject-line Unicode-block diversity. A subject made entirely of Mathematical Sans-Serif Bold characters is a near-100% phishing tell; legitimate senders don't do this.

**What the tool missed.** The `freetier_cloud_origin` rule fires on *any* `storage.googleapis.com/` URL, which is too broad — Google Cloud Storage hosts plenty of legitimate content. In production this rule should be combined with an `AND` against a brand-keyword path token before it alerts. The current rule is a triage-time hint, not a blocking signal.
