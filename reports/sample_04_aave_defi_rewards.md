# Sample 04 — Aave (DeFi) "rewards waiting" lure

**Source file:** `samples/emails/sample-5714.eml`
**Category:** crypto/DeFi credential phish, brand impersonation
**Captured:** 2025-05-19

---

## Headers

| Field | Value |
|---|---|
| From | `Aave Team` <contact@cityopp.com> |
| Reply-To | `contact@cityopp.com` |
| Return-Path | `contact@cityopp.com` |
| Subject | `Your Aave Rewards Are Waiting!` |
| Date | Mon, 19 May 2025 14:40:51 -0700 |
| Message-ID | `<NZU3MTI.NJEZOTG.56177705191440202551915017015@cityopp.com>` |
| Originating IP | **5.230.101.34** _(Hetzner Online GmbH, DE)_ |

### Received chain

| # | IP | Class |
|---|---|---|
| 0 | `5.230.101.34` | global |
| 1 | `2603:10b6:408:eb:cafe::3f` | global |
| 2 | `2603:10b6:408:eb::26` | global |
| 3 | _(final delivery)_ | ? |

The first hop is German consumer hosting (Hetzner). Subsequent hops are Microsoft 365 Exchange Online — the recipient was a Microsoft 365 mailbox.

## Authentication

- **SPF:** `pass`
- **DKIM:** `pass`
- **DMARC:** `pass`

### Live DNS comparison

- **No `v=spf1` TXT record on `cityopp.com`** at scan time.
- **No `v=DMARC1` TXT record on `_dmarc.cityopp.com`** at scan time.

> **Analyst note.** SPF/DKIM/DMARC all reportedly passed in 2025 against `cityopp.com`. By 2026 the domain has no published SPF/DMARC at all. This is consistent with the kit being torn down (DNS records removed) after the campaign. A timestamp-aware production system would log the records as-they-were-at-receipt and not just look them up now.

## MIME structure

| Path | Content-Type | Filename | Size | SHA-256 |
|---|---|---|---|---|
| 0 | `text/plain` | _(none)_ | 382 | `359cae40b8fcc54c46f49cda4245878106cbd696c03eb483461cd034580c1bb0` |
| 1.0 | `text/html` | _(none)_ | 2,233 | `df811cf779e1222c9d1e5607d30794b58f622614bca9fd29304af60bc6413bc2` |
| 1.1 | `image/png` | `logo.png` | 4,212 | `9151ebb72c08c4c9209ded53f63b8a834ed0d9e9797671cca92b705d558bb02f` |

A small inline `logo.png` embedded by `cid:` reference — almost certainly a copy of the real Aave brand logo to add visual legitimacy.

## Spoof / impersonation findings

- **`display_name_brand_spoof`** — `cityopp.com` (target: `aave.com`) — Display name "Aave Team" claims brand "aave" but from-domain is cityopp.com.

`cityopp.com` itself isn't a typo of `aave.com` — Levenshtein distance is too large for the lookalike-domain detector to fire. The kit operator picked a generic-sounding fake company name (`cityopp.com`) deliberately, hoping recipients ignore the domain because the display name says "Aave Team." Display-name-vs-domain divergence is the only signal that catches this.

## IOCs

**URLs:**
- `https://scheeren-tec.de/phishing@pot` — **note: this URL is sanitized by the phishing_pot corpus collector.** The literal token `phishing@pot` is the placeholder substituted in for the original attacker URL during corpus publication. We can't enrich the real URL from this sample.

## YARA matches

| Rule | Severity | Target | Strings |
|---|---|---|---|
| `crypto_payout_lure` | high | `raw_eml` | `$rewards_waiting -> Rewards Are Waiting` (×3) |
| `crypto_payout_lure` | high | `body_text` | `$rewards_waiting -> Rewards Are Waiting`; `$claim_rewards -> Claim Your Rewards`; `$brand_aave -> Aave` |
| `crypto_payout_lure` | high | `body_html` | `$rewards_waiting`; `$claim_rewards -> Claim Your Rewards` |

Three independent buffers (raw eml, body_text, body_html) all fire on the same rule via different string combinations. Strong signal.

## PhishTank cross-reference

**Programmatic (Phishing.Database mirror):** the only URL is sanitized; no lookup possible.

**Manual phishtank.org lookup:** [search for `cityopp.com`](https://www.phishtank.com/phish_search.php?valid=y&active=All&Search=Search&page=&search_text=cityopp.com)

## urlscan.io

_(Skipped — the URL in the body has been sanitized by the corpus, so submitting `phishing@pot` would tell us nothing. In a production deployment this URL would be a real attacker domain to submit.)_

## CyberChef Analysis

**Recipe:** [Extract URLs](https://gchq.github.io/CyberChef/#recipe=Extract_URLs(true))

**Input:** the decoded HTML body part (`text/html`).

**What it told us.** A single sanitized URL — `https://scheeren-tec.de/phishing@pot`. The URL position in the HTML (an `<a href="…">` wrapping the call-to-action button) confirms this is the credential-harvest pivot point. No additional hidden URLs in style tags or JavaScript.

**Second recipe used:** [Render Image (PNG)](https://gchq.github.io/CyberChef/#recipe=Render_Image('Raw')) on the decoded `logo.png` MIME part (sha256 `9151ebb…`) confirmed it's the legitimate Aave brand logo. Stolen branding, not a kit-original asset.

## Analyst commentary

**What this is.** A DeFi-themed credential-harvest lure impersonating Aave — the largest decentralized lending protocol. Like sample 01 (DocuSign), the attacker isn't bothering to register a typosquat domain; they're banking on the recipient seeing "Aave Team" in the display name and not checking the actual sending domain. The kit was hosted on consumer-grade German hosting (Hetzner) and the from-domain was a generic-sounding `cityopp.com` that has since gone dark.

**Kill chain.** Recipient sees "Aave Team" + "Your Aave Rewards Are Waiting!" → clicks "Claim Your Rewards" button → lands on attacker-controlled wallet-connection page → either harvests the wallet's seed phrase via a fake "verify your wallet" form or initiates an out-of-protocol transaction sign request. DeFi phishing is uniquely profitable because seed-phrase exfiltration is final and irreversible — there's no equivalent of a bank's chargeback.

**Most reliable production detection signal.** For DeFi/crypto-brand phishing, three signals stack:
1. **Display name claims a DeFi brand AND from-domain isn't on that brand's allowlist.** Aave, Coinbase, Binance, MetaMask, Uniswap — top-targeted brands. Same detector as sample 01 (`display_name_brand_spoof`), with the brand list extended to cover crypto.
2. **`Rewards|Airdrop|Claim` keywords paired with a brand keyword.** `crypto_payout_lure` fires three times here on three different buffers. The kit reuses the same copy across HTML and plaintext body parts; each presents an independent matchable surface.
3. **Hetzner / OVH / consumer-VPS originating IP + DeFi-brand claim.** Consumer hosting providers are over-represented as origin for crypto-phishing; legit Aave / Coinbase mail comes from their own SES / SendGrid infrastructure.

**What the tool missed.** The original phishing URL is sanitized in the corpus. In a real deployment, this is exactly the URL that would be submitted to urlscan.io / VirusTotal as the highest-priority IOC. The triage tool itself is fine; the corpus chose to sanitize.
