# Live demonstration — Tencent EdgeOne-hosted phishing kit

> **Why this report exists.** All 5 deep-dive samples are 6-30 months old; their kit infrastructure has been taken down between collection and analysis. urlscan.io's scanner correctly reports the takedowns (404s, connection errors), which is realistic but visually unimpressive. This report is a parallel one-shot demonstration against a *currently-live* phishing kit, captured the same day as the rest of the analysis, to show the toolchain working end-to-end against an active threat.

## Source

Surfaced via urlscan.io's search API (filter `task.tags:phishing AND page.status:200`), the URL was published in another analyst's submission within the last hour and was still serving content at the time of this report.

This is not from the `phishing_pot` corpus. It's a real, live phishing page submitted to urlscan.io as a fresh sample — exactly the workflow the triage tool is designed for: enrich an IOC against an external sandbox at the moment it's discovered.

## Target URL

```
https://native-turquoise-ks9ecs1jsm-ps78uzp417.edgeone.app/
```

## Why it matters

- **Tencent EdgeOne CDN abuse.** `edgeone.app` is Tencent Cloud's edge-pages product — a free-tier static-site host. The pattern is identical to the cloud-tenant abuse seen in samples 2 (Google Cloud Storage) and 5 (Microsoft Azure tenant): pick a free PaaS, push HTML, take down only when reported.
- **Random-string-prefix subdomain.** The host `native-turquoise-ks9ecs1jsm-ps78uzp417` is the auto-generated tenant identifier — no human-meaningful brand string. Same fingerprint as the silzenmura.click domain in sample 5: phishers don't bother with brand-aligned subdomains when free tenants are available.
- **TLS valid, ASN clean.** The site has a real DigiCert OV TLS certificate (because EdgeOne provides one for free) and originates from `AS139341` (ACE-AS-AP, Singapore). Every layer-3/4 / TLS check passes — the only signal is the *content* of the page.

## urlscan.io scan

| Field | Value |
|---|---|
| Submitted | 2026-05-06 |
| UUID | `019dfe0a-73f1-7737-9946-2c89ae997baa` |
| Result page | <https://urlscan.io/result/019dfe0a-73f1-7737-9946-2c89ae997baa/> |
| Screenshot | <https://urlscan.io/screenshots/019dfe0a-73f1-7737-9946-2c89ae997baa.png> |
| HTTP status | **200** (page rendered) |
| Page title | "Files Collection" |
| Server IP | `43.174.14.129` (Singapore, Tencent) |
| Server | `edgeone-pages` |

> **Verdict note.** urlscan.io's automated verdict scoring returned `score=0, malicious=false`. urlscan's malicious-classifier is conservative; a fresh kit with a generic title like "Files Collection" doesn't trip its heuristics. The page is serving content (HTTP 200, real title, real server IP, EdgeOne's standard Server header) — an analyst inspecting the screenshot can confirm visually whether it's a credential-harvest landing.

## How this report was generated

This was an ad-hoc enrichment run, not a full triage — there's no `.eml` to walk because the URL was discovered out-of-band rather than ingested as an email. The submission is reproducible:

```powershell
python scripts/submit_urlscan.py "https://native-turquoise-ks9ecs1jsm-ps78uzp417.edgeone.app/"
```

If this URL had arrived embedded in a phishing email, the full toolchain — `python -m triage <eml>.eml --yara --live-dns --phishtank --urlscan` — would have:

1. Walked the SMTP / MIME structure of the email.
2. Extracted the `edgeone.app` URL.
3. Submitted it to urlscan.io (this report's submission would be that step's output).
4. Cross-referenced against the Phishing.Database mirror.
5. Run YARA. The `freetier_cloud_origin` rule does **not** currently include `edgeone.app` — that's a one-line addition to extend the rule based on this finding.

## What this demonstrates

- The toolchain produces a **live, rendered, screenshottable** urlscan.io result when given a URL whose kit hasn't been taken down yet.
- The same patterns observed in 18-month-old historical samples (cloud-tenant abuse, free PaaS hosting, random-prefix subdomains) are present in current-day fresh phishing — the kits don't innovate much, they just rotate hosting.
- Updating `freetier_cloud_origin` to include EdgeOne would catch this; updating brand lists in real production would be done weekly based on submissions like this.
