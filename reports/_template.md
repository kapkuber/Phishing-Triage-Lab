# Phishing Triage Report — `<sample-filename>.eml`

> Pre-fill this by running:
> `python -m triage samples/emails/<file>.eml --yara --live-dns --phishtank --urlscan --report-md > reports/sample_NN_<title>.md`
>
> Then hand-edit the **CyberChef Analysis**, **Manual PhishTank lookup**, and **Analyst commentary** sections.

## Headers

| Field | Value |
|---|---|
| From | … |
| Reply-To | … |
| Return-Path | … |
| Subject | … |
| Date | … |
| Message-ID | … |
| Originating IP | … |

### Address divergence

(auto-filled if any divergence found)

### Received chain

(auto-filled)

## Authentication

- SPF, DKIM, DMARC verdicts from the receiving MTA
- Live DNS comparison (if `--live-dns` used)

## MIME structure

(auto-filled table)

## Spoof / impersonation findings

(auto-filled — exec impersonation, lookalike domains)

## IOCs

(auto-filled URLs, emails, IPs, base64 hits)

## YARA matches

(auto-filled when `--yara` is used)

## PhishTank cross-reference

**Programmatic (Phishing.Database mirror):** auto-filled.

**Manual phishtank.org lookup:**
- Searched URL: `<paste URL>`
- Result page: `<paste phishtank.org permalink>`
- Screenshot: `reports/screenshots/sample_NN_phishtank.png`

## urlscan.io

(auto-filled when `--urlscan` is used. Add screenshot reference manually.)

## CyberChef Analysis

Recipe used: `<paste CyberChef share URL>`

What it does and why we ran it:

```
<paste short description — e.g. "From Base64 -> Strings (min 8) — to surface obfuscated URLs and PE imports">
```

Output highlights:

- …

## Analyst commentary

1-2 paragraphs:

- What is this sample? (kit, brand impersonated, victim profile)
- Kill-chain — how would the attack succeed if the user clicked?
- Most reliable detection signal — what would *you* alert on if you owned this kit's detection in production?
- What did the tool miss?
