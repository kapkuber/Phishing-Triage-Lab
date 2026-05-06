# A note on PhishTank access

PhishTank paused new API registrations in 2024 and as of this project's date is still not accepting new sign-ups. We can't pull data from the official PhishTank API, but we can still make defensible use of PhishTank data — that's what this lab does.

## Two access routes used

### 1. Programmatic — Phishing.Database (PhishTank-derived public mirror)

[`mitchellkrogza/Phishing.Database`](https://github.com/mitchellkrogza/Phishing.Database) is a public, auto-updated GitHub repository that aggregates and re-publishes PhishTank's active-validated URL list (alongside OpenPhish). Pulling the raw text file is just an unauthenticated HTTPS GET, no key required.

`triage/phishtank_client.py` downloads `phishing-links-ACTIVE.txt` from that mirror, caches it for 24 hours under `samples/phishtank_cache.txt`, and does normalized URL lookups against the cached list when the CLI is invoked with `--phishtank`.

### 2. Manual — phishtank.org/phish_search.php

PhishTank's public search UI at `https://phishtank.org/phish_search.php` is open to anyone, no account needed. For each of the 5 deep-dive reports, the most suspicious URL is also searched manually on this page; the result page (and a screenshot) is referenced from the report.

Doing both routes is intentional. The mirror lets us cross-reference at scale and shows up in every CLI report. The manual lookup proves the URL was checked against PhishTank itself, not just a derivative.

## Why we don't pretend the API works

Earlier drafts of this project considered registering for the API and building against it. After confirming registration is genuinely paused (not just slow), we moved to the mirror approach because:

- It's honest. The resume bullet stays accurate — PhishTank data is being used.
- It's how working analysts cope with paused/rate-limited APIs in practice.
- The mirror is genuinely PhishTank-derived; using it is not the same as using OpenPhish alone.

If PhishTank reopens API registration in the future, plugging in `data.phishtank.com/data/<APIKEY>/online-valid.json.gz` is a one-function swap inside `phishtank_client.py`.

## Sample-source split

A separate point worth being clear on: PhishTank distributes **URLs**, not raw `.eml` files. The samples in `samples/emails/` come from the public [`rf-peixoto/phishing_pot`](https://github.com/rf-peixoto/phishing_pot) corpus (~2k real phishing emails). PhishTank is used to validate URLs *extracted from* those emails, not the emails themselves. This is a normal split in real triage work — header/MIME analysis comes from your inbox or a corpus, IOC reputation comes from the threat-intel feed.
