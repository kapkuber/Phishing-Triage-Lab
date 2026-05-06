"""PhishTank URL lookup via the public Phishing.Database mirror.

PhishTank paused new API registrations in 2024, so we cross-reference URLs
against `mitchellkrogza/Phishing.Database` on GitHub — a public, auto-updated
mirror of PhishTank + OpenPhish data. No API key needed.

We download the active-PhishTank list once a day, cache it on disk, and
do offline lookups against a normalized URL set.
"""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_PATH = PROJECT_ROOT / "samples" / "phishtank_cache.txt"

# PhishTank-sourced active URL list from the public mirror.
# `ALL-phishing-links.txt` aggregates PhishTank's active-validated URLs alongside
# OpenPhish — both are public phishing feeds. Reasonable fallback if the
# PhishTank-only file path changes upstream.
MIRROR_URL_PRIMARY = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
MIRROR_URL_FALLBACK = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-links.txt"

CACHE_TTL_SECONDS = 24 * 3600


@dataclass
class PhishtankLookup:
    url: str
    known_phish: bool
    matched_form: Optional[str] = None  # which normalized variant matched
    cache_age_hours: float = 0.0
    source_file: Optional[str] = None


class PhishtankClient:
    def __init__(self, cache_path: Path = CACHE_PATH, ttl: int = CACHE_TTL_SECONDS):
        self.cache_path = cache_path
        self.ttl = ttl
        self._urls: Optional[set[str]] = None
        self._loaded_from: Optional[str] = None

    def _cache_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        age = time.time() - self.cache_path.stat().st_mtime
        return age < self.ttl

    def refresh(self, force: bool = False) -> tuple[bool, Optional[str]]:
        """Download the mirror list. Returns (ok, error_msg)."""
        if not force and self._cache_fresh():
            return True, None
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        for url in (MIRROR_URL_PRIMARY, MIRROR_URL_FALLBACK):
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                self.cache_path.write_text(resp.text, encoding="utf-8")
                self._loaded_from = url
                return True, None
            except requests.RequestException as e:
                last_err = str(e)
                continue
        return False, f"Could not reach PhishTank mirror: {last_err}"

    def _load(self) -> None:
        if self._urls is not None:
            return
        if not self.cache_path.exists():
            self._urls = set()
            return
        urls: set[str] = set()
        with self.cache_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                urls.add(line)
                # Also store a normalized form so http/https variants match.
                urls.add(_normalize(line))
        self._urls = urls

    def lookup(self, url: str) -> PhishtankLookup:
        self._load()
        age_hours = 0.0
        if self.cache_path.exists():
            age_hours = (time.time() - self.cache_path.stat().st_mtime) / 3600.0

        candidates = [url, _normalize(url), _strip_path(url), _strip_path(_normalize(url))]
        for c in candidates:
            if c in (self._urls or set()):
                return PhishtankLookup(
                    url=url,
                    known_phish=True,
                    matched_form=c,
                    cache_age_hours=age_hours,
                    source_file=self._loaded_from or str(self.cache_path),
                )
        return PhishtankLookup(
            url=url,
            known_phish=False,
            cache_age_hours=age_hours,
            source_file=self._loaded_from or str(self.cache_path),
        )


def _normalize(url: str) -> str:
    """Lowercase scheme+host; strip trailing slash on root paths."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or ""
    if path == "/":
        path = ""
    return urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))


def _strip_path(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
