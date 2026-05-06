"""urlscan.io API client.

Workflow:
  1. submit(url) -> uuid
  2. result(uuid) -> verdict + screenshot link (polls until ready)

Free tier limits: 60/min, 5000/day, 100 public scans/day. We default to
visibility="unlisted" so submitted URLs aren't surfaced on the public urlscan feed.

Results are cached on disk (by URL hash) so re-running the CLI on the same
sample doesn't re-submit.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = PROJECT_ROOT / "samples" / "urlscan_cache"

API_BASE = "https://urlscan.io/api/v1"


@dataclass
class UrlscanResult:
    url: str
    uuid: Optional[str] = None
    verdict: Optional[str] = None      # "malicious" / "suspicious" / "neutral" / etc.
    score: Optional[int] = None
    screenshot_url: Optional[str] = None
    page_url: Optional[str] = None     # the human-readable result page
    dom_url: Optional[str] = None
    submitted: bool = False
    error: Optional[str] = None
    raw: dict = field(default_factory=dict)


class UrlscanClient:
    def __init__(self, api_key: Optional[str] = None, cache_dir: Path = CACHE_DIR):
        self.api_key = api_key or os.environ.get("URLSCAN_API_KEY", "")
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, url: str) -> Path:
        h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]
        return self.cache_dir / f"{h}.json"

    def _read_cache(self, url: str) -> Optional[UrlscanResult]:
        p = self._cache_path(url)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return UrlscanResult(**{k: v for k, v in data.items() if k in UrlscanResult.__dataclass_fields__})

    def _write_cache(self, res: UrlscanResult) -> None:
        p = self._cache_path(res.url)
        p.write_text(json.dumps(res.__dict__, default=str, indent=2), encoding="utf-8")

    def submit_and_fetch(
        self,
        url: str,
        *,
        visibility: str = "unlisted",
        timeout: float = 45.0,
        use_cache: bool = True,
    ) -> UrlscanResult:
        if use_cache:
            cached = self._read_cache(url)
            if cached:
                return cached
        res = UrlscanResult(url=url)
        if not self.api_key:
            res.error = "URLSCAN_API_KEY not set in environment"
            return res

        try:
            r = requests.post(
                f"{API_BASE}/scan/",
                headers={"API-Key": self.api_key, "Content-Type": "application/json"},
                json={"url": url, "visibility": visibility},
                timeout=20,
            )
            if r.status_code == 400:
                res.error = f"submit rejected: {r.json().get('message', r.text)[:200]}"
                return res
            r.raise_for_status()
        except requests.RequestException as e:
            res.error = f"submit failed: {e}"
            return res

        body = r.json()
        res.uuid = body.get("uuid")
        res.page_url = body.get("result")
        res.dom_url = body.get("api")
        res.submitted = True

        result_api = body.get("api")
        if not result_api or not res.uuid:
            res.error = "submit response missing uuid"
            return res

        # Poll the result endpoint until ready or timeout.
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(3.0)
            try:
                rr = requests.get(result_api, timeout=15)
            except requests.RequestException:
                continue
            if rr.status_code == 404:
                continue  # still processing
            if rr.status_code == 200:
                payload = rr.json()
                verdicts = payload.get("verdicts", {}).get("overall", {}) or {}
                res.verdict = "malicious" if verdicts.get("malicious") else (
                    "suspicious" if verdicts.get("score", 0) > 0 else "neutral"
                )
                res.score = verdicts.get("score")
                res.screenshot_url = payload.get("task", {}).get("screenshotURL") or f"https://urlscan.io/screenshots/{res.uuid}.png"
                res.raw = {"verdicts": verdicts}
                break
        else:
            res.error = "result polling timed out"

        self._write_cache(res)
        return res
