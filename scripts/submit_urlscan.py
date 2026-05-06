"""Submit a single URL to urlscan.io and print the result. Used to enrich the
deep-dive reports with one verdict per sample.

Usage:
    python scripts/submit_urlscan.py <url>
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running as a standalone script from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from triage.urlscan_client import UrlscanClient  # noqa: E402


def main(url: str) -> int:
    load_dotenv()
    client = UrlscanClient()
    if not client.api_key:
        print("URLSCAN_API_KEY missing from environment / .env", file=sys.stderr)
        return 2
    res = client.submit_and_fetch(url, timeout=60.0)
    print(f"URL:        {res.url}")
    print(f"UUID:       {res.uuid or '-'}")
    print(f"Verdict:    {res.verdict or '-'}")
    print(f"Score:      {res.score if res.score is not None else '-'}")
    print(f"Result:     {res.page_url or '-'}")
    print(f"Screenshot: {res.screenshot_url or '-'}")
    if res.error:
        print(f"Error:      {res.error}")
    return 0 if not res.error else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
