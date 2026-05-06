"""Fetch phishing .eml samples from the public phishing_pot corpus into samples/emails/.

Usage:
    python scripts/fetch_samples.py --count 50

The corpus is rf-peixoto/phishing_pot on GitHub (MIT-licensed, ~2k samples).
We shallow-clone into a temp directory and copy a randomized subset into samples/emails/.
"""
from __future__ import annotations

import argparse
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORPUS_URL = "https://github.com/rf-peixoto/phishing_pot.git"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = PROJECT_ROOT / "samples" / "emails"


def clone_corpus(dest: Path) -> None:
    cmd = ["git", "clone", "--depth", "1", CORPUS_URL, str(dest)]
    subprocess.run(cmd, check=True)


def collect_emls(corpus_dir: Path, count: int, seed: int) -> list[Path]:
    all_emls = sorted(corpus_dir.rglob("*.eml"))
    if not all_emls:
        raise SystemExit("No .eml files found in cloned corpus — repo layout may have changed.")
    random.seed(seed)
    if count >= len(all_emls):
        return all_emls
    return random.sample(all_emls, count)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=50, help="number of .eml files to copy (default: 50)")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed for reproducible selection")
    parser.add_argument("--clean", action="store_true", help="empty samples/emails/ before fetching")
    args = parser.parse_args()

    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    if args.clean:
        for f in TARGET_DIR.glob("*.eml"):
            f.unlink()

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / "phishing_pot"
        print(f"[*] Cloning {CORPUS_URL} ...")
        clone_corpus(tmp_path)
        picks = collect_emls(tmp_path, args.count, args.seed)
        print(f"[*] Copying {len(picks)} samples into {TARGET_DIR} ...")
        for src in picks:
            shutil.copy2(src, TARGET_DIR / src.name)
    print(f"[+] Done. {len(picks)} .eml files in {TARGET_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
