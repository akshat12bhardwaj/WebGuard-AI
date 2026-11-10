"""Download and safely extract the UCI PhiUSIIL dataset (skips the download if a valid copy exists).

Usage: python -m ml.data_download [--force]
Writes: data/raw/phiusiil.zip, data/raw/phiusiil/*.csv, reports/metrics/download_provenance.json
"""
from __future__ import annotations

import argparse
import urllib.request
import zipfile
from pathlib import Path

from ml.utils import METRICS, RAW, RAW_CSV, get_logger, now_utc, save_json, sha256

URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
ZIP = RAW / "phiusiil.zip"
log = get_logger("data_download")


def safe_extract(zip_path: Path, target: Path) -> list[str]:
    """Extract, refusing members that would land outside `target` (zip-slip)."""
    target = target.resolve()
    with zipfile.ZipFile(zip_path) as z:
        bad = z.testzip()
        if bad:
            raise RuntimeError(f"Corrupt member in archive: {bad}")
        for m in z.infolist():
            if not (target / m.filename).resolve().is_relative_to(target):
                raise RuntimeError(f"Unsafe path in archive: {m.filename}")
        z.extractall(target)
        return [m.filename for m in z.infolist()]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true", help="re-download even if a valid copy exists")
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)

    if ZIP.exists() and zipfile.is_zipfile(ZIP) and not args.force:
        log.info("Existing archive found, validating instead of downloading: %s", ZIP)
        downloaded_at = None
    else:
        log.info("Downloading %s", URL)
        req = urllib.request.Request(URL, headers={"User-Agent": "website-risk-analyzer-student/1.0"})
        with urllib.request.urlopen(req, timeout=120) as r:
            ctype = r.headers.get("Content-Type", "")
            data = r.read()
        if "html" in ctype.lower() or not data.startswith(b"PK"):
            raise RuntimeError(f"Download is not a ZIP (Content-Type={ctype!r}); got an error page?")
        ZIP.write_bytes(data)
        downloaded_at = now_utc()

    members = safe_extract(ZIP, RAW / "phiusiil")
    if not RAW_CSV.exists():
        raise FileNotFoundError(f"Expected {RAW_CSV} after extraction; archive members: {members}")
    prov = {
        "source_page": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset",
        "download_url": URL, "downloaded_at_utc": downloaded_at, "validated_at_utc": now_utc(),
        "zip_path": str(ZIP.relative_to(RAW.parents[1])), "zip_bytes": ZIP.stat().st_size, "zip_sha256": sha256(ZIP),
        "members": members, "csv_path": str(RAW_CSV.relative_to(RAW.parents[1])),
        "csv_bytes": RAW_CSV.stat().st_size, "csv_sha256": sha256(RAW_CSV),
    }
    old = METRICS / "download_provenance.json"
    if downloaded_at is None and old.exists():  # keep the original download date
        import json
        prov["downloaded_at_utc"] = json.loads(old.read_text()).get("downloaded_at_utc")
    save_json(prov, old)
    log.info("Dataset ready: %s (%d bytes, sha256 %s)", RAW_CSV.name, prov["csv_bytes"], prov["csv_sha256"])


if __name__ == "__main__":
    main()
