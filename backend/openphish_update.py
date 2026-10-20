"""Refresh the local OpenPhish Community feed snapshot used by the API lookup.

Usage: python -m backend.openphish_update [--force]
Writes data/feeds/openphish/feed_<UTC>.txt + feed_<UTC>.json (provenance). The frozen evaluation snapshot in
data/raw/openphish/ is never modified. OpenPhish terms: research/personal use, no redistribution -> files stay local
(gitignored). The feed updates every 12 h, so refreshing more often is refused unless --force.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime

from backend.threat_intel import OPENPHISH_DIRS, latest_openphish_snapshot
from ml.external_data import OPENPHISH_COMMITS, OPENPHISH_FEED, _get, parse_openphish
from ml.utils import ROOT, save_json, sha256

MIN_HOURS = 12


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    last = latest_openphish_snapshot()
    if last and not args.force:
        age = (datetime.now(UTC) - datetime.strptime(last.stem[5:], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)).total_seconds() / 3600
        if age < MIN_HOURS:
            raise SystemExit(f"Latest snapshot {last.name} is {age:.1f} h old (< {MIN_HOURS} h); use --force to override.")
    out_dir = OPENPHISH_DIRS[0]
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    data = _get(OPENPHISH_FEED)
    urls = parse_openphish(data.decode("utf-8"))
    if not urls:
        raise SystemExit("Feed download contained no URLs; snapshot not written.")
    path = out_dir / f"feed_{stamp}.txt"
    path.write_bytes(data)
    commit = json.loads(_get(OPENPHISH_COMMITS))[0]
    save_json({"source": OPENPHISH_FEED, "fetched_at_utc": stamp, "github_commit": commit["sha"],
               "commit_time_utc": commit["commit"]["committer"]["date"], "urls": len(urls), "sha256": sha256(path),
               "terms": "OpenPhish Terms of Use: research/personal use; no redistribution"}, path.with_suffix(".json"))
    print(f"Wrote {path.relative_to(ROOT)} ({len(urls)} URLs, commit {commit['sha'][:7]})")


if __name__ == "__main__":
    main()
