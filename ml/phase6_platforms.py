"""Evaluation-only hosting-platform list for the Phase 6 supplementary group (protocol section 5, D55).

Never used by production code. Built deterministically from two documented sources:
  1. the PRIVATE section of the Public Suffix List snapshot bundled with tldextract (domains whose owners declare that
     third parties register names under them, e.g. pages.dev, vercel.app, typedream.app);
  2. the production list SHARED_HOSTING_SUFFIXES (ml/feature_extraction.py), unchanged.
Hosts on neither list are 'unknown' and never counted as confirmed shared hosting.
Usage: python -m ml.phase6_platforms   (writes ml/phase6_platforms.json once; refuses to overwrite)
"""
from __future__ import annotations

import json
from functools import cache
from pathlib import Path

import tldextract
from tldextract.suffix_list import extract_tlds_from_suffix_list

from ml.feature_extraction import SHARED_HOSTING_SUFFIXES
from ml.utils import sha256

LIST_PATH = Path(__file__).with_name("phase6_platforms.json")
PSL_SNAPSHOT = Path(tldextract.__file__).parent / ".tld_set_snapshot"
VERSION = "1"


def _canonical(suffix: str) -> str:
    """Same form as get_host(): lower case, IDNs as punycode (stdlib IDNA 2003 codec), so Unicode entries can match."""
    s = suffix.lower()
    return s if s.isascii() else s.encode("idna").decode("ascii")


def build() -> dict:
    _, private = extract_tlds_from_suffix_list(PSL_SNAPSHOT.read_text(encoding="utf-8"))
    # '*.x' wildcards mean every name under x is delegated; '!' exceptions carve names back out -> not platforms.
    psl = sorted({_canonical(s.removeprefix("*.")) for s in private if not s.startswith("!")})
    return {"version": VERSION, "purpose": "Phase 6 supplementary group only; not used by production",
            "sources": {"psl_private": {"file": f"tldextract {tldextract.__version__} bundled .tld_set_snapshot",
                                        "sha256": sha256(PSL_SNAPSHOT), "licence": "MPL-2.0 (Public Suffix List)",
                                        "count": len(psl)},
                        "production_shared_hosting": {"file": "ml/feature_extraction.py SHARED_HOSTING_SUFFIXES",
                                                      "count": len(SHARED_HOSTING_SUFFIXES)}},
            "suffixes": sorted(set(psl) | set(SHARED_HOSTING_SUFFIXES))}


@cache
def suffixes(path: Path = LIST_PATH) -> frozenset[str]:
    return frozenset(json.loads(path.read_text(encoding="utf-8"))["suffixes"])


def is_platform(host: str, platform_suffixes: frozenset[str] | None = None) -> bool:
    """True if the host is strictly under a listed platform suffix (the platform's own apex does not count)."""
    s = platform_suffixes if platform_suffixes is not None else suffixes()
    labels = host.split(".")
    return any(".".join(labels[i:]) in s for i in range(1, len(labels)))


def main() -> None:
    with open(LIST_PATH, "x", encoding="utf-8") as f:
        json.dump(build(), f, indent=1)
    print(f"Wrote {LIST_PATH.name} ({len(suffixes())} suffixes)")


if __name__ == "__main__":
    main()
