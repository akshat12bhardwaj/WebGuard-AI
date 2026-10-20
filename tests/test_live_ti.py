"""LIVE smoke tests against the real services. Skipped unless WRA_LIVE_TESTS=1 (they use the network)."""
import os

import pytest

from backend import threat_intel as ti

pytestmark = pytest.mark.skipif(os.getenv("WRA_LIVE_TESTS") != "1", reason="set WRA_LIVE_TESTS=1 to call live APIs")


def test_live_phishtank_benign_url_is_checked():
    ti._cache.clear()
    r = ti.check_phishtank("https://www.wikipedia.org/")
    assert r.status in ("no_match", "unverified"), r  # observed 2026-10-15: unverified (reported, not verified)


@pytest.mark.skipif(not os.getenv("URLHAUS_AUTH_KEY"), reason="URLHAUS_AUTH_KEY not set")
def test_live_urlhaus_benign_url_is_checked():
    assert ti.check_urlhaus("https://www.wikipedia.org/").status == "no_match"


@pytest.mark.skipif(not os.getenv("GOOGLE_SAFE_BROWSING_KEY"), reason="GOOGLE_SAFE_BROWSING_KEY not set")
def test_live_safe_browsing_benign_url_is_checked():
    ti._cache.clear()
    assert ti.check_safe_browsing("https://www.wikipedia.org/").status == "no_match"
