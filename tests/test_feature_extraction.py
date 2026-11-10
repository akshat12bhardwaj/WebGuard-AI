import math

import pytest

from ml.feature_extraction import (
    FEATURE_NAMES,
    InvalidURLError,
    extract_features,
    get_host,
    normalize_url,
    registered_domain,
)


def test_valid_url_has_all_features_and_finite_values():
    f = extract_features("https://login.example.co.uk/path?q=1")
    assert list(f) == FEATURE_NAMES
    assert all(math.isfinite(v) for v in f.values())
    assert f["subdomain_count"] == 1 and f["tld_length"] == len("co.uk")


def test_scheme_path_and_www_do_not_change_features():
    assert extract_features("example.com") == extract_features("https://WWW.Example.com./a/b?c=1")
    assert normalize_url("example.com") == "http://example.com"


def test_ip_hostnames():
    f = extract_features("http://192.0.2.1:8080/login")
    assert f["is_ip"] == 1 and f["num_numeric_labels"] == 0 and f["tld_length"] == 0
    assert registered_domain("192.0.2.1") == "192.0.2.1"
    assert extract_features("http://[2001:db8::1]/")["is_ip"] == 1


def test_long_hostname():
    host = "a" * 60 + "." + "b" * 60 + ".example.com"
    f = extract_features(f"https://{host}/")
    assert f["host_length"] == len(host) and f["longest_label_length"] == 60


def test_unicode_and_punycode_hostnames_agree():
    assert get_host("https://bücher.de/") == "xn--bcher-kva.de"
    assert extract_features("https://bücher.de/") == extract_features("https://xn--bcher-kva.de")
    assert extract_features("https://xn--bcher-kva.de")["has_punycode"] == 1


@pytest.mark.parametrize("bad", ["", "   ", None, 42, "javascript:alert(1)", "mailto:a@b.com",
                                 "ftp://x.com", "http://", "http://exa mple.com", "http://x.com:99999", "http://[invalid/path",
                                 "a" * 3000])
def test_invalid_inputs_raise(bad):
    with pytest.raises(InvalidURLError):
        extract_features(bad)


def test_repeated_calls_are_deterministic():
    url = "https://secure-paypal.verify-account.web.app/x"
    assert all(extract_features(url) == extract_features(url) for _ in range(5))


def test_registered_domain_uses_public_suffix():
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("x.web.app") == "web.app"  # ICANN-only PSL: private suffixes not split
    assert registered_domain("host.unknownsuffixzz") == "host.unknownsuffixzz"
