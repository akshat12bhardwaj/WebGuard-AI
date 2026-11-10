import pandas as pd
import pytest

from ml.external_data import EXTERNAL, host_rows, parse_openphish, parse_tranco
from ml.kaggle_data import binary_hosts, overlap, to_binary, url_key
from ml.utils import PROCESSED


def test_parse_openphish_dedupes_and_skips_blanks():
    text = "https://a.example/x\n\nhttps://a.example/x\n# note\nhttp://b.example/\n"
    assert parse_openphish(text) == ["https://a.example/x", "http://b.example/"]


def test_parse_tranco():
    df = parse_tranco("1,google.com\n2,Facebook.com\r\nbad line\n")
    assert df.to_dict("list") == {"rank": [1, 2], "domain": ["google.com", "facebook.com"]}
    with pytest.raises(ValueError):
        parse_tranco("rank,domain\n")


def test_host_rows_drops_invalid_and_duplicates():
    rows = host_rows(["https://a.example.com/x", "a.example.com", "javascript:x"], 0, "t")
    assert list(rows["host"]) == ["a.example.com"] and rows["reg_domain"].item() == "example.com"


def test_kaggle_schema_and_label_normalisation():
    raw = pd.DataFrame({"url": ["br-icloud.com.br", "en.wikipedia.org/wiki/X", "http://x.ru/a.exe", "evil.com/"],
                        "type": ["phishing", "benign", "malware", "defacement"]})
    b = to_binary(raw)
    assert list(b["is_phishing"]) == [1, 0]  # phishing = 1, benign = 0, other threats excluded
    hosts, _ = binary_hosts(raw)
    assert dict(zip(hosts["host"], hosts["is_phishing"])) == {"br-icloud.com.br": 1, "en.wikipedia.org": 0}
    with pytest.raises(ValueError):
        to_binary(pd.DataFrame({"URL": ["a"], "label": [1]}))


def test_url_and_domain_overlap_detection():
    assert url_key("WWW.Example.com/a/") == url_key("https://example.com/a") == "example.com/a"
    assert url_key("javascript:x") is None
    a = pd.DataFrame({"reg_domain": ["example.com", "x.org"]})
    b = pd.DataFrame({"reg_domain": ["example.com", "y.net"]})
    assert overlap(a, b, "reg_domain") == 1


@pytest.mark.skipif(not EXTERNAL.exists(), reason="external set not built (python -m ml.external_data)")
def test_external_set_integrity():
    ext = pd.read_csv(EXTERNAL, keep_default_na=False)
    train = set(pd.read_csv(PROCESSED / "train.csv", keep_default_na=False, usecols=["reg_domain"])["reg_domain"])
    assert not set(ext["reg_domain"]) & train
    assert ext["host"].is_unique and set(ext["is_phishing"]) == {0, 1}
    assert (ext.loc[ext["subset"] == "openphish", "is_phishing"] == 1).all()
    assert (ext.loc[ext["subset"] != "openphish", "is_phishing"] == 0).all()
