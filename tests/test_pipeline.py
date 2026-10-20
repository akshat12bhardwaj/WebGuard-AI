"""Data-preparation and model-pipeline tests on a small synthetic fixture (no real dataset needed)."""
import joblib
import numpy as np
import pandas as pd
import pytest
from xgboost import XGBClassifier

from ml.feature_extraction import FEATURE_NAMES, MODEL_FEATURES
from ml.predict import predict
from ml.preprocessing import preprocess
from ml.split_dataset import grouped_split
from ml.utils import binary_metrics


@pytest.fixture
def raw():
    rng = np.random.default_rng(0)
    rows = [(f"https://www.site{i}.com", 1) for i in range(300)]  # PhiUSIIL: 1 = legitimate
    rows += [(f"http://login-{i}.verify{rng.integers(1e6)}.web{i % 40}.xyz/a", 0) for i in range(300)]
    rows += [("https://www.site1.com", 1),           # duplicate host
             ("http://site2.com/x", 0),              # same host as a legitimate row -> conflict
             ("javascript:alert(1)", 0), (None, 1)]  # invalid / missing
    return pd.DataFrame(rows, columns=["URL", "label"])


def test_preprocess_labels_duplicates_conflicts_invalid(raw):
    out, rep = preprocess(raw)
    assert set(out["is_phishing"]) == {0, 1}
    assert out.loc[out["host"] == "site1.com", "is_phishing"].item() == 0  # label flipped: 1 -> legitimate
    assert rep["rows_missing_url_or_label"] == 1 and rep["rows_invalid_url"] == 1
    assert rep["hosts_with_conflicting_labels"] == 1 and "site2.com" not in set(out["host"])
    assert out["host"].is_unique and not out[FEATURE_NAMES].isna().any().any()
    assert "label" not in out.columns and "is_phishing" not in MODEL_FEATURES  # no target leakage


def test_preprocess_is_stable_and_rejects_bad_labels(raw):
    a, _ = preprocess(raw)
    b, _ = preprocess(raw)
    pd.testing.assert_frame_equal(a, b)
    with pytest.raises(ValueError):
        preprocess(pd.DataFrame({"URL": ["a.com"], "label": [2]}))


def test_grouped_split_proportions_and_no_domain_overlap(raw):
    out, _ = preprocess(raw)
    parts = grouped_split(out)
    sizes = {k: len(v) / len(out) for k, v in parts.items()}
    assert abs(sizes["train"] - 0.70) < 0.08 and abs(sizes["val"] - 0.15) < 0.08
    doms = [set(p["reg_domain"]) for p in parts.values()]
    assert not (doms[0] & doms[1] or doms[0] & doms[2] or doms[1] & doms[2])
    assert sum(map(len, parts.values())) == len(out)
    again = grouped_split(out)
    assert all(parts[k].index.equals(again[k].index) for k in parts)  # reproducible with seed 42


def test_train_save_load_predict(raw, tmp_path):
    out, _ = preprocess(raw)
    X, y = out[MODEL_FEATURES].astype(float), out["is_phishing"]
    model = XGBClassifier(n_estimators=20, max_depth=3, random_state=42).fit(X, y)
    bundle = {"model": model, "features": MODEL_FEATURES, "thresholds": {"alert": 0.4, "high": 0.6},
              "train_min": X.min().to_dict(), "train_max": X.max().to_dict(), "version": "test"}
    joblib.dump(bundle, tmp_path / "b.joblib")
    loaded = joblib.load(tmp_path / "b.joblib")
    p = loaded["model"].predict_proba(X)
    assert p.shape == (len(X), 2) and np.isfinite(p).all() and ((p >= 0) & (p <= 1)).all()
    r = predict(loaded, "https://www.site5.com/")  # inference uses the same extractor as training
    assert 0 <= r["model_probability_phishing"] <= 1
    assert r["model_probability_phishing"] == pytest.approx(float(p[out["host"] == "site5.com"][0, 1]), abs=1e-4)


def test_binary_metrics_match_hand_computation():
    m = binary_metrics([0, 0, 1, 1, 1], [0.1, 0.6, 0.7, 0.4, 0.9], threshold=0.5)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (2, 1, 1, 1)
    assert m["precision"] == pytest.approx(2 / 3) and m["recall"] == pytest.approx(2 / 3)
    assert m["fpr"] == pytest.approx(0.5) and m["accuracy"] == pytest.approx(0.6)
