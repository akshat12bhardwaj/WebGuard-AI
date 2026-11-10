"""Standalone inference: load models/model_bundle.joblib and score URLs (no page is fetched).

Usage: python -m ml.predict https://example.com [more URLs]
Output is the calibrated model probability only; it is NOT the final 0-100 risk score.
"""
from __future__ import annotations

import argparse
import json

import joblib
import pandas as pd

from ml.feature_extraction import InvalidURLError, extract_features
from ml.utils import MODELS


def load_bundle(path=MODELS / "model_bundle.joblib") -> dict:
    # joblib/pickle can execute code: only load bundles you trained yourself.
    return joblib.load(path)


def predict(bundle: dict, url: str) -> dict:
    feats = extract_features(url)
    p = float(bundle["model"].predict_proba(pd.DataFrame([feats])[bundle["features"]].astype(float))[0, 1])
    th = bundle["thresholds"]
    out_of_range = [f for f in bundle["features"] if not bundle["train_min"][f] <= feats[f] <= bundle["train_max"][f]]
    return {"url": url, "model_probability_phishing": p,  # unrounded: rounding shifts tied isotonic scores across thresholds
            "above_alert_threshold": p >= th["alert"],
            "above_high_threshold": p >= th["high"], "out_of_training_range": out_of_range,
            "model_version": bundle["version"]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("urls", nargs="+")
    bundle = load_bundle()
    for url in ap.parse_args().urls:
        try:
            print(json.dumps(predict(bundle, url)))
        except InvalidURLError as exc:
            print(json.dumps({"url": url, "error": str(exc)}))


if __name__ == "__main__":
    main()
