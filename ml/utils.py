"""Shared paths, logging, JSON helpers and metrics for the ML pipeline."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
RAW, PROCESSED = ROOT / "data" / "raw", ROOT / "data" / "processed"
MODELS, METRICS, FIGURES = ROOT / "models", ROOT / "reports" / "metrics", ROOT / "reports" / "figures"
SEED = 42
RAW_CSV = RAW / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"


def get_logger(name: str) -> logging.Logger:
    """Console + logs/implementation.log logger (never log secrets or full datasets)."""
    log = logging.getLogger(name)
    if not log.handlers:
        (ROOT / "logs").mkdir(exist_ok=True)
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        for h in (logging.StreamHandler(), logging.FileHandler(ROOT / "logs" / "implementation.log", encoding="utf-8")):
            h.setFormatter(fmt)
            log.addHandler(h)
        log.setLevel(logging.INFO)
    return log


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_json(obj, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)))


def binary_metrics(y_true, prob, threshold: float = 0.5) -> dict:
    """Metrics with phishing = positive class (1)."""
    y_true, prob = np.asarray(y_true), np.asarray(prob)
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    both = len(np.unique(y_true)) == 2
    return {
        "threshold": round(float(threshold), 4),
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, prob)) if both else float("nan"),
        "pr_auc": float(average_precision_score(y_true, prob)) if both else float("nan"),
        "brier": float(brier_score_loss(y_true, prob)),
        "fpr": float(fp / (fp + tn)) if fp + tn else float("nan"),
        "fnr": float(fn / (fn + tp)) if fn + tp else float("nan"),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def rounded(d: dict, nd: int = 4) -> dict:
    return {k: round(v, nd) if isinstance(v, float) else v for k, v in d.items()}
