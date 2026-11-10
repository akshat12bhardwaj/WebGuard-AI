"""Real backend responses must pass the extension's JavaScript validator (keeps api.js in sync with the API)."""
import json
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from backend import api
from backend.evidence import TIResult
from ml.utils import MODELS, ROOT

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(not NODE or not (MODELS / "model_bundle.joblib").exists(), reason="needs node and the bundle")


@pytest.mark.parametrize("url,lookups", [
    ("https://www.wikipedia.org/", {"PhishTank": lambda u: TIResult("PhishTank", "no_match")}),
    ("https://secure-paypal.com/", {"URLhaus": lambda u: TIResult("URLhaus", "error", "timeout")}),
    ("https://x.example.org/", {"PhishTank": lambda u: TIResult("PhishTank", "match", "verified phish")}),
    ("http://192.168.1.10/admin", {"PhishTank": lambda u: TIResult("PhishTank", "no_match")}),
])
def test_real_response_passes_js_validator(tmp_path, url, lookups):
    with TestClient(api.app) as c:
        api.state["analyzer"].lookups = lookups
        body = c.post("/api/v1/analyze", json={"url": url}).json()
    f = tmp_path / "r.json"
    f.write_text(json.dumps(body), encoding="utf-8")
    out = subprocess.run([NODE, str(ROOT / "extension" / "tests" / "validate_cli.js"), str(f)],
                         capture_output=True, text=True, timeout=30, check=False)  # returncode asserted below
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["category"] == body["assessment"]["category"]
