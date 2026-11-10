"""backend.serve: .env loading for the local API, and Google Safe Browsing configured vs not configured through
POST /api/v1/analyze. Uses temporary .env files with a fake key; the real .env is never read. No network: the HTTP layer
of backend.threat_intel is replaced by a mock transport."""
import os
import subprocess
import sys
import types
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import api, serve
from backend import threat_intel as ti
from backend.service import Analyzer
from ml.utils import MODELS

FAKE = "fake-test-key-123"
NAMES = ("GOOGLE_SAFE_BROWSING_KEY", "URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY", "A", "B", "C", "D", "E", "F")


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch):
    for n in NAMES:  # recorded by monkeypatch, so the original environment is restored after each test
        monkeypatch.setenv(n, "x")
        monkeypatch.delenv(n)
    ti._cache.clear()


def write(tmp_path, text):
    p = tmp_path / ".env"
    p.write_text(text, encoding="utf-8")
    return p


def test_load_env_parses_placeholders_comments_quotes_and_never_overrides(tmp_path, monkeypatch):
    p = write(tmp_path, "# comment\n\nA=1\nexport B=two\nC=\"quoted value\"\nD='single'\nE=v # note\nF=\nnot a line\n")
    monkeypatch.setenv("A", "from-shell")
    loaded = serve.load_env(p)
    assert loaded == ["B", "C", "D", "E"]  # names only; A already set; F empty
    assert os.environ["A"] == "from-shell" and os.environ["B"] == "two"
    assert os.environ["C"] == "quoted value" and os.environ["D"] == "single" and os.environ["E"] == "v"
    assert "F" not in os.environ


def test_load_env_without_file_is_a_no_op(tmp_path):
    assert serve.load_env(tmp_path / "missing.env") == []


def test_env_file_is_the_repository_root_not_the_working_directory():
    assert serve.ENV_FILE == MODELS.parent / ".env"


def test_launcher_loads_env_before_importing_the_app():
    src = Path(serve.__file__).read_text(encoding="utf-8")
    assert src.index("names = load_env()") < src.index("import uvicorn")
    assert "os.environ[name]" in src and "print(f\"Loaded from .env: {', '.join(sorted(names))" in src  # names, never values


def _child(code, tmp_path, env_text, **extra):
    """Run `code` in a fresh interpreter with a fake .env (never the real one) and no inherited reputation keys."""
    env = {k: v for k, v in os.environ.items() if k not in NAMES}
    env.update(WRA_ENV_FILE=str(write(tmp_path, env_text)), **extra)
    out = subprocess.run([sys.executable, "-c", code], check=False, cwd=MODELS.parent, env=env, capture_output=True,
                         text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-400:]
    return out.stdout


CHECK = "import os; print('KEY_SET' if os.environ.get('GOOGLE_SAFE_BROWSING_KEY') == '" + FAKE + "' else 'KEY_MISSING')"


def test_plain_uvicorn_start_loads_env_before_the_app(tmp_path):
    # what `uvicorn backend.api:app` does: uvicorn is imported first, then the app module by name
    out = _child("import uvicorn, importlib; importlib.import_module('backend.api'); " + CHECK, tmp_path,
                 f"GOOGLE_SAFE_BROWSING_KEY={FAKE}")
    assert "KEY_SET" in out and "Loaded from .env: GOOGLE_SAFE_BROWSING_KEY" in out
    assert FAKE not in out  # names only, never the value


def test_without_uvicorn_nothing_is_loaded(tmp_path):
    # pytest, scripts and the Phase 6 runner import backend without uvicorn: the .env is not read
    assert "KEY_MISSING" in _child("import backend.api; " + CHECK, tmp_path, f"GOOGLE_SAFE_BROWSING_KEY={FAKE}")


def test_shell_variable_wins_over_env_file(tmp_path):
    out = _child("import uvicorn, backend.api, os; print(os.environ['GOOGLE_SAFE_BROWSING_KEY'])", tmp_path,
                 "GOOGLE_SAFE_BROWSING_KEY=from-file", GOOGLE_SAFE_BROWSING_KEY="from-shell")
    assert out.strip().endswith("from-shell")


# ---------- through the API (needs the model bundle) ----------
needs_bundle = pytest.mark.skipif(not (MODELS / "model_bundle.joblib").exists(), reason="run the ML pipeline first")


@pytest.fixture
def mocked_http(monkeypatch):
    """Route threat_intel's HTTP calls to a mock; record which services were called and with which key."""
    calls = []

    def handler(req):
        calls.append((req.url.host, req.url.params.get("key")))
        if req.url.host == "safebrowsing.googleapis.com":
            return httpx.Response(200, json={})  # documented: empty object = no match
        if req.url.host == "checkurl.phishtank.com":
            return httpx.Response(200, json={"results": {"in_database": False}})
        return httpx.Response(404)
    fake = types.SimpleNamespace(Client=lambda **kw: httpx.Client(transport=httpx.MockTransport(handler)),
                                 TimeoutException=httpx.TimeoutException, HTTPError=httpx.HTTPError)
    monkeypatch.setattr(ti, "httpx", fake)
    return calls


def analyze(url="https://www.wikipedia.org/"):
    with TestClient(api.app) as c:
        api.state["analyzer"] = Analyzer()  # default lookups: the real threat_intel functions
        return c.post("/api/v1/analyze", json={"url": url})


def gsb(body):
    return next(t for t in body["evidence"]["threat_intel"] if t["source"] == "Google Safe Browsing")


@needs_bundle
def test_key_in_env_file_reaches_the_backend_and_is_checked(tmp_path, mocked_http):
    assert serve.load_env(write(tmp_path, f"GOOGLE_SAFE_BROWSING_KEY={FAKE}\nURLHAUS_AUTH_KEY=\n")) == ["GOOGLE_SAFE_BROWSING_KEY"]
    r = analyze()
    body = r.json()
    assert gsb(body)["status"] == "no_match"
    assert "Google Safe Browsing not checked: not_configured" not in body["assessment"]["notes"]
    assert ("safebrowsing.googleapis.com", FAKE) in mocked_http  # the key from .env was used for the request
    assert FAKE not in r.text  # never echoed back


@needs_bundle
def test_without_a_key_the_backend_runs_and_reports_not_configured(tmp_path, mocked_http):
    assert serve.load_env(write(tmp_path, "GOOGLE_SAFE_BROWSING_KEY=\n")) == []
    body = analyze().json()
    assert gsb(body)["status"] == "not_configured"
    assert "Google Safe Browsing not checked: not_configured" in body["assessment"]["notes"]
    assert not any(host == "safebrowsing.googleapis.com" for host, _ in mocked_http)
