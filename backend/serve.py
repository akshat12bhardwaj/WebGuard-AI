"""Load the repository's .env for the local API. Two equivalent ways to start it:
    python -m backend.serve  [--host 127.0.0.1] [--port 8000]
    uvicorn backend.api:app --host 127.0.0.1 --port 8000      (backend/__init__.py calls load_env() under uvicorn)

The backend reads keys such as GOOGLE_SAFE_BROWSING_KEY from the environment only (backend/threat_intel.py, frozen for
Phase 6), and uvicorn's own --env-file needs python-dotenv, which is not installed; this uses the standard library.
Variables already set in the environment always win; empty values are skipped, so a missing or empty key still
reports `not_configured`. Values are never printed or logged.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"  # repository root, independent of the working directory


def load_env(path: Path | None = None) -> list[str]:
    """Set KEY=VALUE pairs from `path` (default: $WRA_ENV_FILE, else the repository .env) that are not already in
    os.environ. Returns the names set (never values)."""
    path = Path(path or os.environ.get("WRA_ENV_FILE") or ENV_FILE)
    if not path.is_file():
        return []
    loaded = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.removeprefix("export ").split("=", 1)
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:  # inline comment after an unquoted value
            value = value.split(" #", 1)[0].rstrip()
        if name.isidentifier() and value and name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()
    names = load_env()
    print(f"Loaded from .env: {', '.join(sorted(names)) or 'nothing'}")  # names only
    import uvicorn  # after load_env: threat_intel reads its settings at import time

    uvicorn.run("backend.api:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
