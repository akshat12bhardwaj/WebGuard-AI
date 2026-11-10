import sys

# Served by `uvicorn backend.api:app`: load the repository .env before backend.api and backend.threat_intel are imported,
# so keys such as GOOGLE_SAFE_BROWSING_KEY reach the API. Only under uvicorn: pytest and the Phase 6 runner never import
# it, so tests and the frozen evaluation keep seeing only their own environment. Shell variables win; names only printed.
if "uvicorn" in sys.modules:
    from backend.serve import load_env

    if names := load_env():
        print(f"Loaded from .env: {', '.join(sorted(names))}")
