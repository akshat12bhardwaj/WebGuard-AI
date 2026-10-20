"""Thin FastAPI layer (no Chrome extension yet).

Run from the repository root:  uvicorn backend.api:app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.fusion import fuse
from backend.service import Analyzer
from ml.feature_extraction import InvalidURLError

DISCLAIMER = ("Automated assessment from the URL, rules and threat-intelligence lists. It can be wrong; "
              "'low risk' or no threat-intelligence match is not proof that a site is safe.")
API_VERSION = "1.0"  # docs/API_CONTRACT.md; bump on any breaking schema change
state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    state["analyzer"] = Analyzer()
    yield


app = FastAPI(title="Website Risk Analyzer API", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origin_regex=r"chrome-extension://[a-p]{32}",
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


@app.get("/api/v1/health")
def health() -> dict:
    a = state.get("analyzer")
    return {"status": "ok", "model_loaded": bool(a and a.bundle), "api_version": API_VERSION}


@app.post("/api/v1/analyze")
def analyze(req: AnalyzeRequest) -> dict:  # sync: runs in FastAPI's threadpool
    try:
        ev, caveats = state["analyzer"].collect(req.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"api_version": API_VERSION, "assessment": fuse(ev, caveats).to_dict(), "evidence": ev.to_dict(),
            "disclaimer": DISCLAIMER}
