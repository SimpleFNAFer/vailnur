"""
CSRF Detector — HTTP inference server

POST /predict
  Body:  { "method": "POST", "url": "https://...", "params": {"key": ["val"]} }
  Reply: { "label": "csrf"|"safe", "probability": 0.0-1.0,
           "branch_probs": {"mitch": float, "dwvm": float, "hackerone": float} }

POST /predict/batch
  Body:  [ { "method": ..., "url": ..., "params": ... }, ... ]
  Reply: [ { same as /predict }, ... ]

GET /health
  Reply: { "status": "ok" }

Run:
  .venv/bin/uvicorn ml.server:app --host 0.0.0.0 --port 8000
  or:
  .venv/bin/python ml/server.py
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ml.model import CSRFDetector


# ── Shared state ──────────────────────────────────────────────────────────────

detector: CSRFDetector | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector
    detector = CSRFDetector.load()
    yield


app = FastAPI(title="CSRF Detector", lifespan=lifespan)


# ── Schemas ───────────────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    method: str
    url: str
    params: dict[str, list[str]] = {}


class BranchProbs(BaseModel):
    mitch: float
    dwvm: float
    hackerone: float


class PredictResponse(BaseModel):
    label: str
    probability: float
    branch_probs: BranchProbs


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest) -> Any:
    if detector is None:
        raise HTTPException(status_code=503, detail="model not loaded")
    result = detector.from_request(req.method, req.url, req.params)
    return {**result, "branch_probs": result["branch_probs"]}


@app.post("/predict/batch", response_model=list[PredictResponse])
def predict_batch(reqs: list[PredictRequest]) -> Any:
    if detector is None:
        raise HTTPException(status_code=503, detail="model not loaded")
    if not reqs:
        return []
    feature_dicts = [
        CSRFDetector.extract_features(r.method, r.url, r.params) for r in reqs
    ]
    return detector.predict_batch(feature_dicts)


# ── Dev entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ml.server:app", host="0.0.0.0", port=8000, reload=False)
