# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CSRF vulnerability detection system for authorized penetration testing. Three components communicate at runtime:

```
frontend/ → backend/ → ml/
(React 18)   (Go)      (Python + TensorFlow)
```

- **ml/** — Python: stacked generalisation model (3 GBT branches + TF linear meta-classifier), HTTP inference server
- **backend/** — Go: BFS web crawler + HTML parser, ML client, CSRF exploit executor, REST API
- **frontend/** — React 18 (Vite): single-page pentest UI

## Monorepo Structure

```
ml/           # Python package — model.py, server.py, requirements.txt, saved_models/
backend/      # Go module — go.mod, main.go, internal/{api,crawler,mlclient,exploit,store}/
frontend/     # Vite/React — package.json, vite.config.js, src/
assets/       # Training datasets: mitch/, dwvm/, hackerone/
.venv/        # Python virtualenv (Python 3.14 + tf-nightly + sklearn + fastapi)
```

## Ports

| Service | Port | Notes |
|---------|------|-------|
| Python ML server | **8000** | uvicorn, FastAPI |
| Go backend | **8080** | chi router |
| Frontend dev server | **5173** | Vite, proxies /api → :8080 |

## Starting All Services

```bash
# 1. ML server (from project root)
.venv/bin/uvicorn ml.server:app --host 0.0.0.0 --port 8000

# 2. Go backend (from backend/)
go run .

# 3. Frontend (from frontend/)
npm run dev
```

Open **http://localhost:5173**.

## Inter-Service Communication

- **Frontend → Go backend**: REST JSON over HTTP, base path `/api`
- **Go backend → Python ML server**: `POST http://localhost:8000/predict/batch`
- All dependency installs must use `.venv/bin/pip` — never system pip

## Python ML Module (`ml/`)

### Model Architecture

Stacked generalisation, two levels:

1. **Level 1 — three GBT branches** (sklearn `GradientBoostingClassifier`, 300 estimators):
   - `branch_mitch` — trained on `assets/mitch/dataset/features_matrix.csv`
   - `branch_dwvm` — trained on `assets/dwvm/features_matrix.csv`
   - `branch_hackerone` — trained on `assets/hackerone/features_matrix.csv`
   - All 52 features go into every branch

2. **Level 2 — TF linear meta-classifier** (`Dense(1, sigmoid)`):
   - Input: `[p_mitch, p_dwvm, p_hackerone]`
   - Output: final CSRF probability

Training uses K-fold out-of-fold predictions (stacked generalisation) to avoid data leakage.

### Saved Models

```
ml/saved_models/
  branch_mitch.pkl
  branch_dwvm.pkl
  branch_hackerone.pkl
  meta_classifier.keras
```

### Feature Schema (52 columns)

5 numeric + 42 keyword-in-path/params flags (21 keywords × 2) + 5 HTTP method flags.
See `assets/mitch/dataset/README.md` for full column descriptions.

### Files

- `model.py` — training pipeline + `CSRFDetector` inference class
- `server.py` — FastAPI HTTP server wrapping `CSRFDetector`

### ML Server API

```
GET  /health
POST /predict        { method, url, params } → { label, probability, branch_probs }
POST /predict/batch  [{ method, url, params }] → [{ label, probability, branch_probs }]
```

To retrain: `python ml/model.py` (from project root, inside venv)

## Go Backend (`backend/`)

### Internal Packages

| Package | Responsibility |
|---------|---------------|
| `internal/api` | chi router, CORS middleware, HTTP handlers, request deduplication |
| `internal/crawler` | BFS web crawler — extracts `<a href>` (GET) and `<form>` (GET/POST) with `<input>`, `<textarea>`, `<select>` fields |
| `internal/mlclient` | HTTP client for `/predict/batch` on the ML server |
| `internal/exploit` | Executes exploit HTTP requests (GET with query params / POST with form body) |
| `internal/store` | In-memory job store (sync.RWMutex) for scan and exploit jobs |

### REST API

```
POST /api/scan           { url, depth?, max_pages? }  → { job_id }
GET  /api/scan/{id}      → ScanJob (status, candidates[])
POST /api/exploit        { targets[] }                → { job_id }
GET  /api/exploit/{id}   → ExploitJob (status, results[])
```

Jobs run in goroutines; clients poll GET endpoints.

### Crawler Notes

- BFS, same-domain only (Host match)
- Deduplicates requests by `method|url|sorted_params` before ML analysis
- Query params from `<a href="?key=val">` are moved into the `params` dict (not left in URL)
- Skips `input type="submit/button/reset/image"` from form params

## Frontend (`frontend/`)

- React 18 + Vite 5, no external UI libraries
- Single page, three sections:
  1. **Scan** — URL input, depth/max_pages settings, scan progress
  2. **CSRF Candidates** — table with checkboxes, probability bar, inline params editor
  3. **Exploit Results** — status codes (colored 2xx/3xx/4xx), response excerpts
- `/api` requests are proxied to `http://localhost:8080` by Vite dev server

## Datasets (`assets/`)

| Dataset | Source | Requests | CSRF rate |
|---------|--------|----------|-----------|
| mitch | Academic paper | 6204 | 14.9% |
| dwvm | DVWA | 617 | 19.1% |
| hackerone | HackerOne disclosures | 6102 | 41.9% |

All datasets share the same 54-column schema: `reqId`, `flag`, 52 feature columns.

## Security

This tool is for **authorized penetration testing only**. When writing code:
- Validate and sanitize all inputs at each service boundary
- Never expose raw model internals or internal error details to the frontend
- Use HTTPS between services in production
- The exploit module must only be used against systems you have permission to test

## Development Notes

- Run `/dev-start` to start all three services in order
- Run `/verify` to check all three components before committing
- Add component-specific CLAUDE.md files under `ml/`, `backend/`, and `frontend/` as each matures
