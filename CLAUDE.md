# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Multilingual security project with three components that communicate at runtime:

```
frontend/ → backend/ → ml/
(React/Vue)  (Go)      (Python + TensorFlow)
```

- **ml/** — Python: TensorFlow model with three branches and two levels, training datasets, saved model file, and an HTTP server that accepts inference requests
- **backend/** — Go: HTTP server that proxies/transforms requests from the frontend to the Python ML server
- **frontend/** — React or Vue (TBD): user-facing UI that talks to the Go backend

## Monorepo Structure

Each component lives in its own top-level directory with its own dependency management:

```
ml/          # Python package (pyproject.toml or requirements.txt)
backend/     # Go module (go.mod)
frontend/    # JS/TS project (package.json)
```

## Inter-Service Communication

- Frontend → Go backend: REST or GraphQL (decide and document here when settled)
- Go backend → Python ML server: HTTP POST with inference params, JSON response
- Python ML server port: **TBD** (document the agreed port here once fixed)
- Go backend port: **TBD**
- Frontend dev port: **TBD**

## Python ML Module (`ml/`)

- Framework: TensorFlow
- Model architecture: three branches, two levels (details TBD — update this section when defined)
- Datasets: three datasets for training (details TBD)
- The Python server receives requests with model input params and returns model predictions
- When adding new model code, keep the training pipeline, model definition, and server in separate files

## Go Backend (`backend/`)

- Sends requests to the Python ML server and forwards responses to the frontend
- Details TBD — update when the backend design is settled

## Frontend (`frontend/`)

- Framework TBD (React, Vue, or another reactive framework)
- Details TBD — update when the framework is chosen

## Security

This is a security-focused project. When writing code:
- Validate and sanitize all inputs at each service boundary
- Never expose raw model internals or internal error details to the frontend
- Use HTTPS between services in production
- Document any security assumptions in the relevant component's README

## Development Notes

- Run `/dev-start` to start all three services in order
- Run `/verify` to check all three components before committing
- Add component-specific CLAUDE.md files under `ml/`, `backend/`, and `frontend/` as each matures
