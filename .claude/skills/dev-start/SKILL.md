---
name: dev-start
description: Start all three services (Python ML server, Go backend, frontend dev server) in the correct order for local development. Use when you want to run the full stack locally.
disable-model-invocation: true
---

Start the full development stack in order. Each step depends on the previous being healthy.

## Step 1: Python ML Server (`ml/`)

```bash
cd ml && python server.py
# or: uvicorn server:app --reload   (if using FastAPI)
# or: flask run                      (if using Flask)
```

Run in the background. Wait for the server to print a "listening" or "running" message before proceeding.

Note the port it binds to — update CLAUDE.md if it differs from the documented port.

## Step 2: Go Backend (`backend/`)

```bash
cd backend && go run .
# or: go run cmd/server/main.go
```

Run in the background. Wait for it to be ready before starting the frontend.

Confirm it can reach the Python ML server by checking its startup logs.

## Step 3: Frontend (`frontend/`)

```bash
cd frontend && npm run dev
# or: yarn dev
```

Run in the background. Print the local URL once available (e.g., http://localhost:5173).

## Output

Print all three service URLs once they're running:
- ML server: http://localhost:PORT
- Go backend: http://localhost:PORT
- Frontend: http://localhost:PORT

If any service fails to start, print the error and stop — don't start dependent services.
