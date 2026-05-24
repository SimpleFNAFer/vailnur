---
name: verify
description: Run checks across all three project components (Python ML, Go backend, frontend) to validate changes before committing. Use this before any PR or commit.
---

Run verification checks across all components. For each component, only run if its directory exists.

## Python ML (`ml/`)

1. Run linting: `ruff check .` (or `flake8` if ruff is not installed)
2. Run type checking: `mypy .` if a `mypy.ini` or `py.typed` marker exists
3. Run tests: `pytest` (skip if no tests directory exists yet)
4. Report any failures clearly

## Go Backend (`backend/`)

1. Run `go vet ./...`
2. Run `go build ./...`
3. Run `go test ./...`
4. Report any failures clearly

## Frontend (`frontend/`)

1. Run `npm run lint` or `yarn lint` (whichever lockfile exists)
2. Run `npm run build` or `yarn build` to confirm the build compiles
3. Run `npm test` or `yarn test` if a test script exists
4. Report any failures clearly

## Summary

After running all checks, print a summary table:

| Component | Lint | Build/Type | Tests |
|-----------|------|------------|-------|
| ml/       | ✓/✗  | ✓/✗        | ✓/✗   |
| backend/  | ✓/✗  | ✓/✗        | ✓/✗   |
| frontend/ | ✓/✗  | ✓/✗        | ✓/✗   |

If any check failed, list the errors and suggest fixes.
