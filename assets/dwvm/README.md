# DVWA CSRF Dataset

HTTP requests collected from **DVWA** (Damn Vulnerable Web Application) — a deliberately insecure PHP/MySQL web application used for security training.

## Source

DVWA provides intentionally vulnerable endpoints covering CSRF, SQL Injection, XSS, Command Injection, File Upload, and more. Requests were collected by interacting with the application at its default local deployment (`http://localhost/dvwa/`).

## Contents

- `dataset.json` — raw HTTP requests in compact JSON
- `dataset_prettified.json` — same data, human-readable
- `features_matrix.csv` — feature space representation (same schema as mitch)

## Statistics

| Label | Count |
|-------|-------|
| CSRF-vulnerable (`y`) | 17 |
| Safe (`n`) | 33 |
| **Total** | **50** |

## CSRF-vulnerable endpoints captured

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/dvwa/vulnerabilities/csrf/` | GET/POST | Password change (main CSRF demo) |
| `/dvwa/login.php` | POST | Login form |
| `/dvwa/security.php` | POST | Security level change |
| `/dvwa/vulnerabilities/xss_s/` | POST | Stored XSS message submission |
| `/dvwa/vulnerabilities/exec/` | POST | Command execution |
| `/dvwa/setup.php` | POST | Database setup/reset |
| `/dvwa/vulnerabilities/upload/` | POST | File upload |
| `/dvwa/vulnerabilities/brute/` | POST | Brute-force form |

## Feature Schema

Identical to the mitch dataset — see `../mitch/dataset/README.md` for full column descriptions.

## Notes

- Sensitive values (passwords, emails, usernames) are anonymized as `<password>`, `<email>`, `<username>`
- CSRF via GET is included (DVWA low-security mode allows password change through a crafted GET URL)
- Flag `y` = endpoint is CSRF-vulnerable (state-changing, no anti-CSRF token or bypassable token)
- Flag `n` = read-only or otherwise not CSRF-exploitable in the collected context
