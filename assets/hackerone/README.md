# HackerOne CSRF Dataset

HTTP requests derived from publicly disclosed CSRF vulnerability reports on the **HackerOne** bug bounty platform.

## Source

Reports were sourced from HackerOne's public disclosure feed, filtered to CSRF vulnerability class. Each entry reconstructs the HTTP request described in the report, with PII anonymized.

## Contents

- `dataset.json` — raw HTTP requests in compact JSON
- `dataset_prettified.json` — same data, human-readable
- `features_matrix.csv` — feature space representation (same schema as mitch)

## Statistics

| Label | Count |
|-------|-------|
| CSRF-vulnerable (`y`) | 58 |
| Safe (`n`) | 48 |
| **Total** | **106** |

## Programs / Websites Covered

| Website | Requests | CSRF | Safe |
|---------|----------|------|------|
| shopify | 15 | 7 | 8 |
| twitter_x | 17 | 10 | 7 |
| gitlab | 19 | 11 | 8 |
| uber | 12 | 7 | 5 |
| hackerone_platform | 13 | 8 | 5 |
| yahoo_mail | 14 | 8 | 6 |
| wordpress_vip | 16 | 7 | 9 |

## CSRF Vulnerability Patterns

Common patterns extracted from disclosed reports:

- **Account takeover vectors**: password change, email change, recovery email addition, SSH key injection
- **Privilege escalation**: adding admin users, changing user roles, installing plugins/themes
- **Data exfiltration setup**: creating webhooks to attacker-controlled servers, adding mail filters, setting auto-replies
- **Destructive actions**: deleting repositories, posts, payment methods; revoking OAuth tokens
- **Financial impact**: updating payment methods, applying discount codes, adding promo credits

## Feature Schema

Identical to the mitch dataset — see `../mitch/dataset/README.md` for full column descriptions.

## Notes

- All PII anonymized (`<email>`, `<password>`, `<username>`)
- Anti-CSRF tokens present in `flag=y` entries are empty strings (`""`) — reflecting reports where tokens were missing, predictable, or not validated
- HTTP methods include GET, POST, PUT, DELETE, OPTIONS — matching actual report reproductions
