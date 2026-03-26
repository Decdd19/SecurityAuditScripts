# HTTP Security Headers Auditor

Audits a domain's HTTP security response headers over HTTPS. No credentials required — uses outbound HTTPS on port 443 only.

## Checks

| ID | Name | Condition | Severity |
|---|---|---|---|
| HDR-00 | Connectivity | Could not connect | CRITICAL |
| HDR-01 | X-Frame-Options | Header absent | HIGH |
| HDR-01 | X-Frame-Options | ALLOW-FROM (deprecated) | WARN |
| HDR-02 | X-Content-Type-Options | Header absent or not `nosniff` | MEDIUM |
| HDR-03 | Content-Security-Policy | Header absent | HIGH |
| HDR-03 | Content-Security-Policy | Contains `unsafe-inline` or `unsafe-eval` | WARN |
| HDR-04 | Referrer-Policy | Header absent or unsafe value | MEDIUM |
| HDR-05 | Permissions-Policy | Header absent | WARN |

## Usage

### Standalone

```bash
python3 http_headers_auditor.py --domain acme.ie
python3 http_headers_auditor.py --domain acme.ie --port 8443
python3 http_headers_auditor.py --domain acme.ie --format all --output http_headers_report
```

### Via orchestrator

```bash
python3 audit.py --client "Acme Corp" --http-headers --domain acme.ie
python3 audit.py --client "Acme Corp" --ssl --http-headers --domain acme.ie
```

## Requirements

- Python 3.8+
- No external dependencies (stdlib only: `http.client`, `socket`, `csv`, `json`, `html`)
- Outbound HTTPS access to port 443 on the target domain

## Limitations

- **HTTPS only** — checks headers over port 443 by default. Use `--port 80` if you need to audit plain HTTP headers (uncommon for security headers).
- **Single request** — headers are read from a single `GET /` request. Subpath or redirect responses may present different headers.
- **Permissions-Policy** — reported as WARN (not FAIL) when absent; this is a newer spec and many servers do not yet set it.

## Tests

```bash
cd Network/http-headers-auditor
python -m pytest tests/ -v
```
