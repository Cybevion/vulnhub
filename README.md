# VulnLab — Web Application Security Demo Platform

**Built by Yuvraj Todankar | Cybevion**

An intentionally vulnerable web application for teaching web security concepts.  
Every module has a **Vulnerable mode** and a **Safe/Patched mode** side by side.

---

## ⚠️ WARNING

This app is **deliberately insecure**. Run it only in an isolated lab environment.  
**Never expose it to the internet or a production network.**

---

## Quick Start

### Option 1 — Docker (recommended)

```bash
docker compose up --build
# Visit http://localhost:5005
```

### Option 2 — Python directly

```bash
pip install -r requirements.txt
python app.py
# Visit http://localhost:5002
```

> **Note:** Docker maps container port `5002` → host port `5005`. If running via Docker, access the app at `http://localhost:5005`, not `5000`.

---

## Modules

| # | Module | OWASP | Severity | Route |
|---|--------|-------|----------|-------|
| 1 | SQL Injection — Auth Bypass | A03:2021 | CRITICAL | `/sqli/login` |
| 2 | SQL Injection — UNION Extract | A03:2021 | CRITICAL | `/sqli/search` |
| 3 | XSS — Reflected | A03:2021 | CRITICAL | `/xss/reflected` |
| 4 | XSS — Stored | A03:2021 | CRITICAL | `/xss/stored` |
| 5 | IDOR — Profile | A01:2021 | CRITICAL | `/idor/profile` |
| 6 | IDOR — Orders | A01:2021 | CRITICAL | `/idor/orders` |
| 7 | CSRF — Fund Transfer | A01:2021 | HIGH | `/csrf/transfer` |
| 8 | File Upload → Web Shell | A03:2021 | CRITICAL | `/upload` |
| 9 | SSRF — URL Fetch | A10:2021 | HIGH | `/ssrf/fetch` |
| 10 | JWT — None Alg + Weak Secret | A07:2021 | HIGH | `/jwt/login` |
| 11 | SSTI — Jinja2 | A03:2021 | CRITICAL | `/ssti` |
| 12 | Open Redirect | A01:2021 | MEDIUM | `/redirect` |
| 13 | Security Headers | A05:2021 | HIGH | `/headers` |
| 14 | Business Logic — Price Tamper | A04:2021 | HIGH | `/logic/checkout` |

---

## Test Accounts

| Username | Password | Role | ID |
|----------|----------|------|----|
| admin | admin123 | admin | 1 |
| alice | password1 | user | 2 |
| bob | bob123 | user | 3 |
| charlie | charlie456 | user | 4 |

---

## Safe Mode Toggle

Every route accepts `?safe=0` (vulnerable) or `?safe=1` (patched).  
The UI shows what changed and why the fix works.

```
# Vulnerable mode (default)
http://localhost:5005/sqli/login?safe=0

# Patched mode
http://localhost:5005/sqli/login?safe=1
```

---

## Usage with Burp Suite

1. Set browser proxy to `127.0.0.1:8080`
2. Open Burp → Proxy → Intercept On
3. Use the app normally — intercept and modify requests
4. Good targets: `price` field in `/logic/checkout`, `id` param in `/idor/profile`

---

## Recommended Lab Flow (per module)

1. Understand the vulnerable code (shown in UI)
2. Exploit it in `?safe=0` mode
3. Switch to `?safe=1` — see the fix in action
4. Read the diff — understand WHY the fix works

---

## Bonus Findings (Undocumented)

These are intentional vulnerabilities not listed in the main module table. Find them yourself — or use them to challenge advanced students.

### API — Unauthenticated Data Exposure
`GET /api/users` — In vulnerable mode (`?safe=0`), this endpoint requires no authentication and returns the full users table including SSN, address, balance, and plaintext passwords. In safe mode, it enforces session auth and filters to `id`, `username`, `email` only.

### API — IDOR in Messages
`GET /api/message/<id>` — In vulnerable mode, any authenticated user can retrieve any message by ID. Safe mode enforces that `sender_id` or `receiver_id` must match the session user.

### Session Cookie Forgery
`app.secret_key` is set to `supersecretkey123` — intentionally weak. Flask session cookies are signed with this key. A student who knows the secret can forge session cookies using tools like `flask-unsign` to impersonate any user, including admin. This is not covered in a dedicated module but can be explored independently.

---

## ⚠️ Instructor Notes

Important behaviours to communicate to students before starting labs:

### SSTI is Live Code Execution
Module 11 (`/ssti`) uses `render_template_string()` with unsanitised user input. Jinja2 payloads like `{{7*7}}`, `{{config}}`, and full RCE sandbox-escape chains will **actually execute** inside the Python process. Since the app runs in Docker, the blast radius is contained — but students should understand they are executing real server-side code, not a simulation. This is intentional: the goal is to demonstrate real impact.

### Path Traversal on File Serve Endpoint
The route `/upload/serve/<path:filename>` uses Flask's `path:` converter, which allows slashes in the URL. In vulnerable mode, a request like `/upload/serve/../../etc/passwd` may resolve to files outside the upload directory. This is not documented as a standalone module but is a valid finding for students who probe the upload feature beyond the intended flow.

### Port Mapping (Docker vs Direct)
- **Docker:** app runs on container port `5002`, exposed as host port `5005` → access at `http://localhost:5005`  
- **Direct (`python app.py`):** app runs on port `5002` → access at `http://localhost:5002`  
- The README previously referenced port `5000` which is incorrect for both modes.

### No Rate Limiting
No brute-force protection exists on any endpoint by design. In a real application, login endpoints, API endpoints, and file upload routes would all have rate limiting. Students should note this gap when comparing to production security controls.

### Weak Secret Key
The Flask `secret_key` is hardcoded as `supersecretkey123`. In addition to enabling session forgery (see Bonus Findings), this also affects the JWT module where `"weak"` is used as the HMAC secret — intentionally chosen to be brute-forceable with tools like `hashcat` or `jwt_tool`. Safe mode switches to `Str0ng-R4nd0m-S3cr3t-K3y-2024!`.

---

## Presenter / Instructor Mode

VulnLab includes a built-in presentation controller for classroom use.

| Route | Purpose |
|-------|---------|
| `/presentation` | Slide/module presenter view |
| `/notes` | Instructor notes view |
| `GET /api/presentation/state` | Get current module index |
| `POST /api/presentation/state` | Set current module index |

The presentation state is in-memory — it resets if the app restarts.

---

## Health Check

```bash
curl http://localhost:5005/health
# {"status": "ok", "db": true}
```

Returns `200` if the DB is reachable, `503` if degraded.

---

*For educational use only. Built by Cybevion.*