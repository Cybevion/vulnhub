# VulnLab — Web Application Security Demo Platform

**Built by Yuvraj Todankar | Cybevion | University Cybersecurity Program**

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
# Visit http://localhost:5000
```

### Option 2 — Python directly
```bash
pip install -r requirements.txt
python app.py
# Visit http://localhost:5000
```

---

## Modules

| # | Module | OWASP | Severity |
|---|--------|-------|----------|
| 1 | SQL Injection — Auth Bypass | A03:2021 | CRITICAL |
| 2 | SQL Injection — UNION Extract | A03:2021 | CRITICAL |
| 3 | XSS — Reflected | A03:2021 | CRITICAL |
| 4 | XSS — Stored | A03:2021 | CRITICAL |
| 5 | IDOR — Profile | A01:2021 | CRITICAL |
| 6 | IDOR — Orders | A01:2021 | CRITICAL |
| 7 | CSRF — Fund Transfer | A01:2021 | HIGH |
| 8 | File Upload → Web Shell | A03:2021 | CRITICAL |
| 9 | SSRF — URL Fetch | A10:2021 | HIGH |
| 10 | JWT — None Alg + Weak Secret | A07:2021 | HIGH |
| 11 | SSTI — Jinja2 | A03:2021 | CRITICAL |
| 12 | Open Redirect | A01:2021 | MEDIUM |
| 13 | Security Headers | A05:2021 | HIGH |
| 14 | Business Logic — Price Tamper | A04:2021 | HIGH |

---

## Test Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | admin |
| alice | password1 | user (id=2) |
| bob | bob123 | user (id=3) |
| charlie | charlie456 | user (id=4) |

---

## Safe Mode Toggle

Every route accepts `?safe=0` (vulnerable) or `?safe=1` (patched).  
The UI shows what changed and why the fix works.

---

## Usage with Burp Suite

1. Set browser proxy to `127.0.0.1:8080`
2. Open Burp → Proxy → Intercept On
3. Use the app normally — intercept and modify requests
4. Good targets: price field in `/logic/checkout`, id param in `/idor/profile`

---

## Recommended Lab Flow (per module)

1. Understand the vulnerable code (shown in UI)
2. Exploit it in `?safe=0` mode
3. Switch to `?safe=1` — see the fix in action
4. Read the diff — understand WHY the fix works

---

*For educational use only. Build by Cybevion.*
