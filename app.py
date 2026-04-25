"""
VulnLab — Web Application Security Demo Platform
Built by Yuvraj Todankar | Cybevion
University Cybersecurity Program

Each route has two modes:
  ?safe=0  → vulnerable (default)
  ?safe=1  → patched — shows the fix in action
"""

from flask import Flask, request, render_template, redirect, url_for, session, jsonify, make_response
import sqlite3, os, hashlib, hmac, base64, json, time, re, uuid, html
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey123"   # intentionally weak for JWT demo
DB = "/tmp/vulnlab.db"

# ── helpers ────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS posts;
        DROP TABLE IF EXISTS comments;
        DROP TABLE IF EXISTS orders;
        DROP TABLE IF EXISTS messages;
        DROP TABLE IF EXISTS files;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 1000.0,
            ssn TEXT,
            address TEXT
        );

        CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            title TEXT,
            body TEXT,
            author_id INTEGER
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            post_id INTEGER,
            author TEXT,
            body TEXT,
            created_at TEXT
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            price REAL,
            quantity INTEGER,
            total REAL,
            status TEXT DEFAULT 'pending'
        );

        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER,
            receiver_id INTEGER,
            body TEXT,
            created_at TEXT
        );

        CREATE TABLE files (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            filename TEXT,
            filepath TEXT,
            uploaded_at TEXT
        );

        INSERT INTO users VALUES
            (1, 'admin',   'admin123',   'admin@vulnlab.local',  'admin', 9999.99, '000-00-0000', '1 Admin St'),
            (2, 'alice',   'password1',  'alice@example.com',    'user',  1000.00, '111-22-3333', '42 Elm St'),
            (3, 'bob',     'bob123',     'bob@example.com',      'user',  500.00,  '444-55-6666', '7 Oak Ave'),
            (4, 'charlie', 'charlie456', 'charlie@example.com',  'user',  250.00,  '777-88-9999', '99 Pine Rd');

        INSERT INTO posts VALUES
            (1, 'Welcome to VulnLab', 'This is the intentionally vulnerable demo platform.', 1),
            (2, 'Security Tips', 'Always validate your inputs!', 1),
            (3, 'My Weekend', 'Had a great hike this weekend.', 2);

        INSERT INTO comments VALUES
            (1, 1, 'alice', 'Great platform!', '2024-01-01'),
            (2, 1, 'bob',   'Very educational.', '2024-01-02');

        INSERT INTO orders VALUES
            (1, 2, 'Laptop', 999.99, 1, 999.99, 'delivered'),
            (2, 2, 'Mouse',   29.99, 1,  29.99, 'pending'),
            (3, 3, 'Keyboard',79.99, 1,  79.99, 'pending'),
            (4, 1, 'Server', 4999.99,1,4999.99, 'pending');

        INSERT INTO messages VALUES
            (1, 1, 2, 'Welcome to VulnLab, Alice!', '2024-01-01'),
            (2, 2, 1, 'Thanks admin!', '2024-01-02'),
            (3, 1, 3, 'Hey Bob, check the new modules.', '2024-01-03');
    """)
    conn.commit()
    conn.close()

def safe_mode():
    return request.args.get("safe", "0") == "1"

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return user

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def make_jwt(payload: dict, secret: str = "weak") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).rstrip(b"=").decode()
    body   = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{header}.{body}.{sig_b64}"

def verify_jwt(token: str, safe: bool = False):
    """Vulnerable: accepts alg:none. Safe: enforces HS256 + strong secret."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        pad = lambda s: s + "=" * (-len(s) % 4)
        header  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))

        if safe:
            # enforce algorithm + use strong secret
            if header.get("alg") != "HS256":
                return None
            secret = "Str0ng-R4nd0m-S3cr3t-K3y-2024!"
            sig_input = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
            provided_sig = base64.urlsafe_b64decode(pad(parts[2]))
            if not hmac.compare_digest(expected_sig, provided_sig):
                return None
        else:
            # VULNERABLE: accept alg:none — skip signature verification
            alg = header.get("alg", "").lower()
            if alg == "none":
                pass  # ← the bug — no verification
            else:
                secret = "weak"  # ← easily crackable
                sig_input = f"{parts[0]}.{parts[1]}".encode()
                expected_sig = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
                provided_sig = base64.urlsafe_b64decode(pad(parts[2]))
                if not hmac.compare_digest(expected_sig, provided_sig):
                    return None

        return payload
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    init_db()
    user = current_user()
    return render_template("index.html", user=user)

# ══════════════════════════════════════════════════════════════════════════════
# 1. SQL INJECTION — AUTH BYPASS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/sqli/login", methods=["GET", "POST"])
def sqli_login():
    safe = safe_mode()
    error = None
    query_shown = None
    result = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()
        if safe:
            # parameterised query
            row = conn.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (username, password)
            ).fetchone()
            query_shown = f"SELECT * FROM users WHERE username=? AND password=?  [params: '{username}', '{password}']"
        else:
            # VULNERABLE: string concatenation
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            query_shown = query
            try:
                row = conn.execute(query).fetchone()
            except Exception as e:
                error = str(e)
                row = None
        conn.close()

        if row and not error:
            result = dict(row)
            session["user_id"] = row["id"]
        elif not error:
            error = "Invalid credentials."

    return render_template("sqli_login.html", safe=safe, error=error,
                           query_shown=query_shown, result=result)

# ══════════════════════════════════════════════════════════════════════════════
# 2. SQL INJECTION — UNION DATA EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/sqli/search")
def sqli_search():
    safe = safe_mode()
    q = request.args.get("q", "")
    results = []
    query_shown = None
    error = None

    if q:
        conn = get_db()
        if safe:
            rows = conn.execute(
                "SELECT id, title, body FROM posts WHERE title LIKE ?",
                (f"%{q}%",)
            ).fetchall()
            query_shown = f"SELECT id,title,body FROM posts WHERE title LIKE '%{q}%'  [parameterised]"
            results = [dict(r) for r in rows]
        else:
            query = f"SELECT id, title, body FROM posts WHERE title LIKE '%{q}%'"
            query_shown = query
            try:
                rows = conn.execute(query).fetchall()
                results = [dict(r) for r in rows]
            except Exception as e:
                error = str(e)
        conn.close()

    return render_template("sqli_search.html", safe=safe, q=q,
                           results=results, query_shown=query_shown, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# 3. XSS — REFLECTED
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/xss/reflected")
def xss_reflected():
    safe = safe_mode()
    q = request.args.get("q", "")
    if safe:
        output = html.escape(q)
    else:
        output = q   # ← raw — XSS fires here
    return render_template("xss_reflected.html", safe=safe, q=q, output=output)

# ══════════════════════════════════════════════════════════════════════════════
# 4. XSS — STORED
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/xss/stored", methods=["GET", "POST"])
def xss_stored():
    safe = safe_mode()
    error = None

    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        body   = request.form.get("body", "")
        post_id = 1

        if safe:
            author = html.escape(author)
            body   = html.escape(body)

        conn = get_db()
        conn.execute(
            "INSERT INTO comments (post_id,author,body,created_at) VALUES (?,?,?,?)",
            (post_id, author, body, datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
        conn.close()

    conn = get_db()
    comments = conn.execute("SELECT * FROM comments WHERE post_id=1 ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("xss_stored.html", safe=safe, comments=comments)

# ══════════════════════════════════════════════════════════════════════════════
# 5. IDOR
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/idor/profile")
@login_required
def idor_profile():
    safe = safe_mode()
    target_id = request.args.get("id", session.get("user_id"))

    conn = get_db()
    if safe:
        # enforce: you can only see your own profile
        try:
            target_id_int = int(target_id)
        except (TypeError, ValueError):
            conn.close()
            return render_template("idor_profile.html", safe=safe, error="Invalid profile ID.", profile=None, own_id=session["user_id"], target_id=target_id)
        if target_id_int != session["user_id"]:
            conn.close()
            return render_template("idor_profile.html", safe=safe, error="Access Denied: You can only view your own profile.", profile=None, own_id=session["user_id"], target_id=target_id)
        row = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    else:
        # VULNERABLE: uses user-supplied id, no ownership check
        row = conn.execute("SELECT * FROM users WHERE id=?", (target_id,)).fetchone()
    conn.close()

    return render_template("idor_profile.html", safe=safe, profile=dict(row) if row else None,
                           target_id=target_id, own_id=session["user_id"], error=None)

@app.route("/idor/orders")
@login_required
def idor_orders():
    safe = safe_mode()
    target_id = request.args.get("user_id", session.get("user_id"))

    conn = get_db()
    if safe:
        if int(target_id) != session["user_id"]:
            conn.close()
            return render_template("idor_orders.html", safe=safe, error="Access Denied.", orders=[], own_id=session["user_id"])
        orders = conn.execute("SELECT * FROM orders WHERE user_id=?", (session["user_id"],)).fetchall()
    else:
        orders = conn.execute("SELECT * FROM orders WHERE user_id=?", (target_id,)).fetchall()
    conn.close()

    return render_template("idor_orders.html", safe=safe, orders=[dict(o) for o in orders],
                           target_id=target_id, own_id=session["user_id"], error=None)

# ══════════════════════════════════════════════════════════════════════════════
# 6. CSRF
# ══════════════════════════════════════════════════════════════════════════════

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = str(uuid.uuid4())
    return session["csrf_token"]

@app.route("/csrf/transfer", methods=["GET", "POST"])
@login_required
def csrf_transfer():
    safe = safe_mode()
    message = None
    error = None

    app.jinja_env.globals["csrf_token"] = generate_csrf_token()

    if request.method == "POST":
        to_user = request.form.get("to_user", "")
        amount  = float(request.form.get("amount", 0))

        if safe:
            # validate CSRF token
            token = request.form.get("csrf_token", "")
            if not hmac.compare_digest(token, session.get("csrf_token", "")):
                error = "CSRF token validation failed! Request rejected."
            else:
                message = f"Transfer of ${amount:.2f} to {to_user} completed. [CSRF token validated ✓]"
        else:
            # VULNERABLE: no token check
            message = f"Transfer of ${amount:.2f} to {to_user} completed. [No CSRF protection!]"

    csrf_poc = f"""<html>
<body onload="document.forms[0].submit()">
  <form action="http://localhost:5000/csrf/transfer?safe=0" method="POST">
    <input name="to_user" value="attacker">
    <input name="amount"  value="9999">
  </form>
</body>
</html>"""

    return render_template("csrf_transfer.html", safe=safe, message=message,
                           error=error, csrf_poc=csrf_poc,
                           csrf_token=session.get("csrf_token",""))

# ══════════════════════════════════════════════════════════════════════════════
# 7. FILE UPLOAD
# ══════════════════════════════════════════════════════════════════════════════

UPLOAD_DIR = "/tmp/vulnlab_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}
MAGIC_BYTES = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG":      "image/png",
    b"GIF8":         "image/gif",
}

def check_magic(data: bytes) -> bool:
    for magic in MAGIC_BYTES:
        if data[:len(magic)] == magic:
            return True
    return False

@app.route("/upload", methods=["GET", "POST"])
@login_required
def file_upload():
    safe = safe_mode()
    message = None
    error = None
    uploaded_path = None

    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            error = "No file selected."
        else:
            filename = f.filename
            data = f.read()

            if safe:
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if ext not in ALLOWED_EXTENSIONS:
                    error = f"Extension '{ext}' not allowed. Only: {', '.join(ALLOWED_EXTENSIONS)}"
                elif not check_magic(data):
                    error = "File content doesn't match an allowed image type (magic bytes check failed)."
                else:
                    safe_name = f"{uuid.uuid4()}.{ext}"
                    path = os.path.join(UPLOAD_DIR, safe_name)
                    with open(path, "wb") as fout:
                        fout.write(data)
                    message = f"Uploaded safely as {safe_name} (UUID rename + extension + magic bytes validated)"
                    conn = get_db()
                    conn.execute("INSERT INTO files (user_id,filename,filepath,uploaded_at) VALUES (?,?,?,?)",
                                 (session["user_id"], safe_name, path, datetime.now().strftime("%Y-%m-%d %H:%M")))
                    conn.commit()
                    conn.close()
            else:
                # VULNERABLE: save with original filename, no checks
                path = os.path.join(UPLOAD_DIR, filename)
                with open(path, "wb") as fout:
                    fout.write(data)
                uploaded_path = f"/upload/serve/{filename}"
                message = f"Uploaded: {filename}"
                conn = get_db()
                conn.execute("INSERT INTO files (user_id,filename,filepath,uploaded_at) VALUES (?,?,?,?)",
                             (session["user_id"], filename, path, datetime.now().strftime("%Y-%m-%d %H:%M")))
                conn.commit()
                conn.close()

    conn = get_db()
    files = conn.execute("SELECT * FROM files ORDER BY id DESC LIMIT 10").fetchall()
    conn.close()

    return render_template("file_upload.html", safe=safe, message=message,
                           error=error, files=[dict(fi) for fi in files],
                           uploaded_path=uploaded_path)

@app.route("/upload/serve/<path:filename>")
def serve_upload(filename):
    """VULNERABLE: serves uploaded files — including .php"""
    path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        # simulate: if php, execute (for demo we just show content)
        if filename.endswith(".php") or ".php" in filename:
            resp = make_response(f"<pre style='color:red'>[PHP Execution Simulated]\n\nFile content:\n{data.decode('utf-8','replace')}\n\nIn a real server: this would execute as PHP code → RCE!</pre>")
            resp.headers["Content-Type"] = "text/html"
            return resp
        resp = make_response(data)
        resp.headers["Content-Disposition"] = f"inline; filename={filename}"
        return resp
    return "File not found", 404

# ══════════════════════════════════════════════════════════════════════════════
# 8. SSRF
# ══════════════════════════════════════════════════════════════════════════════

import urllib.request
import urllib.parse

SSRF_BLOCKLIST = [
    "169.254.", "192.168.", "10.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "127.", "0.0.0.0", "localhost", "::1"
]

@app.route("/ssrf/fetch")
def ssrf_fetch():
    safe = safe_mode()
    url = request.args.get("url", "")
    result = None
    error = None
    blocked = False

    if url:
        if safe:
            # check against blocklist
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            if any(host.startswith(b) or host == b.rstrip(".") for b in SSRF_BLOCKLIST):
                blocked = True
                error = f"SSRF Protection: Host '{host}' is in the blocklist (internal/cloud metadata IP ranges)."
            elif parsed.scheme not in ("http", "https"):
                error = f"SSRF Protection: Schema '{parsed.scheme}' not allowed. Only http/https permitted."
            else:
                try:
                    req = urllib.request.urlopen(url, timeout=3)
                    result = req.read().decode("utf-8", "replace")[:2000]
                except Exception as e:
                    error = str(e)
        else:
            # VULNERABLE: fetch any URL the user provides
            try:
                # simulate metadata response for educational demo
                if "169.254.169.254" in url or "metadata" in url.lower():
                    if "security-credentials" in url:
                        result = json.dumps({
                            "Code": "Success",
                            "Type": "AWS-HMAC",
                            "AccessKeyId": "ASIA1234567890EXAMPLE",
                            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                            "Token": "AQoDYXdzEJr//////////...",
                            "Expiration": "2024-12-31T23:59:59Z"
                        }, indent=2)
                    elif "iam" in url:
                        result = "EC2InstanceRole"
                    else:
                        result = "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nplacement/\npublic-ipv4\nsecurity-groups"
                elif "localhost" in url or "127.0.0.1" in url:
                    result = "[Simulated] Internal service response:\nRedis 7.0.0\nConnected: 3 clients\nUsed memory: 2.1MB"
                else:
                    req = urllib.request.urlopen(url, timeout=3)
                    result = req.read().decode("utf-8", "replace")[:2000]
            except Exception as e:
                error = str(e)

    return render_template("ssrf_fetch.html", safe=safe, url=url,
                           result=result, error=error, blocked=blocked)

# ══════════════════════════════════════════════════════════════════════════════
# 9. JWT ATTACKS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/jwt/login", methods=["GET", "POST"])
def jwt_login():
    safe = safe_mode()
    token = None
    payload = None
    error = None

    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password)).fetchone()
        conn.close()
        if row:
            secret = "Str0ng-R4nd0m-S3cr3t-K3y-2024!" if safe else "weak"
            payload_data = {"user_id": row["id"], "username": row["username"], "role": row["role"], "exp": int(time.time())+3600}
            token = make_jwt(payload_data, secret)
            payload = payload_data
        else:
            error = "Invalid credentials."

    return render_template("jwt_login.html", safe=safe, token=token, payload=payload, error=error)

@app.route("/jwt/verify")
def jwt_verify():
    safe = safe_mode()
    token = request.args.get("token","")
    payload = None
    error = None

    if token:
        payload = verify_jwt(token, safe=safe)
        if not payload:
            error = "Token invalid or signature verification failed."

    return render_template("jwt_verify.html", safe=safe, token=token, payload=payload, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# 10. SSTI — Server-Side Template Injection
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/ssti")
def ssti():
    safe = safe_mode()
    name = request.args.get("name", "World")
    result = None
    error = None

    if safe:
        # safe: render_template_string with escaped variable
        result = f"Hello, {html.escape(name)}!"
    else:
        # VULNERABLE: directly render user input as Jinja2 template
        from flask import render_template_string
        try:
            result = render_template_string(f"Hello, {name}!")
        except Exception as e:
            error = str(e)

    return render_template("ssti.html", safe=safe, name=name, result=result, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# 11. OPEN REDIRECT
# ══════════════════════════════════════════════════════════════════════════════

ALLOWED_REDIRECTS = ["http://localhost:5000", "https://vulnlab.local"]

@app.route("/redirect")
def open_redirect():
    safe = safe_mode()
    url = request.args.get("url", "/")
    warning = None

    if safe:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and not any(url.startswith(a) for a in ALLOWED_REDIRECTS):
            warning = f"Redirect blocked: '{url}' is not in the allowlist."
            return render_template("open_redirect.html", safe=safe, url=url, warning=warning)
    return redirect(url)

@app.route("/redirect/demo")
def open_redirect_demo():
    safe = safe_mode()
    return render_template("open_redirect.html", safe=safe, url=request.args.get("url",""), warning=None)

# ══════════════════════════════════════════════════════════════════════════════
# 12. SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/headers")
def security_headers():
    safe = safe_mode()
    resp = make_response(render_template("security_headers.html", safe=safe))
    if safe:
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # in vulnerable mode: no security headers added
    return resp

# ══════════════════════════════════════════════════════════════════════════════
# 13. BUSINESS LOGIC — PRICE MANIPULATION
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/logic/checkout", methods=["GET","POST"])
@login_required
def logic_checkout():
    safe = safe_mode()
    message = None
    error = None

    items = [
        {"id":1, "name":"Laptop Pro", "server_price": 999.99},
        {"id":2, "name":"Wireless Mouse", "server_price": 29.99},
        {"id":3, "name":"USB Hub", "server_price": 49.99},
    ]

    if request.method == "POST":
        item_id = int(request.form.get("item_id", 0))
        quantity = int(request.form.get("quantity", 1))
        client_price = float(request.form.get("price", 0))

        item = next((i for i in items if i["id"] == item_id), None)
        if not item:
            error = "Invalid item."
        elif safe:
            # use server-side price — ignore client price
            total = item["server_price"] * quantity
            message = f"Order placed: {item['name']} x{quantity} = ${total:.2f} [Price from server — client value ignored]"
        else:
            # VULNERABLE: trust client-supplied price
            total = client_price * quantity
            message = f"Order placed: {item['name']} x{quantity} = ${total:.2f} [Client-supplied price used — VULNERABLE!]"

    return render_template("logic_checkout.html", safe=safe, items=items, message=message, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET","POST"])
def login_page():
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (u,p)).fetchone()
        conn.close()
        if row:
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS (for AJAX / Burp demo)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/users")
def api_users():
    """VULNERABLE: returns all users with sensitive data, no auth"""
    safe = safe_mode()
    conn = get_db()
    if safe:
        if not session.get("user_id"):
            return jsonify({"error": "Unauthorized"}), 401
        # only return safe fields
        rows = conn.execute("SELECT id, username, email FROM users").fetchall()
    else:
        rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/message/<int:msg_id>")
def api_message(msg_id):
    """IDOR in API"""
    safe = safe_mode()
    if not session.get("user_id"):
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    if safe:
        row = conn.execute("SELECT * FROM messages WHERE id=? AND (sender_id=? OR receiver_id=?)",
                           (msg_id, session["user_id"], session["user_id"])).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Access denied or message not found"}), 403
    else:
        row = conn.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)) if row else (jsonify({"error":"Not found"}), 404)

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5002)

# ══════════════════════════════════════════════════════════════════════════════
# PRESENTATION MODE
# ══════════════════════════════════════════════════════════════════════════════

# Shared state — current module index (in-memory, single instructor machine)
_presentation_state = {"module": 0}

@app.route("/presentation")
def presentation():
    return render_template("presentation.html")

@app.route("/notes")
def notes():
    return render_template("notes.html")

@app.route("/api/presentation/state", methods=["GET"])
def pres_get_state():
    return jsonify(_presentation_state)

@app.route("/api/presentation/state", methods=["POST"])
def pres_set_state():
    data = request.get_json()
    if "module" in data:
        _presentation_state["module"] = int(data["module"])
    return jsonify(_presentation_state)

# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health")
def health():
    try:
        conn = get_db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    status = "ok" if db_ok else "degraded"
    return jsonify({"status": status, "db": db_ok}), 200 if db_ok else 503
