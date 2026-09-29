"""Auth & session modules: CSRF, JWT, brute force, login/logout."""
from flask import Blueprint, render_template, request, session, redirect, url_for, current_app
import hmac, uuid, time
from common import get_db, safe_mode, login_required, make_jwt, verify_jwt

bp = Blueprint("auth", __name__)

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = str(uuid.uuid4())
    return session["csrf_token"]


@bp.route("/csrf/transfer", methods=["GET", "POST"])
@login_required
def csrf_transfer():
    safe = safe_mode()
    message = None
    error = None

    current_app.jinja_env.globals["csrf_token"] = generate_csrf_token()

    if request.method == "POST":
        to_user = request.form.get("to_user", "")
        try:
            amount = float(request.form.get("amount", 0) or 0)
        except (TypeError, ValueError):
            amount = 0.0

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
  <form action="{request.host_url}csrf/transfer?safe=0" method="POST">
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


@bp.route("/jwt/login", methods=["GET", "POST"])
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


@bp.route("/jwt/verify")
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


_login_attempts = {}          # ip -> {"count": int, "locked_until": float}
BRUTE_MAX_ATTEMPTS = 5
BRUTE_LOCKOUT_SECS = 30


@bp.route("/bruteforce", methods=["GET", "POST"])
def bruteforce():
    safe = safe_mode()
    ip = request.remote_addr or "?"
    state = _login_attempts.setdefault(ip, {"count": 0, "locked_until": 0.0})
    message = None
    error = None
    locked = False

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        def creds_ok():
            conn = get_db()
            row = conn.execute("SELECT * FROM users WHERE username=? AND password=?",
                               (username, password)).fetchone()
            conn.close()
            return row is not None

        if safe:
            now = time.time()
            if state["locked_until"] > now:
                locked = True
                error = f"Too many failed attempts. Locked for {int(state['locked_until'] - now)}s."
            elif creds_ok():
                state["count"] = 0
                message = "Login successful. [rate limiter reset]"
            else:
                state["count"] += 1
                if state["count"] >= BRUTE_MAX_ATTEMPTS:
                    state["locked_until"] = now + BRUTE_LOCKOUT_SECS
                    state["count"] = 0
                    locked = True
                    error = f"Too many failed attempts. Locked out for {BRUTE_LOCKOUT_SECS}s."
                else:
                    error = f"Invalid credentials. {BRUTE_MAX_ATTEMPTS - state['count']} attempts left before lockout."
        else:
            # VULNERABLE: no throttling — every guess is answered
            state["count"] += 1
            if creds_ok():
                message = "Login successful."
            else:
                error = f"Invalid credentials. (Attempt #{state['count']} — no limit, brute-force freely.)"

    return render_template("bruteforce.html", safe=safe, message=message,
                           error=error, locked=locked, attempts=state["count"],
                           max_attempts=BRUTE_MAX_ATTEMPTS)

# ══════════════════════════════════════════════════════════════════════════════
# 18. XXE — XML EXTERNAL ENTITY
# ══════════════════════════════════════════════════════════════════════════════


@bp.route("/login", methods=["GET","POST"])
def login_page():
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username=? AND password=?", (u,p)).fetchone()
        conn.close()
        if row:
            session["user_id"] = row["id"]
            return redirect(url_for("misc.index"))
        return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html", error=None)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("misc.index"))

# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS (for AJAX / Burp demo)
# ══════════════════════════════════════════════════════════════════════════════

