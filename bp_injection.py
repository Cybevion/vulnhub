"""Injection modules (A03): SQLi, XSS, SSTI, Command Injection."""
from flask import Blueprint, render_template, request, session
from datetime import datetime
import os, subprocess, re, html
from common import get_db, safe_mode

bp = Blueprint("injection", __name__)

@bp.route("/sqli/login", methods=["GET", "POST"])
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


@bp.route("/sqli/search")
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


@bp.route("/xss/reflected")
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


@bp.route("/xss/stored", methods=["GET", "POST"])
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


@bp.route("/ssti")
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


@bp.route("/cmdi", methods=["GET", "POST"])
def cmdi():
    safe = safe_mode()
    host = request.values.get("host", "")
    output = None
    error = None
    cmd_shown = None

    if host:
        if safe:
            # validate: hostnames / IPs only — reject shell metacharacters,
            # then run WITHOUT a shell so input can never be interpreted as code
            if not re.fullmatch(r"[A-Za-z0-9.\-]{1,100}", host):
                error = "Blocked: only letters, digits, dots and hyphens allowed (no shell metacharacters)."
            else:
                cmd_shown = f"subprocess.run(['ping', '-c', '1', {host!r}], shell=False)"
                try:
                    proc = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", host],
                        capture_output=True, text=True, timeout=5
                    )
                    output = proc.stdout + proc.stderr
                except Exception as e:
                    error = str(e)
        else:
            # VULNERABLE: user input concatenated into a shell string
            cmd = f"ping -c 1 -W 1 {host}"
            cmd_shown = cmd
            try:
                output = os.popen(cmd).read()
            except Exception as e:
                error = str(e)

    return render_template("cmdi.html", safe=safe, host=host,
                           output=output, error=error, cmd_shown=cmd_shown)

# ══════════════════════════════════════════════════════════════════════════════
# 16. INSECURE DESERIALIZATION
# ══════════════════════════════════════════════════════════════════════════════

