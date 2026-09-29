"""Dashboard, API endpoints, presenter, health, reset."""
from flask import Blueprint, render_template, request, session, jsonify, make_response
from common import get_db, init_db, current_user, safe_mode, MODULES

bp = Blueprint("misc", __name__)

@bp.route("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)

# ══════════════════════════════════════════════════════════════════════════════
# 1. SQL INJECTION — AUTH BYPASS
# ══════════════════════════════════════════════════════════════════════════════


@bp.route("/headers")
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


@bp.route("/api/users")
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


@bp.route("/api/message/<int:msg_id>")
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

# ══════════════════════════════════════════════════════════════════════════════
# PRESENTATION MODE
# ══════════════════════════════════════════════════════════════════════════════

# Shared state — current module index (in-memory, single instructor machine)

_presentation_state = {"module": 0}


@bp.route("/presentation")
def presentation():
    return render_template("presentation.html")


@bp.route("/notes")
def notes():
    return render_template("notes.html")


@bp.route("/api/modules")
def api_modules():
    """Canonical module registry (single source of truth for the presenter and
    the per-module pages). Served as JSON so the presentation view consumes the
    same data the routes/templates use."""
    return jsonify(MODULES)


@bp.route("/api/presentation/state", methods=["GET"])
def pres_get_state():
    return jsonify(_presentation_state)


@bp.route("/api/presentation/state", methods=["POST"])
def pres_set_state():
    data = request.get_json(silent=True) or {}
    if "module" in data:
        try:
            _presentation_state["module"] = int(data["module"])
        except (TypeError, ValueError):
            return jsonify({"error": "module must be an integer"}), 400
    return jsonify(_presentation_state)

# ══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════


@bp.route("/health")
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

# ══════════════════════════════════════════════════════════════════════════════
# RESET
# ══════════════════════════════════════════════════════════════════════════════


@bp.route("/reset", methods=["POST"])
def reset_db():
    init_db()
    session.clear()
    return jsonify({"status": "reset", "message": "Database reset. All state cleared."})

# ══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT — must stay at the end of the file: app.run() blocks, so any route
# defined after it would never be registered when run via `python app.py`.
# ══════════════════════════════════════════════════════════════════════════════

