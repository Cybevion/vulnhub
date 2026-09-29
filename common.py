"""Shared helpers for VulnLab, used across the route blueprints.

Kept free of the Flask `app` object so blueprints can import it without a
circular dependency (the app factory lives in app.py).
"""
import sqlite3
import base64
import hashlib
import hmac
import json
import time
from functools import wraps

from flask import request, session

from modules import MODULES, MODULES_BY_ID  # noqa: F401 (re-exported for convenience)

DB = "/tmp/vulnlab.db"
DEFAULT_LAB_USER_ID = 2  # alice — the default identity for classroom convenience


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
            # Lab convenience: auto-authenticate as the default demo user (alice)
            # instead of bouncing students to a login wall. An authenticated
            # session is a *precondition* for the IDOR and CSRF demos, so we grant
            # one rather than require a manual login. Students can still switch
            # identity via /login or by exploiting the SQLi auth-bypass module.
            session["user_id"] = DEFAULT_LAB_USER_ID
        return f(*args, **kwargs)
    return decorated


def make_jwt(payload: dict, secret: str = "weak") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
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
        header = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
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
            # enforce expiry — a valid signature on an expired token is still invalid
            exp = payload.get("exp")
            if exp is not None and time.time() > exp:
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


# Maps a view function name to its registry module id, so each module page
# automatically receives its `module` metadata (payloads, code diff) from
# modules.py instead of hardcoding it in the template.
ENDPOINT_TO_MODULE = {
    "sqli_login": "sqli-auth",
    "sqli_search": "sqli-union",
    "xss_reflected": "xss-reflected",
    "xss_stored": "xss-stored",
    "idor_profile": "idor",
    "idor_orders": "idor",
    "csrf_transfer": "csrf",
    "file_upload": "fileupload",
    "ssrf_fetch": "ssrf",
    "jwt_login": "jwt",
    "jwt_verify": "jwt",
    "ssti": "ssti",
    "security_headers": "headers",
    "logic_checkout": "logic",
    "cmdi": "cmdi",
    "deserialize": "deserialize",
    "bruteforce": "bruteforce",
    "xxe": "xxe",
    "open_redirect_demo": "open-redirect",
}
