"""Server-side modules: file upload, SSRF, deserialization, XXE, open redirect."""
from flask import Blueprint, render_template, request, session, redirect, make_response
from datetime import datetime
import os, uuid, base64, json, pickle, socket, ipaddress
import urllib.request, urllib.parse
from lxml import etree
from common import get_db, safe_mode, login_required

bp = Blueprint("server", __name__)

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


@bp.route("/upload", methods=["GET", "POST"])
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


@bp.route("/upload/serve/<path:filename>")
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
import ipaddress
import socket



def resolves_to_private(host: str) -> bool:
    """Resolve a hostname to every IP it maps to and return True if ANY of them
    is private/loopback/link-local/reserved. Resolving defeats decimal-IP,
    '127.1', IPv6 and DNS-name tricks that a string blocklist misses."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # can't resolve — treat as unsafe rather than fetch blindly
        return True
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False



@bp.route("/ssrf/fetch")
def ssrf_fetch():
    safe = safe_mode()
    url = request.args.get("url", "")
    result = None
    error = None
    blocked = False

    if url:
        if safe:
            # Resolve the host and reject any that maps to an internal IP.
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or ""
            if parsed.scheme not in ("http", "https"):
                error = f"SSRF Protection: Schema '{parsed.scheme}' not allowed. Only http/https permitted."
            elif not host or resolves_to_private(host):
                blocked = True
                error = f"SSRF Protection: Host '{host}' resolves to an internal/reserved address (or cannot be resolved)."
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


ALLOWED_REDIRECTS = ["https://vulnlab.local"]


@bp.route("/redirect")
def open_redirect():
    safe = safe_mode()
    url = request.args.get("url", "/")
    warning = None

    # The app's own origin is always a valid redirect target, whatever port it
    # runs on (5002 direct / 5005 docker), so derive it from the live request.
    allowed = ALLOWED_REDIRECTS + [request.host_url.rstrip("/")]

    if safe:
        parsed = urllib.parse.urlparse(url)
        # Browsers treat backslashes as forward slashes, so normalise before the
        # "//" check to catch "/\evil.com" and "\/\/evil.com" style bypasses.
        normalised = url.replace("\\", "/")
        # A safe internal redirect is a relative path: no scheme AND no netloc, and
        # not protocol-relative ("//evil.com") or scheme-relative ("https:evil.com").
        is_relative = (not parsed.scheme) and (not parsed.netloc) and not normalised.startswith("//")
        is_allowlisted = any(url.startswith(a + "/") or url == a for a in allowed)
        if not (is_relative or is_allowlisted):
            warning = f"Redirect blocked: '{url}' is not in the allowlist."
            return render_template("open_redirect.html", safe=safe, url=url, warning=warning)
    return redirect(url)


@bp.route("/redirect/demo")
def open_redirect_demo():
    safe = safe_mode()
    return render_template("open_redirect.html", safe=safe, url=request.args.get("url",""), warning=None)

# ══════════════════════════════════════════════════════════════════════════════
# 12. SECURITY HEADERS
# ══════════════════════════════════════════════════════════════════════════════


@bp.route("/deserialize", methods=["GET", "POST"])
def deserialize():
    safe = safe_mode()
    blob = request.values.get("blob", "")
    result = None
    error = None

    if blob:
        try:
            raw = base64.b64decode(blob)
        except Exception:
            raw = None
            error = "Input is not valid base64."

        if raw is not None:
            if safe:
                # SAFE: JSON carries data only — no code, no __reduce__ hook
                try:
                    result = repr(json.loads(raw.decode("utf-8", "replace")))
                except Exception:
                    error = "Not valid JSON. (Safe mode refuses to unpickle — send JSON preferences instead.)"
            else:
                # VULNERABLE: pickle.loads runs __reduce__ on the incoming object
                try:
                    obj = pickle.loads(raw)
                    result = obj.decode("utf-8", "replace") if isinstance(obj, (bytes, bytearray)) else repr(obj)
                except Exception as e:
                    error = f"Deserialization error: {e}"

    return render_template("deserialize.html", safe=safe, blob=blob,
                           result=result, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# 17. BRUTE FORCE — NO RATE LIMITING
# ══════════════════════════════════════════════════════════════════════════════


def _xml_text(root):
    text = (root.text or "").strip()
    return text or etree.tostring(root, method="text", encoding="unicode").strip()


@bp.route("/xxe", methods=["GET", "POST"])
def xxe():
    safe = safe_mode()
    xml_input = request.form.get("xml", "")
    result = None
    error = None

    if xml_input.strip():
        data = xml_input.encode("utf-8", "replace")
        if safe:
            # reject DTDs (where external entities live) and never resolve them
            low = xml_input.lower()
            if "<!doctype" in low or "<!entity" in low:
                error = "Blocked: DTD / entity declarations are not allowed (prevents XXE)."
            else:
                try:
                    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
                    result = _xml_text(etree.fromstring(data, parser))
                except Exception as e:
                    error = f"XML parse error: {e}"
        else:
            # VULNERABLE: resolve external entities + load DTDs
            try:
                parser = etree.XMLParser(load_dtd=True, resolve_entities=True, no_network=False)
                result = _xml_text(etree.fromstring(data, parser))
            except Exception as e:
                error = f"XML parse error: {e}"

    return render_template("xxe.html", safe=safe, xml_input=xml_input,
                           result=result, error=error)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════

