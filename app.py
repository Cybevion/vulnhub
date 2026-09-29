"""VulnLab — application entrypoint.

Routes are split into category blueprints (bp_injection, bp_access, bp_auth,
bp_server, bp_misc); shared helpers live in common.py. Several names are
re-exported here so `from app import app, init_db` (Docker) and the test suite
keep working unchanged.
"""
from flask import Flask, request

from common import (  # noqa: F401  — re-exported for Docker / tests / callers
    init_db, get_db, safe_mode, current_user, login_required,
    make_jwt, verify_jwt, DEFAULT_LAB_USER_ID, ENDPOINT_TO_MODULE,
    MODULES, MODULES_BY_ID,
)
from bp_injection import bp as injection_bp
from bp_access import bp as access_bp
from bp_auth import bp as auth_bp, _login_attempts  # noqa: F401 — re-exported for tests
from bp_server import bp as server_bp
from bp_misc import bp as misc_bp

app = Flask(__name__)
app.secret_key = "supersecretkey123"   # intentionally weak for JWT demo

for _bp in (injection_bp, access_bp, auth_bp, server_bp, misc_bp):
    app.register_blueprint(_bp)


@app.context_processor
def inject_current_user():
    # Makes `current_user` available to every template (nav + lab banner).
    return {"current_user": current_user()}


@app.context_processor
def inject_module():
    # The current page's registry entry + shared UI state. request.endpoint is
    # "<blueprint>.<func>", so map on the function-name half.
    fn = (request.endpoint or "").split(".")[-1]
    mod_id = ENDPOINT_TO_MODULE.get(fn)
    return {
        "module": MODULES_BY_ID.get(mod_id),
        "current_module_id": mod_id,
        "is_safe": safe_mode(),
    }


if __name__ == "__main__":
    init_db()
    # debug=False: the Werkzeug interactive debugger is a remote-console RCE when
    # bound to 0.0.0.0 — a real risk beyond the intended teaching modules.
    app.run(debug=False, host="0.0.0.0", port=5002)
