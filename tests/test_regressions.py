"""Regression tests for defects fixed during the security pass.

Each test here corresponds to a specific bug that was found and fixed. They
exist so those bugs cannot silently return.
"""
import time

import pytest


class TestOpenRedirectBypass:
    """Safe mode must reject protocol-relative / backslash targets, not just
    those with an explicit scheme."""

    def test_protocol_relative_is_blocked(self, client):
        r = client.get("/redirect", query_string={"url": "//evil.com", "safe": "1"})
        assert r.status_code == 200
        assert b"not in the allowlist" in r.data
        assert "Location" not in r.headers

    def test_backslash_trick_is_blocked(self, client):
        r = client.get("/redirect", query_string={"url": "/\\/\\evil.com", "safe": "1"})
        assert b"not in the allowlist" in r.data

    def test_own_origin_still_allowed(self, client):
        # request.host_url is added to the allowlist dynamically
        r = client.get("/redirect", query_string={"url": "http://localhost/x", "safe": "1"},
                       base_url="http://localhost")
        assert r.status_code == 302


class TestJwtExpiryEnforced:
    """Safe verification must reject an expired token even with a valid signature."""

    SECRET = "Str0ng-R4nd0m-S3cr3t-K3y-2024!"

    def test_expired_token_rejected(self, mod):
        expired = mod.make_jwt({"role": "admin", "exp": int(time.time()) - 10}, self.SECRET)
        assert mod.verify_jwt(expired, safe=True) is None

    def test_unexpired_token_accepted(self, mod):
        valid = mod.make_jwt({"role": "admin", "exp": int(time.time()) + 3600}, self.SECRET)
        assert mod.verify_jwt(valid, safe=True) is not None


class TestSsrfResolvesInternalHosts:
    """The blocklist was replaced with real resolution; these all map to loopback
    and must be blocked in safe mode."""

    @pytest.mark.parametrize("url", [
        "http://127.1/",
        "http://2130706433/",   # 127.0.0.1 in decimal
        "http://localhost/",
        "http://[::1]/",
        "file:///etc/passwd",   # non-http scheme
    ])
    def test_internal_host_blocked(self, client, url):
        r = client.get("/ssrf/fetch", query_string={"url": url, "safe": "1"})
        assert b"SSRF Protection" in r.data


class TestInputCrashGuards:
    """Hostile / malformed input must not 500."""

    def test_idor_orders_non_numeric_user_id(self, auth_client):
        r = auth_client.get("/idor/orders", query_string={"user_id": "abc", "safe": "1"})
        assert r.status_code == 200
        assert b"Invalid user ID" in r.data

    def test_checkout_non_numeric_price(self, auth_client):
        r = auth_client.post("/logic/checkout?safe=0",
                             data={"item_id": "x", "quantity": "1", "price": "abc"})
        assert r.status_code == 200
        assert b"must be numeric" in r.data

    def test_csrf_transfer_garbage_amount(self, auth_client):
        r = auth_client.post("/csrf/transfer?safe=0",
                             data={"to_user": "x", "amount": "notanumber"})
        assert r.status_code == 200

    def test_presentation_state_post_without_body(self, client):
        r = client.post("/api/presentation/state")
        assert r.status_code == 200
        assert r.get_json()["module"] == 0

    def test_presentation_state_rejects_non_integer(self, client):
        r = client.post("/api/presentation/state", json={"module": "bad"})
        assert r.status_code == 400


class TestLabConvenience:
    """Auto-login + banner added for classroom flow."""

    def test_gated_route_auto_logs_in_as_alice(self, client):
        # brand-new client, no session -> should NOT bounce to /login
        r = client.get("/idor/profile")
        assert r.status_code == 200
        with client.session_transaction() as s:
            assert s.get("user_id") == 2  # alice

    def test_lab_banner_shows_current_user(self, client):
        r = client.get("/idor/profile")
        assert b"Lab mode" in r.data
        assert b"auto-logged-in as" in r.data
        assert b"alice" in r.data

    def test_login_can_switch_identity(self, client):
        r = client.post("/login", data={"username": "bob", "password": "bob123"},
                        follow_redirects=True)
        assert b"logged in as <strong>bob" in r.data


class TestModuleRegistry:
    """The presenter and per-module pages read from one canonical registry
    served at /api/modules."""

    def test_api_modules_returns_registry(self, client):
        r = client.get("/api/modules")
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, list) and len(data) >= 13
        ids = {m["id"] for m in data}
        assert {"sqli-auth", "idor", "ssti", "jwt", "logic"} <= ids

    def test_registry_entries_have_required_fields(self, client):
        data = client.get("/api/modules").get_json()
        for m in data:
            assert "id" in m and "title" in m and "demoUrl" in m
            if not m.get("intro"):
                # real modules must carry the fields the presenter renders
                for key in ("owasp", "sev", "tagline", "payloads", "vuln_code", "safe_code"):
                    assert key in m, f"{m['id']} missing {key}"


class TestEntrypointRegistersAllRoutes:
    """The `python app.py` entrypoint must sit at the end of the file: app.run()
    blocks, so a route defined after it is silently unregistered in direct-run
    mode (health, reset, presentation, api/modules were all affected)."""

    def test_late_routes_are_registered(self, app):
        rules = {r.rule for r in app.url_map.iter_rules()}
        for route in ("/health", "/reset", "/presentation", "/notes",
                      "/api/modules", "/api/presentation/state"):
            assert route in rules, f"{route} not registered"

    def test_entrypoint_is_after_all_routes(self):
        # guard the file ordering so the bug cannot silently return
        src = open("app.py").read()
        main_pos = src.index('if __name__ == "__main__"')
        last_route_pos = src.rindex("@app.route(")
        assert main_pos > last_route_pos, "app.run() must come after every @app.route"


class TestPlatformEndpoints:
    def test_health_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.get_json() == {"status": "ok", "db": True}

    def test_reset_clears_session(self, auth_client):
        r = auth_client.post("/reset")
        assert r.get_json()["status"] == "reset"
        with auth_client.session_transaction() as s:
            assert s.get("user_id") is None
