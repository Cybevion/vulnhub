"""Stage B: module pages render their payload/code content from the registry.

These assert on wording that exists ONLY in modules.py (not in the old inline
template blocks), proving the page is sourced from the registry — and guarding
against a broken/empty loop, which the security-contract tests would not catch.
"""


class TestXssPagesUseRegistry:
    def test_reflected_renders_registry_payloads(self, client):
        r = client.get("/xss/reflected")
        assert r.status_code == 200
        # registry wording ("SVG event-based XSS"), not the old "SVG-based XSS"
        assert b"SVG event-based XSS" in r.data
        assert b"onerror=alert(1)" in r.data  # payload code is present

    def test_stored_renders_registry_payloads(self, client):
        r = client.get("/xss/stored")
        assert r.status_code == 200
        # registry wording ("Exfil API data..."), not the old "Steal API data"
        assert b"Exfil API data" in r.data


class TestSstiPageUsesRegistry:
    def test_payloads_from_registry(self, client):
        r = client.get("/ssti")
        assert r.status_code == 200
        # registry wording ("leaks SECRET_KEY, DB URI"), not old "exposes SECRET_KEY"
        assert b"leaks SECRET_KEY, DB URI" in r.data

    def test_code_diff_from_registry(self, client):
        r = client.get("/ssti")
        # vuln_code marker that only exists in the registry entry
        assert b"leaks all Flask config" in r.data


class TestSqliLoginPageUsesRegistry:
    def test_payloads_from_registry(self, client):
        r = client.get("/sqli/login")
        assert r.status_code == 200
        # registry wording + the added optional pw field both render
        assert b"bypasses password check" in r.data
        assert b"anything" in r.data  # pw for the admin'-- payload
