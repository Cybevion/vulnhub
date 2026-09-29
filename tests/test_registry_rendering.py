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
