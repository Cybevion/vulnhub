"""Injection modules (A03): SQLi auth-bypass, SQLi UNION, XSS reflected/stored, SSTI.

Each test asserts the two halves of the safe/vulnerable contract:
the exploit FIRES in ?safe=0 and is BLOCKED in ?safe=1.
"""


class TestSqliAuthBypass:
    def test_vulnerable_bypass_logs_in_as_admin(self, client):
        # `' OR 1=1--` comments out the password check -> first row (admin) returned
        r = client.post("/sqli/login?safe=0",
                        data={"username": "' OR 1=1--", "password": "x"})
        assert r.status_code == 200
        with client.session_transaction() as s:
            assert s.get("user_id") == 1  # logged in as admin without a password

    def test_safe_mode_blocks_injection(self, client):
        r = client.post("/sqli/login?safe=1",
                        data={"username": "' OR 1=1--", "password": "x"})
        assert b"Invalid credentials" in r.data
        with client.session_transaction() as s:
            assert s.get("user_id") is None

    def test_every_listed_payload_actually_bypasses(self, client, mod):
        # each sqli-auth registry payload, submitted with its own pw hint, must
        # log in — guards against listing a payload that doesn't work here
        payloads = mod.MODULES_BY_ID["sqli-auth"]["payloads"]
        for p in payloads:
            c = client.application.test_client()
            c.post("/sqli/login?safe=0", data={"username": p["code"], "password": p.get("pw", "x")})
            with c.session_transaction() as s:
                assert s.get("user_id"), f"payload did not log in: {p['code']!r}"


class TestSqliUnion:
    PAYLOAD = "%' UNION SELECT id, username, password FROM users-- "

    def test_vulnerable_union_leaks_passwords(self, client):
        r = client.get("/sqli/search", query_string={"q": self.PAYLOAD, "safe": "0"})
        assert b"admin123" in r.data      # admin's plaintext password exfiltrated
        assert b"password1" in r.data     # alice's too

    def test_safe_mode_parameterised_no_leak(self, client):
        r = client.get("/sqli/search", query_string={"q": self.PAYLOAD, "safe": "1"})
        assert b"admin123" not in r.data


class TestXssReflected:
    def test_vulnerable_reflects_raw_script(self, client):
        r = client.get("/xss/reflected", query_string={"q": "<script>alert(1)</script>", "safe": "0"})
        assert b"<script>alert(1)</script>" in r.data  # unescaped -> executes

    def test_safe_mode_escapes_output(self, client):
        r = client.get("/xss/reflected", query_string={"q": "<script>alert(1)</script>", "safe": "1"})
        assert b"<script>alert(1)</script>" not in r.data
        assert b"&lt;script&gt;" in r.data


class TestXssStored:
    def test_vulnerable_stores_and_renders_raw(self, client):
        payload = "<script>stored_xss()</script>"
        client.post("/xss/stored?safe=0", data={"author": "attacker", "body": payload})
        r = client.get("/xss/stored?safe=0")
        assert payload.encode() in r.data

    def test_safe_mode_encodes_before_storage(self, client):
        payload = "<script>stored_safe()</script>"
        client.post("/xss/stored?safe=1", data={"author": "attacker", "body": payload})
        r = client.get("/xss/stored?safe=1")
        # the raw script tag must never reach the DOM; the text survives as inert content
        assert b"<script>stored_safe()</script>" not in r.data
        assert b"stored_safe()" in r.data


class TestSsti:
    def test_vulnerable_evaluates_template(self, client):
        r = client.get("/ssti", query_string={"name": "{{7*7}}", "safe": "0"})
        assert b"Hello, 49!" in r.data  # Jinja2 evaluated the expression

    def test_safe_mode_treats_input_as_text(self, client):
        r = client.get("/ssti", query_string={"name": "{{7*7}}", "safe": "1"})
        assert b"Hello, 49!" not in r.data
        assert b"7*7" in r.data
