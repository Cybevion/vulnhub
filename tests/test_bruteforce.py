"""Brute-force / rate-limiting module (A07) — safe/vulnerable contract."""


def _fail(client, safe):
    return client.post(f"/bruteforce?safe={safe}",
                       data={"username": "admin", "password": "wrong"})


class TestBruteForce:
    def test_vulnerable_never_locks_out(self, client):
        # many failed attempts, all answered normally — no lockout
        for _ in range(20):
            r = _fail(client, 0)
        assert r.status_code == 200
        assert b"no limit" in r.data
        # the lockout error (safe-mode only) must never appear in vulnerable mode
        assert b"Too many failed attempts" not in r.data

    def test_vulnerable_login_succeeds_with_valid_creds(self, client):
        r = client.post("/bruteforce?safe=0", data={"username": "admin", "password": "admin123"})
        assert b"Login successful" in r.data

    def test_safe_mode_locks_out_after_max_attempts(self, client):
        last = None
        for _ in range(6):
            last = _fail(client, 1)
        # by the 5th/6th failure the account is locked
        assert b"Locked" in last.data or b"locked" in last.data.lower()

    def test_safe_mode_shows_remaining_attempts(self, client):
        r = _fail(client, 1)
        assert b"attempts left before lockout" in r.data

    def test_page_renders_registry_payloads(self, client):
        r = client.get("/bruteforce")
        assert r.status_code == 200
        assert b"Automated brute-force with a wordlist" in r.data  # registry payload desc
