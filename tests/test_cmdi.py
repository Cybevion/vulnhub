"""OS Command Injection module (A03) — safe/vulnerable contract.

Execution is proven by the output of the injected `id` command ("uid="), which
never appears in the input string — so it can't be confused with the host value
being echoed back into the form field.
"""


class TestCommandInjection:
    # `uname` prints "Linux" — a marker that appears only from real execution,
    # never in the page's static/reference text (unlike `id`'s "uid=").
    def test_vulnerable_executes_chained_command(self, client):
        r = client.get("/cmdi", query_string={"host": "127.0.0.1; uname", "safe": "0"})
        assert r.status_code == 200
        assert b"Linux" in r.data  # the injected `uname` actually ran

    def test_vulnerable_pipe_runs_command(self, client):
        r = client.get("/cmdi", query_string={"host": "127.0.0.1 | uname", "safe": "0"})
        assert b"Linux" in r.data

    def test_safe_mode_blocks_metacharacters(self, client):
        r = client.get("/cmdi", query_string={"host": "127.0.0.1; uname", "safe": "1"})
        assert r.status_code == 200
        assert b"Linux" not in r.data   # injection did NOT execute
        assert b"Blocked" in r.data

    def test_safe_mode_allows_valid_host(self, client):
        r = client.get("/cmdi", query_string={"host": "127.0.0.1", "safe": "1"})
        assert r.status_code == 200
        assert b"Blocked" not in r.data  # a clean host is accepted

    def test_page_renders_registry_payloads(self, client):
        r = client.get("/cmdi")
        assert r.status_code == 200
        assert b"Command substitution" in r.data  # registry payload desc
