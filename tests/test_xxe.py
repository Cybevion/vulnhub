"""XXE module (A05) — safe/vulnerable contract."""

XXE_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
    '<data>&xxe;</data>'
)
NORMAL_XML = '<?xml version="1.0"?><data>hello world</data>'


class TestXXE:
    def test_vulnerable_reads_local_file(self, client, tmp_path):
        # point the entity at a file we control so the assertion is deterministic
        secret = tmp_path / "secret.txt"
        secret.write_text("XXE_SECRET_VALUE")
        payload = (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{secret}">]>\n'
            '<data>&xxe;</data>'
        )
        r = client.post("/xxe?safe=0", data={"xml": payload})
        assert r.status_code == 200
        assert b"XXE_SECRET_VALUE" in r.data  # external entity resolved -> file read

    def test_safe_mode_blocks_dtd(self, client, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("XXE_SECRET_VALUE")
        payload = (
            '<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{secret}">]>\n'
            '<data>&xxe;</data>'
        )
        r = client.post("/xxe?safe=1", data={"xml": payload})
        assert r.status_code == 200
        assert b"XXE_SECRET_VALUE" not in r.data  # entity not resolved
        assert b"Blocked" in r.data

    def test_normal_xml_parses_in_both_modes(self, client):
        for safe in ("0", "1"):
            r = client.post(f"/xxe?safe={safe}", data={"xml": NORMAL_XML})
            assert b"hello world" in r.data

    def test_page_renders_registry_payloads(self, client):
        r = client.get("/xxe")
        assert r.status_code == 200
        assert b"Read /etc/passwd via an external entity" in r.data  # registry payload desc
