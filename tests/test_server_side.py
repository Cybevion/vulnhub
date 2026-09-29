"""Server-side modules: file upload, SSRF, open redirect, security headers."""
import io


class TestFileUpload:
    def test_vulnerable_accepts_php_and_serves_it(self, auth_client):
        data = {"file": (io.BytesIO(b"<?php system($_GET['c']); ?>"), "shell.php")}
        r = auth_client.post("/upload?safe=0", data=data, content_type="multipart/form-data")
        assert b"Uploaded: shell.php" in r.data
        served = auth_client.get("/upload/serve/shell.php")
        assert b"PHP Execution Simulated" in served.data

    def test_safe_mode_rejects_php(self, auth_client):
        data = {"file": (io.BytesIO(b"<?php ?>"), "shell.php")}
        r = auth_client.post("/upload?safe=1", data=data, content_type="multipart/form-data")
        assert b"not allowed" in r.data

    def test_safe_mode_rejects_fake_image_by_magic_bytes(self, auth_client):
        # right extension, wrong content -> magic-byte check fails
        data = {"file": (io.BytesIO(b"not a real image"), "evil.png")}
        r = auth_client.post("/upload?safe=1", data=data, content_type="multipart/form-data")
        assert b"magic bytes check failed" in r.data


class TestSsrf:
    def test_vulnerable_reaches_metadata(self, client):
        r = client.get("/ssrf/fetch",
                       query_string={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
                                     "safe": "0"})
        assert b"SecretAccessKey" in r.data

    def test_safe_mode_blocks_metadata_ip(self, client):
        r = client.get("/ssrf/fetch",
                       query_string={"url": "http://169.254.169.254/", "safe": "1"})
        assert b"SSRF Protection" in r.data


class TestSecurityHeaders:
    def test_vulnerable_omits_headers(self, client):
        r = client.get("/headers?safe=0")
        assert "Content-Security-Policy" not in r.headers

    def test_safe_mode_sets_headers(self, client):
        r = client.get("/headers?safe=1")
        assert r.headers.get("Content-Security-Policy")
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("X-Content-Type-Options") == "nosniff"


class TestOpenRedirect:
    def test_vulnerable_redirects_anywhere(self, client):
        r = client.get("/redirect", query_string={"url": "https://evil.com", "safe": "0"})
        assert r.status_code == 302
        assert r.headers["Location"] == "https://evil.com"

    def test_safe_mode_blocks_external(self, client):
        r = client.get("/redirect", query_string={"url": "https://evil.com", "safe": "1"})
        assert b"not in the allowlist" in r.data

    def test_safe_mode_allows_relative_path(self, client):
        r = client.get("/redirect", query_string={"url": "/dashboard", "safe": "1"})
        assert r.status_code == 302
        assert r.headers["Location"] == "/dashboard"
