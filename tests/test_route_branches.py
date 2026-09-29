"""Coverage for route branches not exercised by the main contract tests:
error handling, safe-mode success paths, and edge cases."""
import io


class TestInputValidationBranches:
    def test_idor_profile_safe_non_numeric_id(self, auth_client):
        r = auth_client.get("/idor/profile", query_string={"id": "abc", "safe": "1"})
        assert r.status_code == 200
        assert b"Invalid profile ID" in r.data

    def test_logic_checkout_invalid_item(self, auth_client):
        r = auth_client.post("/logic/checkout?safe=0",
                             data={"item_id": "999", "quantity": "1", "price": "5"})
        assert b"Invalid item" in r.data

    def test_sqli_login_syntax_error_is_handled(self, client):
        # a lone quote breaks the concatenated query — the error is caught, not 500
        r = client.post("/sqli/login?safe=0", data={"username": "'", "password": "x"})
        assert r.status_code == 200
        with client.session_transaction() as s:
            assert s.get("user_id") is None

    def test_sqli_search_syntax_error_is_handled(self, client):
        r = client.get("/sqli/search", query_string={"q": "'", "safe": "0"})
        assert r.status_code == 200


class TestApiBranches:
    def test_api_message_requires_auth(self, client):
        assert client.get("/api/message/1").status_code == 401

    def test_api_message_not_found(self, auth_client):
        r = auth_client.get("/api/message/9999?safe=0")
        assert r.status_code == 404

    def test_api_message_authorized_own(self, auth_client):
        # message 1 is admin->alice; alice (id 2) is the receiver -> allowed in safe mode
        r = auth_client.get("/api/message/1?safe=1")
        assert r.status_code == 200 and r.get_json()["id"] == 1


class TestServerSideBranches:
    def test_upload_safe_accepts_valid_image(self, auth_client):
        data = {"file": (io.BytesIO(b"\x89PNG\r\n\x1a\n\x00\x00\x00"), "logo.png")}
        r = auth_client.post("/upload?safe=1", data=data, content_type="multipart/form-data")
        assert b"Uploaded safely" in r.data

    def test_upload_no_file_selected(self, auth_client):
        r = auth_client.post("/upload?safe=0", data={}, content_type="multipart/form-data")
        assert b"No file selected" in r.data

    def test_serve_missing_file_404(self, client):
        assert client.get("/upload/serve/nope-does-not-exist.txt").status_code == 404

    def test_deserialize_invalid_base64(self, client):
        r = client.post("/deserialize?safe=0", data={"blob": "!!! not base64 !!!"})
        assert b"not valid base64" in r.data

    def test_xxe_invalid_xml_is_handled(self, client):
        r = client.post("/xxe?safe=0", data={"xml": "<not valid xml"})
        assert r.status_code == 200
        assert b"XML parse error" in r.data

    def test_open_redirect_safe_allows_allowlisted_host(self, client):
        r = client.get("/redirect", query_string={"url": "https://vulnlab.local/x", "safe": "1"})
        assert r.status_code == 302
        assert r.headers["Location"] == "https://vulnlab.local/x"


class TestSsrfSimulatedResponses:
    """Vulnerable SSRF returns simulated internal responses (no real network)."""

    def test_iam_role_name(self, client):
        r = client.get("/ssrf/fetch", query_string={
            "url": "http://169.254.169.254/latest/meta-data/iam/", "safe": "0"})
        assert b"EC2InstanceRole" in r.data

    def test_metadata_index(self, client):
        r = client.get("/ssrf/fetch", query_string={
            "url": "http://169.254.169.254/latest/meta-data/", "safe": "0"})
        assert b"ami-id" in r.data

    def test_loopback_service(self, client):
        r = client.get("/ssrf/fetch", query_string={
            "url": "http://localhost:6379", "safe": "0"})
        assert b"Redis" in r.data


class TestAuthBranches:
    def test_jwt_verify_empty_token(self, client):
        r = client.get("/jwt/verify")
        assert r.status_code == 200  # no token -> just renders the form

    def test_login_page_valid_credentials(self, client):
        r = client.post("/login", data={"username": "bob", "password": "bob123"},
                        follow_redirects=True)
        with client.session_transaction() as s:
            assert s.get("user_id") == 3

    def test_login_page_invalid_credentials(self, client):
        r = client.post("/login", data={"username": "bob", "password": "wrong"})
        assert b"Invalid credentials" in r.data

    def test_logout_clears_session(self, auth_client):
        auth_client.get("/logout")
        with auth_client.session_transaction() as s:
            assert s.get("user_id") is None
