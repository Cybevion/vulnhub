"""Auth & session modules: CSRF and JWT."""


class TestCsrf:
    def test_vulnerable_accepts_transfer_without_token(self, auth_client):
        r = auth_client.post("/csrf/transfer?safe=0",
                             data={"to_user": "attacker", "amount": "9999"})
        assert b"No CSRF protection" in r.data

    def test_safe_mode_rejects_missing_token(self, auth_client):
        r = auth_client.post("/csrf/transfer?safe=1",
                             data={"to_user": "attacker", "amount": "9999"})
        assert b"CSRF token validation failed" in r.data

    def test_safe_mode_accepts_valid_token(self, auth_client):
        # prime the token, then submit it back
        auth_client.get("/csrf/transfer?safe=1")
        with auth_client.session_transaction() as s:
            token = s.get("csrf_token")
        r = auth_client.post("/csrf/transfer?safe=1",
                             data={"to_user": "bob", "amount": "10", "csrf_token": token})
        assert b"CSRF token validated" in r.data


class TestJwt:
    def test_login_issues_token(self, client):
        r = client.post("/jwt/login?safe=0", data={"username": "admin", "password": "admin123"})
        assert r.status_code == 200
        assert b"eyJ" in r.data  # a JWT header segment is rendered

    def test_vulnerable_verify_accepts_alg_none(self, client, mod):
        import base64, json
        def seg(o):
            return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        forged = f"{seg({'alg':'none','typ':'JWT'})}.{seg({'user_id':1,'role':'admin'})}."
        assert mod.verify_jwt(forged, safe=False) == {"user_id": 1, "role": "admin"}

    def test_safe_mode_rejects_alg_none(self, client, mod):
        import base64, json
        def seg(o):
            return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        forged = f"{seg({'alg':'none','typ':'JWT'})}.{seg({'role':'admin'})}."
        assert mod.verify_jwt(forged, safe=True) is None

    def test_vulnerable_secret_is_weak(self, mod):
        # a token signed with the weak secret verifies in vulnerable mode
        tok = mod.make_jwt({"role": "admin"}, secret="weak")
        assert mod.verify_jwt(tok, safe=False) == {"role": "admin"}
