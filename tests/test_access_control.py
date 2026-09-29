"""Access-control modules: IDOR (profile/orders), API exposure, API IDOR, price logic."""


class TestIdorProfile:
    def test_vulnerable_views_other_user(self, auth_client):
        # alice (id 2) reads admin's (id 1) profile
        r = auth_client.get("/idor/profile", query_string={"id": "1", "safe": "0"})
        assert b"000-00-0000" in r.data  # admin's SSN leaked

    def test_safe_mode_denies_cross_user(self, auth_client):
        r = auth_client.get("/idor/profile", query_string={"id": "1", "safe": "1"})
        assert b"Access Denied" in r.data
        assert b"000-00-0000" not in r.data


class TestIdorOrders:
    def test_vulnerable_views_other_orders(self, auth_client):
        # alice reads admin's orders (order #4 = Server)
        r = auth_client.get("/idor/orders", query_string={"user_id": "1", "safe": "0"})
        assert b"Server" in r.data

    def test_safe_mode_denies_cross_user(self, auth_client):
        r = auth_client.get("/idor/orders", query_string={"user_id": "1", "safe": "1"})
        assert b"Access Denied" in r.data


class TestApiUsers:
    def test_vulnerable_leaks_all_fields_unauthenticated(self, client):
        r = client.get("/api/users?safe=0")
        assert r.status_code == 200
        body = r.get_json()
        assert any(u.get("password") == "admin123" for u in body)  # plaintext pw leaked
        assert all("ssn" in u for u in body)

    def test_safe_mode_requires_auth_and_filters(self, client, auth_client):
        assert client.get("/api/users?safe=1").status_code == 401  # no session
        r = auth_client.get("/api/users?safe=1")
        assert r.status_code == 200
        body = r.get_json()
        assert all("password" not in u and "ssn" not in u for u in body)


class TestApiMessageIdor:
    def test_vulnerable_reads_any_message(self, auth_client):
        # message 3 is admin->bob; alice (id 2) is neither party
        r = auth_client.get("/api/message/3?safe=0")
        assert r.status_code == 200
        assert r.get_json()["id"] == 3

    def test_safe_mode_enforces_ownership(self, auth_client):
        r = auth_client.get("/api/message/3?safe=1")
        assert r.status_code == 403


class TestPriceLogic:
    def test_vulnerable_trusts_client_price(self, auth_client):
        r = auth_client.post("/logic/checkout?safe=0",
                             data={"item_id": "1", "quantity": "1", "price": "0.01"})
        assert b"0.01" in r.data  # attacker-supplied price honoured

    def test_safe_mode_uses_server_price(self, auth_client):
        r = auth_client.post("/logic/checkout?safe=1",
                             data={"item_id": "1", "quantity": "1", "price": "0.01"})
        # confirmation must reflect the server price, ignoring the client value
        assert b"Price from server" in r.data
        assert b"999.99" in r.data   # server price for "Laptop Pro"
