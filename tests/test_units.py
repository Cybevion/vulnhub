"""Unit tests for the pure helper functions and registry integrity —
no HTTP, exercising the logic directly."""
import base64
import time

import pytest

import common
import bp_server
from modules import MODULES, MODULES_BY_ID, MODULE_GUIDANCE, MODULE_MODES
from common import ENDPOINT_TO_MODULE


# ── JWT helpers ──────────────────────────────────────────────────────────────

class TestJwtHelpers:
    def test_roundtrip_hs256(self):
        tok = common.make_jwt({"user_id": 1, "role": "admin"}, secret="weak")
        assert common.verify_jwt(tok, safe=False) == {"user_id": 1, "role": "admin"}

    def test_strong_secret_verifies_in_safe_mode(self):
        S = "Str0ng-R4nd0m-S3cr3t-K3y-2024!"
        exp = int(time.time()) + 60
        tok = common.make_jwt({"role": "admin", "exp": exp}, secret=S)
        assert common.verify_jwt(tok, safe=True) == {"role": "admin", "exp": exp}

    def test_malformed_tokens_rejected(self):
        assert common.verify_jwt("not-a-token") is None
        assert common.verify_jwt("only.two") is None
        assert common.verify_jwt("a.b.c") is None  # undecodable segments

    def test_wrong_secret_rejected_in_vuln_hs256(self):
        tok = common.make_jwt({"role": "admin"}, secret="not-weak")
        # vuln mode still verifies HS256 against "weak" — wrong secret fails
        assert common.verify_jwt(tok, safe=False) is None

    def test_expired_token_rejected_in_safe_mode(self):
        S = "Str0ng-R4nd0m-S3cr3t-K3y-2024!"
        tok = common.make_jwt({"role": "admin", "exp": int(time.time()) - 5}, secret=S)
        assert common.verify_jwt(tok, safe=True) is None


# ── SSRF host resolution ─────────────────────────────────────────────────────

class TestResolvesToPrivate:
    @pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0"])
    def test_internal_ips_are_private(self, host):
        assert bp_server.resolves_to_private(host) is True

    def test_public_ip_is_not_private(self):
        assert bp_server.resolves_to_private("8.8.8.8") is False

    def test_unresolvable_host_is_treated_as_unsafe(self):
        assert bp_server.resolves_to_private("no.such.host.invalid.") is True


# ── Upload magic-byte check ──────────────────────────────────────────────────

class TestCheckMagic:
    @pytest.mark.parametrize("data", [b"\xff\xd8\xff\xe0JFIF", b"\x89PNG\r\n", b"GIF89a"])
    def test_valid_image_signatures(self, data):
        assert bp_server.check_magic(data) is True

    @pytest.mark.parametrize("data", [b"not an image", b"<?php ?>", b"", b"PK\x03\x04"])
    def test_non_image_rejected(self, data):
        assert bp_server.check_magic(data) is False


# ── safe_mode() ──────────────────────────────────────────────────────────────

class TestSafeMode:
    def test_safe_mode_reads_query_param(self, app):
        with app.test_request_context("/x?safe=1"):
            assert common.safe_mode() is True
        with app.test_request_context("/x?safe=0"):
            assert common.safe_mode() is False
        with app.test_request_context("/x"):
            assert common.safe_mode() is False


# ── Registry integrity ───────────────────────────────────────────────────────

class TestRegistryIntegrity:
    def test_unique_ids(self):
        ids = [m["id"] for m in MODULES]
        assert len(ids) == len(set(ids))

    def test_every_endpoint_maps_to_a_real_module(self):
        for mod_id in ENDPOINT_TO_MODULE.values():
            assert mod_id in MODULES_BY_ID

    def test_guidance_and_modes_reference_real_modules(self):
        for mid in list(MODULE_GUIDANCE) + list(MODULE_MODES):
            assert mid in MODULES_BY_ID

    def test_real_modules_have_required_fields(self):
        for m in MODULES:
            if m.get("intro"):
                continue
            for key in ("id", "title", "owasp", "sev", "tagline", "demoUrl",
                        "payloads", "vuln_code", "safe_code", "objective", "hints"):
                assert key in m, f"{m['id']} missing {key}"
            assert isinstance(m["payloads"], list) and m["payloads"]
            assert isinstance(m["hints"], list) and m["hints"]
