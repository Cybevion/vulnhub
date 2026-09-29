"""Shared pytest fixtures for the VulnLab test-suite.

The suite's core job is to lock the **safe/vulnerable contract**: for every
module, the exploit must *fire* in ?safe=0 and be *blocked* in ?safe=1. That
contract is exactly where real bugs were found (open-redirect //evil.com, JWT
missing exp check, weak SSRF blocklist), so these tests are the regression net.
"""
import os
import sys

import pytest

# Make the app importable when pytest runs from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as vulnlab  # noqa: E402


@pytest.fixture()
def app():
    vulnlab.app.config.update(TESTING=True)
    vulnlab.init_db()  # fresh, deterministic seed data for every test
    return vulnlab.app


@pytest.fixture()
def client(app):
    """A test client with no session — a brand-new student."""
    return app.test_client()


@pytest.fixture()
def auth_client(app):
    """A test client already authenticated as alice (id 2)."""
    c = app.test_client()
    with c.session_transaction() as sess:
        sess["user_id"] = 2
    return c


@pytest.fixture()
def mod():
    """Direct handle to the app module for calling helpers (make_jwt, etc.)."""
    return vulnlab
