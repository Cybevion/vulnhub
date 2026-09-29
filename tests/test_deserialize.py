"""Insecure Deserialization module (A08) — safe/vulnerable contract."""
import base64
import json
import pickle
import subprocess


def _malicious_pickle():
    """A pickle whose __reduce__ returns the output of `id` when loaded."""
    class RCE:
        def __reduce__(self):
            return (subprocess.check_output, (["id"],))
    return base64.b64encode(pickle.dumps(RCE())).decode()


def _legit_pickle():
    return base64.b64encode(pickle.dumps({"theme": "dark"})).decode()


def _legit_json():
    return base64.b64encode(json.dumps({"theme": "dark"}).encode()).decode()


class TestInsecureDeserialization:
    def test_vulnerable_pickle_executes_code(self, client):
        r = client.post("/deserialize?safe=0", data={"blob": _malicious_pickle()})
        assert r.status_code == 200
        assert b"uid=" in r.data  # code ran during pickle.loads

    def test_vulnerable_loads_legit_pickle(self, client):
        r = client.post("/deserialize?safe=0", data={"blob": _legit_pickle()})
        assert b"theme" in r.data and b"dark" in r.data

    def test_safe_mode_refuses_pickle(self, client):
        # a pickle blob is not valid JSON -> safe mode rejects it, no execution
        r = client.post("/deserialize?safe=1", data={"blob": _malicious_pickle()})
        assert r.status_code == 200
        assert b"uid=" not in r.data
        assert b"refuses to unpickle" in r.data or b"Not valid JSON" in r.data

    def test_safe_mode_accepts_json(self, client):
        r = client.post("/deserialize?safe=1", data={"blob": _legit_json()})
        assert b"theme" in r.data and b"dark" in r.data

    def test_page_renders_registry_payloads(self, client):
        r = client.get("/deserialize")
        assert r.status_code == 200
        assert b"Malicious pickle" in r.data  # registry payload desc
