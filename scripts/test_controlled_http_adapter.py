import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from controlled_http_adapter import observe


class FakeResponse:
    status = 401

    def getheaders(self):
        return [("Content-Length", "0"), ("Retry-After", "30")]

    def getheader(self, name):
        return {"Retry-After": "30", "Content-Length": "0"}.get(name)

    def read(self, limit):
        return b""

    def close(self):
        pass


class FakeConnection:
    calls = []

    def __init__(self, hostname, destination_ip, timeout):
        self.calls.append((hostname, destination_ip, timeout))

    def request(self, method, path, body=None, headers=None):
        self.calls.append((method, path, body, headers))

    def getresponse(self):
        return FakeResponse()

    def close(self):
        pass


class ControlledHttpAdapterTests(unittest.TestCase):
    def _scope(self, path):
        path.write_text(json.dumps({
            "authorization_id": "written-auth-0001",
            "assessment_id": "live-observation-01",
            "authorized": True,
            "owner": "Approved Lab Owner",
            "target_url": "https://example.com/",
            "allowed_hosts": ["example.com"],
            "allowed_destination_ips": ["93.184.216.34"],
            "live_network": True,
            "expires_at": "2099-01-01T00:00:00Z",
            "modules": ["AUTH"],
            "request_budget": 1,
            "timeout_seconds": 5,
            "allowed_routes": [{
                "id": "private-profile", "module": "AUTH", "path": "/private/profile",
                "method": "GET", "protected": True, "expected_status": [401, 403],
                "max_response_bytes": 4096
            }]
        }), encoding="utf-8")

    def test_uses_literal_pinned_ip_and_never_persists_body(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scope, output = root / "scope.json", root / "result.json"
            self._scope(scope)
            FakeConnection.calls = []
            with patch("controlled_http_adapter.PinnedHTTPSConnection", FakeConnection):
                result = observe("AUTH", scope, output, firewall_check=lambda _scope: None)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["result"], "pass")
            self.assertEqual(FakeConnection.calls[0][1], "93.184.216.34")
            self.assertEqual(saved["safety"]["network_connections"], 1)
            self.assertEqual(saved["safety"]["response_body_bytes_persisted"], 0)
            self.assertNotIn("response_body", saved["evidence_records"][0])

    def test_firewall_failure_blocks_before_any_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scope, output = root / "scope.json", root / "result.json"
            self._scope(scope)
            FakeConnection.calls = []
            with patch("controlled_http_adapter.PinnedHTTPSConnection", FakeConnection):
                with self.assertRaisesRegex(ValueError, "firewall verification failed"):
                    observe("AUTH", scope, output,
                            firewall_check=lambda _scope: (_ for _ in ()).throw(ValueError("firewall verification failed")))
            self.assertEqual(FakeConnection.calls, [])
            self.assertFalse(output.exists())

    def test_rejects_scope_without_live_network_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = pathlib.Path(directory) / "scope.json"
            scope.write_text(json.dumps({
                "authorization_id": "written-auth-0001", "authorized": True,
                "owner": "Approved Lab Owner", "target_url": "https://example.com/",
                "allowed_hosts": ["example.com"], "expires_at": "2099-01-01T00:00:00Z",
                "modules": ["AUTH"]
            }))
            with self.assertRaisesRegex(ValueError, "live_network=true"):
                observe("AUTH", scope, pathlib.Path(directory) / "out.json")

    def test_rejects_private_destination_even_if_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = pathlib.Path(directory) / "scope.json"
            scope.write_text(json.dumps({
                "authorization_id": "written-auth-0001", "authorized": True,
                "owner": "Approved Lab Owner", "target_url": "https://example.com/",
                "allowed_hosts": ["example.com"], "allowed_destination_ips": ["127.0.0.1"],
                "live_network": True, "expires_at": "2099-01-01T00:00:00Z",
                "modules": ["AUTH"], "request_budget": 1,
                "allowed_routes": [{"id": "private", "module": "AUTH", "path": "/private",
                                    "method": "GET", "protected": True, "expected_status": [401, 403]}]
            }))
            with self.assertRaisesRegex(ValueError, "non-global"):
                observe("AUTH", scope, pathlib.Path(directory) / "out.json")


if __name__ == "__main__":
    unittest.main()
