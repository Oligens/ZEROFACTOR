import datetime as dt
import unittest

from validate_scope import validate_scope


def live_scope():
    return {
        "authorization_id": "written-auth-0001",
        "assessment_id": "live-assessment-001",
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
            "id": "private-profile",
            "module": "AUTH",
            "path": "/private/profile",
            "method": "GET",
            "protected": True,
            "expected_status": [401, 403],
            "max_response_bytes": 4096
        }]
    }


class LiveScopeValidationTests(unittest.TestCase):
    def test_accepts_explicit_public_ip_pinned_read_only_route(self):
        result = validate_scope(live_scope(), now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        self.assertTrue(result["live_network"])
        self.assertEqual(result["allowed_destination_ips"], ["93.184.216.34"])
        self.assertEqual(result["allowed_routes"][0]["method"], "GET")

    def test_rejects_missing_destination_ip_allowlist(self):
        scope = live_scope()
        del scope["allowed_destination_ips"]
        with self.assertRaisesRegex(ValueError, "allowed_destination_ips"):
            validate_scope(scope)

    def test_rejects_private_or_loopback_destination(self):
        scope = live_scope()
        scope["allowed_destination_ips"] = ["127.0.0.1"]
        with self.assertRaisesRegex(ValueError, "non-global"):
            validate_scope(scope)

    def test_rejects_live_input_submission_route(self):
        scope = live_scope()
        scope["modules"] = ["INPUT"]
        scope["allowed_routes"][0] = {
            "id": "input", "module": "INPUT", "path": "/search",
            "method": "GET", "expected_status": [200]
        }
        with self.assertRaisesRegex(ValueError, "not explicitly authorized|supported"):
            validate_scope(scope)

    def test_rejects_auth_route_not_marked_protected(self):
        scope = live_scope()
        scope["allowed_routes"][0]["protected"] = False
        with self.assertRaisesRegex(ValueError, "marked protected"):
            validate_scope(scope)

    def test_rejects_query_string_and_non_allowlisted_module(self):
        scope = live_scope()
        scope["allowed_routes"][0]["path"] = "/private/profile?next=/admin"
        with self.assertRaisesRegex(ValueError, "query strings"):
            validate_scope(scope)
        scope = live_scope()
        scope["allowed_routes"][0]["module"] = "INPUT"
        with self.assertRaisesRegex(ValueError, "route module"):
            validate_scope(scope)


if __name__ == "__main__":
    unittest.main()
