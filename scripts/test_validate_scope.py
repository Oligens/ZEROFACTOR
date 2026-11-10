import datetime as dt
import unittest
from validate_scope import validate_scope

def valid_scope():
    return {
        "authorization_id": "written-auth-0001",
        "authorized": True,
        "owner": "Synthetic Lab Owner",
        "target_url": "https://fixture.example.test/health",
        "allowed_hosts": ["fixture.example.test"],
        "expires_at": "2099-01-01T00:00:00Z",
        "modules": ["HTTP_POSTURE"],
    }

class ScopeValidationTests(unittest.TestCase):
    def test_accepts_explicit_unexpired_exact_host_scope(self):
        result = validate_scope(valid_scope(), now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual(result["target_origin"], "https://fixture.example.test")
        self.assertEqual(result["modules"], ["HTTP_POSTURE"])

    def test_requires_explicit_authorization(self):
        scope = valid_scope()
        scope["authorized"] = False
        with self.assertRaisesRegex(ValueError, "not explicitly authorized"):
            validate_scope(scope)

    def test_rejects_expired_scope(self):
        scope = valid_scope()
        scope["expires_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "expired"):
            validate_scope(scope)

    def test_rejects_unlisted_hostname(self):
        scope = valid_scope()
        scope["target_url"] = "https://other.example.test/"
        with self.assertRaisesRegex(ValueError, "not exactly allowlisted"):
            validate_scope(scope)

    def test_rejects_non_https_and_credentials(self):
        scope = valid_scope()
        scope["target_url"] = "http://fixture.example.test/"
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            validate_scope(scope)
        scope["target_url"] = "https://user:pass@fixture.example.test/"
        with self.assertRaisesRegex(ValueError, "credentials"):
            validate_scope(scope)

    def test_rejects_unsafe_route_method_and_excess_budget(self):
        scope = valid_scope()
        scope["allowed_routes"] = [{"id": "upload", "path": "/upload", "method": "POST"}]
        with self.assertRaisesRegex(ValueError, "GET and HEAD"):
            validate_scope(scope)
        scope = valid_scope()
        scope["request_budget"] = 13
        with self.assertRaisesRegex(ValueError, "request_budget"):
            validate_scope(scope)

if __name__ == "__main__":
    unittest.main()
