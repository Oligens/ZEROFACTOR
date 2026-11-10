import datetime as dt
import json
import pathlib
import tempfile
import unittest

from controlled_modules import evaluate


class ControlledFixtureModuleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.scope = self.root / "scope.json"
        self.scope.write_text(json.dumps({
            "authorization_id": "synthetic-auth-2026",
            "authorized": True,
            "owner": "ZEROFACTOR Synthetic Test Owner",
            "target_url": "https://fixture.example.test/",
            "allowed_hosts": ["fixture.example.test"],
            "expires_at": "2099-01-01T00:00:00Z",
            "modules": ["AUTH", "INPUT", "FILE", "RATE", "RECOVERY"],
        }), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def run_case(self, module, fixture):
        fixture_path = self.root / (module.lower() + ".json")
        output_path = self.root / (module.lower() + "-result.json")
        fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
        result = evaluate(module, self.scope, fixture_path, output_path,
                          now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual(json.loads(output_path.read_text())["module"], module)
        self.assertEqual(result["safety"]["network_connections"], 0)
        self.assertEqual(result["safety"]["target_files_read"], 0)
        return result

    def test_auth_denies_unauthenticated_and_cross_project_access(self):
        result = self.run_case("AUTH", {
            "module": "AUTH", "case_id": "auth-fixture",
            "observations": [
                {"route_id": "private-profile", "expected_unauthenticated_status": [401, 403],
                 "observed_status": 401, "protected_data_exposed": False},
                {"route_id": "cross-project", "subject_id": "synthetic-viewer",
                 "resource_owner": "synthetic-other-project", "role": "viewer", "action": "read",
                 "expected_allowed": False, "observed_allowed": False},
            ],
        })
        self.assertEqual(result["result"], "pass")

    def test_auth_detects_exposed_protected_data(self):
        result = self.run_case("AUTH", {
            "module": "AUTH", "case_id": "auth-exposure",
            "observations": [{"route_id": "private-profile", "expected_unauthenticated_status": [401, 403],
                              "observed_status": 200, "protected_data_exposed": True}],
        })
        self.assertEqual(result["result"], "fail")

    def test_input_valid_and_invalid_boundaries(self):
        result = self.run_case("INPUT", {
            "module": "INPUT", "case_id": "input-fixture",
            "constraints": [{"field_id": "display-name", "type": "string", "required": True, "min_length": 1, "max_length": 32}],
            "observations": [
                {"case_id": "valid-name", "field_id": "display-name", "value_type": "string", "length": 12, "observed_accepted": True},
                {"case_id": "too-long", "field_id": "display-name", "value_type": "string", "length": 33, "observed_accepted": False},
            ],
        })
        self.assertEqual(result["result"], "pass")

    def test_input_detects_accepted_overlong_value(self):
        result = self.run_case("INPUT", {
            "module": "INPUT", "case_id": "input-bypass",
            "constraints": [{"field_id": "display-name", "type": "string", "required": True, "max_length": 8}],
            "observations": [{"case_id": "too-long", "field_id": "display-name", "value_type": "string",
                              "length": 20, "observed_accepted": True}],
        })
        self.assertEqual(result["result"], "fail")

    def test_file_access_and_metadata_policy(self):
        result = self.run_case("FILE", {
            "module": "FILE", "case_id": "file-fixture",
            "observations": [
                {"fixture_id": "public-avatar", "expected_access": "allow", "observed_access": "allow",
                 "declared_bytes": 1024, "max_bytes": 4096, "content_type_allowed": True, "extension_allowed": True},
                {"fixture_id": "private-document", "expected_access": "deny", "observed_access": "deny",
                 "declared_bytes": 2048, "max_bytes": 4096, "content_type_allowed": True, "extension_allowed": True},
            ],
        })
        self.assertEqual(result["result"], "pass")

    def test_file_detects_private_fixture_exposure(self):
        result = self.run_case("FILE", {
            "module": "FILE", "case_id": "file-exposure",
            "observations": [{"fixture_id": "private-document", "expected_access": "deny", "observed_access": "allow",
                              "declared_bytes": 100, "max_bytes": 4096, "content_type_allowed": True, "extension_allowed": True}],
        })
        self.assertEqual(result["result"], "fail")

    def test_rate_is_inconclusive_without_observed_throttle(self):
        result = self.run_case("RATE", {
            "module": "RATE", "case_id": "rate-fixture",
            "observations": [{"elapsed_ms": 0, "status": 200}, {"elapsed_ms": 1100, "status": 200}],
        })
        self.assertEqual(result["result"], "inconclusive")

    def test_rate_records_existing_throttle_signal(self):
        result = self.run_case("RATE", {
            "module": "RATE", "case_id": "rate-throttled",
            "observations": [{"elapsed_ms": 0, "status": 200},
                             {"elapsed_ms": 1200, "status": 429, "retry_after_present": True}],
        })
        self.assertEqual(result["result"], "pass")

    def test_recovery_requires_all_health_checks_and_rto(self):
        result = self.run_case("RECOVERY", {
            "module": "RECOVERY", "case_id": "recovery-fixture",
            "pre_snapshot_id": "snapshot-before-01", "post_snapshot_id": "snapshot-after-01",
            "operator_action_id": "operator-action-01", "elapsed_seconds": 18, "rto_seconds": 60,
            "post_health_checks": [{"healthy": True}, {"healthy": True}],
            "dependency_checks": [{"healthy": True}],
        })
        self.assertEqual(result["result"], "pass")

    def test_recovery_fails_when_dependency_is_unhealthy(self):
        result = self.run_case("RECOVERY", {
            "module": "RECOVERY", "case_id": "recovery-degraded",
            "pre_snapshot_id": "snapshot-before-02", "post_snapshot_id": "snapshot-after-02",
            "operator_action_id": "operator-action-02", "elapsed_seconds": 18, "rto_seconds": 60,
            "post_health_checks": [{"healthy": True}], "dependency_checks": [{"healthy": False}],
        })
        self.assertEqual(result["result"], "fail")

    def test_scope_permission_is_required_before_fixture_evaluation(self):
        scope = json.loads(self.scope.read_text())
        scope["modules"] = ["AUTH"]
        self.scope.write_text(json.dumps(scope))
        fixture = self.root / "rate.json"
        fixture.write_text(json.dumps({"module": "RATE", "case_id": "rate", "observations": [{"elapsed_ms": 0, "status": 200}]}))
        with self.assertRaisesRegex(ValueError, "explicitly authorize"):
            evaluate("RATE", self.scope, fixture, self.root / "out.json",
                     now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))

    def test_module_mismatch_is_rejected(self):
        fixture = self.root / "bad.json"
        fixture.write_text(json.dumps({"module": "FILE", "case_id": "wrong", "observations": []}))
        with self.assertRaisesRegex(ValueError, "does not match"):
            evaluate("AUTH", self.scope, fixture, self.root / "out.json",
                     now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))


if __name__ == "__main__":
    unittest.main()
