import datetime as dt
import json
import pathlib
import tempfile
import unittest

from run_controlled_module import run


class ControlledEvidenceEnvelopeTests(unittest.TestCase):
    def test_envelope_carries_rust_ingestion_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            scope = root / "scope.json"
            fixture = root / "auth.json"
            output = root / "result.json"
            scope.write_text(json.dumps({
                "authorization_id": "written-auth-0001",
                "assessment_id": "assessment-fixture-01",
                "authorized": True,
                "owner": "Synthetic Lab Owner",
                "target_url": "https://fixture.example.test/",
                "allowed_hosts": ["fixture.example.test"],
                "expires_at": "2099-01-01T00:00:00Z",
                "modules": ["AUTH"],
            }), encoding="utf-8")
            fixture.write_text(json.dumps({
                "module": "AUTH", "case_id": "auth-case-01",
                "observations": [{
                    "route_id": "private-profile",
                    "expected_unauthenticated_status": [401, 403],
                    "observed_status": 200,
                    "protected_data_exposed": True,
                }],
            }), encoding="utf-8")
            result = run("AUTH", scope, fixture, output,
                         now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["assessment_id"], "assessment-fixture-01")
            self.assertEqual(saved["authorization_id"], "written-auth-0001")
            self.assertEqual(saved["expires_at"], "2099-01-01T00:00:00+00:00")
            self.assertEqual(len(saved["target_fingerprint"]), 64)
            self.assertEqual(saved["evidence_records"][0]["assessment_id"], "assessment-fixture-01")
            self.assertEqual(saved["safety"]["network_connections"], 0)
            self.assertEqual(result["result"], "fail")


if __name__ == "__main__":
    unittest.main()
