import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace

from assessment_gate import validate


class AssessmentGateTests(unittest.TestCase):
    def test_rejects_incomplete_graph_and_missing_cve_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            values = {
                "graph.json": {"lockfiles_found": 1, "graph_complete": False, "packages": [], "errors": []},
                "advisories.json": {"matches": []},
                "policy.json": {"passed": False, "source_errors": ["missing OSV metadata"]},
                "spdx.json": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "demo", "versionInfo": "1.0"}]},
                "cdx.json": {"bomFormat": "CycloneDX", "components": [{"name": "demo", "version": "1.0"}]},
            }
            paths = {}
            for name, value in values.items():
                path = root / name
                path.write_text(json.dumps(value))
                paths[name] = path
            args = SimpleNamespace(
                graph=paths["graph.json"], advisories=paths["advisories.json"],
                policy_result=paths["policy.json"], osv_exit_code=0,
                spdx=paths["spdx.json"], cyclonedx=paths["cdx.json"]
            )
            result = validate(args)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("graph is incomplete" in x for x in result["failures"]))
            self.assertTrue(any("CVE policy" in x for x in result["failures"]))

    def test_passes_when_all_required_artifacts_are_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            values = {
                "graph.json": {"lockfiles_found": 1, "graph_complete": True, "packages": [{"name": "demo"}], "errors": []},
                "advisories.json": {"matches": []},
                "policy.json": {"passed": True, "source_errors": []},
                "spdx.json": {"spdxVersion": "SPDX-2.3", "packages": [{"name": "demo", "versionInfo": "1.0"}]},
                "cdx.json": {"bomFormat": "CycloneDX", "components": [{"name": "demo", "version": "1.0"}]},
            }
            paths = {}
            for name, value in values.items():
                path = root / name
                path.write_text(json.dumps(value))
                paths[name] = path
            args = SimpleNamespace(
                graph=paths["graph.json"], advisories=paths["advisories.json"],
                policy_result=paths["policy.json"], osv_exit_code=0,
                spdx=paths["spdx.json"], cyclonedx=paths["cdx.json"]
            )
            self.assertEqual(validate(args)["status"], "passed")


if __name__ == "__main__":
    unittest.main()
