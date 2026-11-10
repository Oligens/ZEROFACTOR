import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace

from assessment_gate import validate


class AssessmentGateTests(unittest.TestCase):
    def setup_artifacts(self, root, graph_packages=None, spdx_packages=None, cdx_components=None):
        values = {
            "graph.json": {"lockfiles_found": 1, "graph_complete": True,
                           "packages": graph_packages if graph_packages is not None else
                           [{"ecosystem":"npm","name":"demo","version":"1.0","dependencies":[],"unresolved_dependencies":[]}],
                           "errors": []},
            "advisories.json": {"matches": []},
            "policy.json": {"passed": True, "source_errors": []},
            "spdx.json": {"spdxVersion": "SPDX-2.3", "packages": spdx_packages if spdx_packages is not None else
                          [{"name":"demo","versionInfo":"1.0"}]},
            "cdx.json": {"bomFormat": "CycloneDX", "components": cdx_components if cdx_components is not None else
                         [{"name":"demo","version":"1.0"}]},
        }
        paths = {}
        for name, value in values.items():
            path = root / name
            path.write_text(json.dumps(value))
            paths[name] = path
        return SimpleNamespace(graph=paths["graph.json"], advisories=paths["advisories.json"],
                               policy_result=paths["policy.json"], osv_exit_code=0, rustsec_exit_code=0,
                               spdx=paths["spdx.json"], cyclonedx=paths["cdx.json"])

    def test_rejects_incomplete_graph_and_missing_cve_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            args = self.setup_artifacts(root)
            graph = json.loads(args.graph.read_text()); graph["graph_complete"] = False
            args.graph.write_text(json.dumps(graph))
            policy = json.loads(args.policy_result.read_text()); policy["passed"] = False
            policy["source_errors"] = ["missing OSV metadata"]
            args.policy_result.write_text(json.dumps(policy))
            result = validate(args)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("graph is incomplete" in x for x in result["failures"]))
            self.assertTrue(any("CVE policy" in x for x in result["failures"]))

    def test_passes_when_graph_edges_and_both_sboms_match(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            graph = [
                {"ecosystem":"npm","name":"demo","version":"1.0","dependencies":["left-pad@1.3.0"],"unresolved_dependencies":[]},
                {"ecosystem":"npm","name":"left-pad","version":"1.3.0","dependencies":[],"unresolved_dependencies":[]},
            ]
            spdx = [{"name":"demo","versionInfo":"1.0"},{"name":"left-pad","versionInfo":"1.3.0"}]
            cdx = [{"name":"demo","version":"1.0"},{"name":"left-pad","version":"1.3.0"}]
            args = self.setup_artifacts(root, graph, spdx, cdx)
            result = validate(args)
            self.assertEqual(result["status"], "passed", result["failures"])
            self.assertEqual(result["dependency_edge_count"], 1)

    def test_fails_when_dependency_edge_target_is_absent(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            graph = [{"ecosystem":"npm","name":"demo","version":"1.0",
                      "dependencies":["missing@2.0"],"unresolved_dependencies":[]}]
            args = self.setup_artifacts(root, graph)
            result = validate(args)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("edge target missing" in x for x in result["dependency_edge_errors"]))

    def test_fails_when_sbom_omits_graph_package(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            graph = [
                {"ecosystem":"npm","name":"demo","version":"1.0","dependencies":[],"unresolved_dependencies":[]},
                {"ecosystem":"npm","name":"left-pad","version":"1.3.0","dependencies":[],"unresolved_dependencies":[]},
            ]
            args = self.setup_artifacts(root, graph,
                [{"name":"demo","versionInfo":"1.0"}],
                [{"name":"demo","version":"1.0"}])
            result = validate(args)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("missing 1 dependency graph package" in x for x in result["failures"]))

    def test_fails_when_advisory_has_no_exact_version(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            args = self.setup_artifacts(root)
            data = {"matches":[{"package":"demo","resolved_version":None}]}
            args.advisories.write_text(json.dumps(data))
            result = validate(args)
            self.assertTrue(any("without exact package/version" in x for x in result["failures"]))


if __name__ == "__main__":
    unittest.main()
