import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCOPE = ROOT / "fixtures" / "controlled" / "scope.synthetic.json"
FIXTURES = ROOT / "fixtures" / "controlled"
MODULES = ["AUTH", "INPUT", "FILE", "RATE", "RECOVERY"]


class RustEvidenceEndToEndTests(unittest.TestCase):
    def test_all_five_module_envelopes_import_into_rust_report(self):
        with tempfile.TemporaryDirectory(prefix="zerofactor-e2e-") as directory:
            temp = pathlib.Path(directory)
            evidence_paths = []
            for module in MODULES:
                output = temp / f"{module.lower()}.json"
                completed = subprocess.run([
                    "python3", str(ROOT / "scripts" / "run_controlled_module.py"),
                    "--module", module, "--scope", str(SCOPE),
                    "--fixture", str(FIXTURES / f"{module.lower()}.json"),
                    "--output", str(output),
                ], cwd=ROOT, check=False, capture_output=True, text=True)
                self.assertEqual(completed.returncode, 2 if module == "RATE" else 0,
                                 msg=f"{module}: {completed.stderr or completed.stdout}")
                self.assertTrue(output.is_file(), msg=f"{module} did not emit an evidence envelope")
                evidence_paths.append(output)

            target = temp / "target"
            target.mkdir()
            (target / "README.md").write_text("synthetic target fixture\n", encoding="utf-8")
            report_path = temp / "assessment.json"
            command = ["cargo", "run", "--quiet", "--", "scan", "--path", str(target), "--format", "json", "--out", str(report_path)]
            for evidence in evidence_paths:
                command.extend(["--evidence", str(evidence)])
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            summaries = {item["module"]: item for item in report["controlled_module_summaries"]}
            self.assertEqual(set(summaries), set(MODULES))
            self.assertEqual(summaries["RATE"]["result"], "inconclusive")
            self.assertTrue(all(item["evidence_kind"] == "synthetic_fixture" for item in summaries.values()))
            self.assertEqual(len(report["evidence_records"]), sum(item["cases"] for item in summaries.values()))
            self.assertIn("controlled_findings", report)


if __name__ == "__main__":
    unittest.main()
