import json
import pathlib
import tempfile
import unittest

from evidence_manifest import build_manifest, verify_manifest


class EvidenceManifestTests(unittest.TestCase):
    def test_manifest_verifies_unchanged_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            artifact = root / "sbom.json"
            artifact.write_text('{"bomFormat":"CycloneDX"}')
            manifest_path = root / "manifest.json"
            build_manifest([str(artifact)], str(manifest_path))
            manifest, errors = verify_manifest(manifest_path)
            self.assertEqual(errors, [])
            self.assertEqual(len(manifest["artifacts"]), 1)

    def test_detects_artifact_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            artifact = root / "graph.json"
            artifact.write_text('{"packages":[]}')
            manifest_path = root / "manifest.json"
            build_manifest([str(artifact)], str(manifest_path))
            artifact.write_text('{"packages":[{"name":"tampered"}]}')
            _, errors = verify_manifest(manifest_path)
            self.assertTrue(any("SHA-256 mismatch" in item for item in errors))

    def test_detects_manifest_metadata_tampering(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            artifact = root / "graph.json"
            artifact.write_text("{}")
            manifest_path = root / "manifest.json"
            build_manifest([str(artifact)], str(manifest_path))
            data = json.loads(manifest_path.read_text())
            data["git_commit"] = "forged"
            manifest_path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "chain_hash mismatch"):
                verify_manifest(manifest_path)


if __name__ == "__main__":
    unittest.main()
