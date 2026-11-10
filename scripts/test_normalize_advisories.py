import json
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT=pathlib.Path(__file__).with_name("normalize_osv.py")


class MultiSourceNormalizationTests(unittest.TestCase):
    def test_correlates_osv_and_rustsec_aliases(self):
        with tempfile.TemporaryDirectory() as td:
            root=pathlib.Path(td)
            osv={"results":[{"source":{"path":"Cargo.lock"},"packages":[{"package":{"name":"demo","version":"1.2.3","ecosystem":"crates.io"},"vulnerabilities":[{"id":"GHSA-TEST","aliases":["RUSTSEC-2026-0001"],"database_specific":{"severity":"HIGH"}}]}]}]}
            rust={"vulnerabilities":{"list":[{"advisory":{"id":"RUSTSEC-2026-0001","aliases":["GHSA-TEST"],"severity":"high"},"package":{"name":"demo","version":"1.2.3"}}]}}
            (root/"osv.json").write_text(json.dumps(osv))
            (root/"rust.json").write_text(json.dumps(rust))
            out=root/"normalized.json"
            subprocess.run(["python3",str(SCRIPT),str(root/"osv.json"),"--rustsec-input",str(root/"rust.json"),"--output",str(out)],check=True)
            result=json.loads(out.read_text())
            self.assertEqual(len(result["matches"]),1)
            self.assertEqual(result["matches"][0]["sources"],["OSV","RustSec"])
            self.assertIn("RUSTSEC-2026-0001",result["matches"][0]["advisory_ids"])


if __name__=="__main__":unittest.main()
