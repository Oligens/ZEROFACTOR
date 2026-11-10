import json,pathlib,subprocess,tempfile,unittest
SCRIPT=pathlib.Path(__file__).with_name("assemble_assessment.py")
class AssemblyTests(unittest.TestCase):
 def test_links_advisory_and_impact_evidence(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td)
   report={"findings":[],"files_examined":3}
   graph={"packages":[{"ecosystem":"npm","name":"demo","version":"1.2.3"}],"graph_complete":True,"lockfiles_found":1}
   advisory={"packages_with_exact_versions":1,"matches":[{"package":"demo","resolved_version":"1.2.3","source_lockfile":"package-lock.json","advisory_ids":["GHSA-test"]}]}
   evidence={"evidence_id":"evidence-0001","assessment_id":"assessment-1","test_id":"test-1","finding_id":"ZF-ADVISORY-GHSA-test","classification":"reproduced","scope":{"authorization_id":"auth-1","target_fingerprint":"sha256:target","expires_at":"2099-01-01T00:00:00Z"},"observed_at":"2026-01-01T00:00:00Z","result":"fail","impact":[{"dimension":"integrity","value":1,"unit":"synthetic records","method":"controlled fixture"}],"integrity":{"sha256":"a"*64}}
   for name,obj in (("report.json",report),("graph.json",graph),("advisory.json",advisory),("evidence.json",evidence)):
    (root/name).write_text(json.dumps(obj))
   out=root/"joined.json"
   subprocess.run(["python3",str(SCRIPT),"--report",str(root/"report.json"),"--dependencies",str(root/"graph.json"),"--advisories",str(root/"advisory.json"),"--evidence",str(root/"evidence.json"),"--output",str(out)],check=True)
   joined=json.loads(out.read_text())
   finding=joined["findings"][0]
   self.assertEqual(finding["evidence_records"],["evidence-0001"])
   self.assertEqual(finding["impact"][0]["dimension"],"integrity")
   self.assertTrue(joined["dependency_graph_complete"])
if __name__=="__main__":unittest.main()
