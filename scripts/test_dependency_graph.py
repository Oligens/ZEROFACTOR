import json, pathlib, subprocess, tempfile, unittest
SCRIPT=pathlib.Path(__file__).with_name("dependency_graph.py")
class LockGraphTests(unittest.TestCase):
 def run_script(self,files):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td)
   for name,content in files.items():
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
   out=root/"out.json";r=subprocess.run(["python3",str(SCRIPT),str(root),"--output",str(out)],capture_output=True,text=True)
   self.assertEqual(r.returncode,0,r.stderr);return json.loads(out.read_text())
 def test_cargo_exact_transitive_edge(self):
  d=self.run_script({"Cargo.lock":'version = 3\n[[package]]\nname = "app"\nversion = "1.0.0"\ndependencies = ["serde 1.0.1"]\n[[package]]\nname = "serde"\nversion = "1.0.1"\n'})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="app")["dependencies"],["serde@1.0.1"])
 def test_npm_nested_package(self):
  d=self.run_script({"package-lock.json":json.dumps({"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/a":{"version":"2.0.0","dependencies":{"b":"^1"}},"node_modules/a/node_modules/b":{"version":"1.2.0"}}})})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="a")["dependencies"],["b@1.2.0"])
 def test_poetry_exact_version(self):
  d=self.run_script({"poetry.lock":'[[package]]\nname = "urllib3"\nversion = "2.2.1"\n'})
  self.assertEqual(d["packages"][0]["version"],"2.2.1")
if __name__=="__main__":unittest.main()
