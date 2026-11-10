import json,pathlib,subprocess,tempfile,unittest
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
 def test_cargo_bare_lock_reference_when_unambiguous(self):
  lock='version = 4\n[[package]]\nname = "app"\nversion = "1.0.0"\ndependencies = ["serde"]\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
  d=self.run_script({"Cargo.lock":lock})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="app")["dependencies"],["serde@1.0.0"])
  self.assertTrue(d["graph_complete"])
 def test_npm_nested_package(self):
  d=self.run_script({"package-lock.json":json.dumps({"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/a":{"version":"2.0.0","dependencies":{"b":"^1"}},"node_modules/a/node_modules/b":{"version":"1.2.0"}}})})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="a")["dependencies"],["b@1.2.0"])
 def test_npm_v1_tree(self):
  d=self.run_script({"package-lock.json":json.dumps({"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}})})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="a")["dependencies"],["b@2.0.0"])
 def test_yarn_classic_edges(self):
  lock='foo@^1.0.0:\n  version "1.2.0"\n  dependencies:\n    bar "^2.0.0"\n\nbar@^2.0.0:\n  version "2.1.0"\n'
  d=self.run_script({"yarn.lock":lock})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="foo")["dependencies"],["bar@2.1.0"])
 def test_yarn_berry_edges(self):
  lock='"__metadata":\n  version: 6\n  cacheKey: 8\n\n"foo@npm:^1.0.0":\n  version: 1.2.0\n  resolution: "foo@npm:1.2.0"\n  dependencies:\n    bar: "npm:^2.0.0"\n\n"bar@npm:^2.0.0":\n  version: 2.1.0\n  resolution: "bar@npm:2.1.0"\n'
  d=self.run_script({"yarn.lock":lock})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="foo")["dependencies"],["bar@2.1.0"])
 def test_pnpm_v9_snapshots(self):
  lock='lockfileVersion: "9.0"\nimporters:\n  .:\n    dependencies:\n      foo:\n        specifier: ^1.0.0\n        version: 1.2.0\npackages:\n  foo@1.2.0:\n    resolution:\n      integrity: sha512-test\n  bar@2.1.0:\n    resolution:\n      integrity: sha512-test\nsnapshots:\n  foo@1.2.0:\n    dependencies:\n      bar: 2.1.0\n  bar@2.1.0: {}\n'
  d=self.run_script({"pnpm-lock.yaml":lock})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="foo")["dependencies"],["bar@2.1.0"])
  self.assertTrue(d["graph_complete"])
 def test_maven_dependency_tree_report(self):
  report='[INFO] com.example:app:jar:1.0:compile\n[INFO] +- org.example:lib:jar:2.0:compile\n[INFO] |  \\- org.example:core:jar:3.0:runtime\n'
  d=self.run_script({"pom.xml":"<project/>","maven-dependency-tree.txt":report})
  app=next(x for x in d["packages"] if x["name"]=="com.example:app")
  lib=next(x for x in d["packages"] if x["name"]=="org.example:lib")
  self.assertEqual(app["dependencies"],["org.example:lib@2.0"])
  self.assertEqual(lib["dependencies"],["org.example:core@3.0"])
  self.assertTrue(d["graph_complete"])
 def test_gradle_dependency_report_and_lock(self):
  report='runtimeClasspath - Runtime classpath\n+--- org.example:lib:1.0 -> 1.2\n|    \\--- org.example:core:2.0\n\\--- org.example:util:3.0\n'
  lock='org.example:lib=1.2\norg.example:core=2.0\norg.example:util=3.0\n'
  d=self.run_script({"gradle.lockfile":lock,"gradle-dependencies.txt":report})
  lib=next(x for x in d["packages"] if x["name"]=="org.example:lib")
  self.assertEqual(lib["version"],"1.2")
  self.assertEqual(lib["dependencies"],["org.example:core@2.0"])
  self.assertTrue(d["graph_complete"])
 def test_gradle_lock_without_report_is_incomplete(self):
  d=self.run_script({"gradle.lockfile":"org.example:lib=1.2\n"})
  self.assertFalse(d["graph_complete"])
 def test_composer_transitive_edge(self):
  lock={"packages":[{"name":"vendor/app","version":"1.0.0","require":{"vendor/lib":"^2.0.0"}},{"name":"vendor/lib","version":"2.1.0","require":{}}]}
  d=self.run_script({"composer.lock":json.dumps(lock)})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="vendor/app")["dependencies"],["vendor/lib@2.1.0"])
 def test_gemfile_lock_edge(self):
  lock='GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n    rack-protection (3.0.0)\n      rack (>= 1.6.0)\n\nPLATFORMS\n  ruby\n'
  d=self.run_script({"Gemfile.lock":lock})
  self.assertEqual(next(x for x in d["packages"] if x["name"]=="rack-protection")["dependencies"],["rack@2.2.8"])
 def test_poetry_exact_version_inventory_is_explicitly_incomplete(self):
  d=self.run_script({"poetry.lock":'[[package]]\nname = "urllib3"\nversion = "2.2.1"\n'})
  self.assertEqual(d["packages"][0]["version"],"2.2.1")
  self.assertFalse(d["graph_complete"])
if __name__=="__main__":unittest.main()
