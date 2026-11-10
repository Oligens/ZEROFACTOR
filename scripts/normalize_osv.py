#!/usr/bin/env python3
"""Normalize OSV-Scanner JSON. Versions are exact versions extracted by OSV-Scanner."""
import argparse,json,pathlib
def main():
 ap=argparse.ArgumentParser();ap.add_argument("input",type=pathlib.Path);ap.add_argument("--output",type=pathlib.Path,default=pathlib.Path("advisory-results.json"));a=ap.parse_args()
 doc=json.loads(a.input.read_text());matches=[];count=0;unresolved=[]
 for result in doc.get("results",[]):
  source=(result.get("source") or {}).get("path","")
  for item in result.get("packages",[]):
   p=item.get("package") or {};name=p.get("name");version=p.get("version");eco=p.get("ecosystem")
   if name and version: count+=1
   for v in (item.get("vulnerabilities") or item.get("vulns") or []):
    ids=sorted(set([v.get("id","UNKNOWN"),*(v.get("aliases") or [])]))
    matches.append({"ecosystem":eco,"package":name,"resolved_version":version,"version_evidence":"exact-version-from-osv-scanner","advisory_ids":ids,"modified":v.get("modified"),"published":v.get("published"),"source_lockfile":source,"summary":v.get("summary","")})
   if not name or not version: unresolved.append({"source":source,"package":p})
 matches.sort(key=lambda x:(str(x["ecosystem"]),str(x["package"]),str(x["resolved_version"]),x["advisory_ids"]))
 out={"schema_version":"1.0","scanner":"OSV-Scanner","packages_with_exact_versions":count,"advisory_matches":len(matches),"matches":matches,"unresolved_package_records":unresolved,"coverage_note":"Results reflect supported extractors and the OSV database at scan time; they do not prove complete global CVE coverage, reachability, or exploitability."}
 a.output.write_text(json.dumps(out,indent=2)+"\n");print(f"exact_packages={count} advisory_matches={len(matches)} unresolved={len(unresolved)}")
if __name__=="__main__":main()
