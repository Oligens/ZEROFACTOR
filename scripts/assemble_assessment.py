#!/usr/bin/env python3
"""Join static scan, lockfile graph, OSV matches and verified evidence into one assessment JSON."""
import argparse,hashlib,json,pathlib,sys

def read(path,default):
 if not path:return default
 return json.loads(pathlib.Path(path).read_text())
def evidence_items(value):
 if value is None:return []
 return value if isinstance(value,list) else [value]
def validate_evidence(item):
 required=("evidence_id","assessment_id","test_id","classification","scope","observed_at","result","integrity")
 missing=[k for k in required if k not in item]
 if missing:raise ValueError("evidence missing required fields: "+", ".join(missing))
 if item["classification"] not in {"static","simulated","reproduced","independently_verified"}:raise ValueError("invalid evidence classification")
 if item["result"] not in {"pass","fail","inconclusive","not_run"}:raise ValueError("invalid evidence result")
 scope=item["scope"]
 if not all(scope.get(k) for k in ("authorization_id","target_fingerprint","expires_at")):raise ValueError("evidence scope is incomplete")
 digest=(item.get("integrity") or {}).get("sha256","")
 if len(digest)!=64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):raise ValueError("evidence SHA-256 is invalid")
 artifact=(item.get("integrity") or {}).get("artifact_uri")
 if artifact:
  p=pathlib.Path(artifact)
  if not p.is_file():raise ValueError("evidence artifact path does not exist locally: "+str(p))
  actual=hashlib.sha256(p.read_bytes()).hexdigest()
  if actual.lower()!=digest.lower():raise ValueError("evidence artifact SHA-256 mismatch: "+str(p))
 return True
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--report",required=True);ap.add_argument("--dependencies");ap.add_argument("--advisories");ap.add_argument("--evidence");ap.add_argument("--output",default="assessment-platform.json");a=ap.parse_args()
 report=read(a.report,{})
 graph=read(a.dependencies,{}) or {}; advisories=read(a.advisories,{}) or {}; ev=evidence_items(read(a.evidence,[]))
 for item in ev:validate_evidence(item)
 packages=graph.get("packages",[]);matches=advisories.get("matches",[])
 findings=list(report.get("findings",[]))
 for m in matches:
  ids=m.get("advisory_ids") or ["UNKNOWN"]
  for advisory_id in ids:
   findings.append({"id":"ZF-ADVISORY-"+advisory_id,"category":"dependency_vulnerability","severity":m.get("severity_label","unknown"),"status":"needs_review","title":str(advisory_id)+" affects "+str(m.get("package")),"path":m.get("source_lockfile",""),"line":None,"evidence":"Exact resolved version "+str(m.get("resolved_version"))+" matched by OSV-Scanner","recommendation":"Review advisory range, fixed version, package reachability and remediation before assigning exploitability."})
 for item in ev:
  fid=item.get("finding_id")
  if fid:
   for finding in findings:
    if finding.get("id")==fid:
     finding.setdefault("evidence_records",[]).append(item["evidence_id"])
     finding.setdefault("impact",[]).extend(item.get("impact",[]))
 impacts={}
 for item in ev:
  for impact in item.get("impact",[]):
   key=impact["dimension"];slot=impacts.setdefault(key,{"records":0,"measured_values":[]})
   slot["records"]+=1;slot["measured_values"].append({"value":impact["value"],"unit":impact["unit"],"method":impact["method"],"confidence":impact.get("confidence")})
 result=dict(report)
 result.update({"findings":findings,"resolved_dependencies":packages,"dependency_graph_complete":bool(graph.get("graph_complete",False)),"lockfiles_found":graph.get("lockfiles_found",0),"advisory_matches":matches,"advisory_scan_package_count":advisories.get("packages_with_exact_versions",0),"evidence_records":ev,"impact_summary":impacts,"platform_metadata":{"schema_version":"1.0","assembly":"scripts/assemble_assessment.py","limitations":["Advisory match is not reachability or exploitability evidence.","Dependency graph completeness is ecosystem and lockfile dependent.","Evidence records are only as trustworthy as their authorization, capture and artifact provenance."]}})
 pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+"\n")
 print(f"findings={len(findings)} resolved_packages={len(packages)} advisories={len(matches)} evidence={len(ev)}")
if __name__=="__main__":main()
