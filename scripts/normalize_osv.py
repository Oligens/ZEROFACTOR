#!/usr/bin/env python3
"""Normalize OSV-Scanner JSON while preserving exact resolved versions and advisory metadata."""
import argparse,json,pathlib
def severity(v):
    db=(v.get("database_specific") or {}).get("severity")
    if db:return str(db).lower()
    for item in v.get("severity") or []:
        score=str(item.get("score","")).strip()
        if score and score.replace(".","",1).isdigit():
            number=float(score)
            if number>=9:return "critical"
            if number>=7:return "high"
            if number>=4:return "medium"
            if number>0:return "low"
    return "unknown"
def main():
    ap=argparse.ArgumentParser();ap.add_argument("input",type=pathlib.Path);ap.add_argument("--output",type=pathlib.Path,default=pathlib.Path("advisory-results.json"));a=ap.parse_args()
    doc=json.loads(a.input.read_text());matches=[];count=0;unresolved=[]
    for result in doc.get("results",[]):
        source=(result.get("source") or {}).get("path","")
        for item in result.get("packages",[]):
            p=item.get("package") or {};name=p.get("name");version=p.get("version");eco=p.get("ecosystem")
            if name and version:count+=1
            for v in (item.get("vulnerabilities") or item.get("vulns") or []):
                ids=sorted(set([v.get("id","UNKNOWN"),*(v.get("aliases") or [])]))
                matches.append({"ecosystem":eco,"package":name,"resolved_version":version,"version_match":bool(name and version),
                    "version_evidence":"exact-version-from-osv-scanner","severity_label":severity(v),"source":"OSV",
                    "advisory_ids":ids,"modified":v.get("modified"),"published":v.get("published"),
                    "source_lockfile":source,"summary":v.get("summary","")})
            if not name or not version:unresolved.append({"source":source,"package":p})
    matches.sort(key=lambda x:(str(x["ecosystem"]),str(x["package"]),str(x["resolved_version"]),x["advisory_ids"]))
    out={"schema_version":"1.0","scanner":"OSV-Scanner","packages_with_exact_versions":count,"advisory_matches":len(matches),
        "matches":matches,"sources":[],"unresolved_package_records":unresolved,
        "coverage_note":"Supply source freshness metadata separately with --source-metadata; advisory modified timestamps are not database freshness timestamps. Results do not prove complete global CVE coverage, reachability or exploitability."}
    a.output.write_text(json.dumps(out,indent=2)+"\n");print(f"exact_packages={count} advisory_matches={len(matches)} unresolved={len(unresolved)}")
if __name__=="__main__":main()
