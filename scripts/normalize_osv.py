#!/usr/bin/env python3
"""Normalize OSV-Scanner and cargo-audit JSON into one exact-version advisory schema."""
import argparse
import json
import pathlib


def severity(v):
    db=(v.get("database_specific") or {}).get("severity") or v.get("severity")
    if db and str(db).lower() in {"critical","high","medium","moderate","low","info","informational"}:
        return str(db).lower()
    for item in v.get("severity") or []:
        score=str(item.get("score","")).strip()
        if score and score.replace(".","",1).isdigit():
            number=float(score)
            if number>=9:return "critical"
            if number>=7:return "high"
            if number>=4:return "medium"
            if number>0:return "low"
    score=v.get("cvss_score") or v.get("cvss")
    try:
        number=float(score)
        if number>=9:return "critical"
        if number>=7:return "high"
        if number>=4:return "medium"
        if number>0:return "low"
    except (TypeError,ValueError):
        pass
    return "unknown"


def normalize_osv(doc):
    matches=[];count=0;unresolved=[]
    for result in doc.get("results",[]):
        source=(result.get("source") or {}).get("path","")
        for item in result.get("packages",[]):
            p=item.get("package") or {};name=p.get("name");version=p.get("version");eco=p.get("ecosystem")
            if name and version:count+=1
            for v in (item.get("vulnerabilities") or item.get("vulns") or []):
                ids=sorted(set([v.get("id","UNKNOWN"),*(v.get("aliases") or [])]))
                matches.append({"ecosystem":eco,"package":name,"resolved_version":version,"version_match":bool(name and version),
                    "version_evidence":"exact-version-from-osv-scanner","severity_label":severity(v),"source":"OSV","sources":["OSV"],
                    "advisory_ids":ids,"modified":v.get("modified"),"published":v.get("published"),
                    "source_lockfile":source,"summary":v.get("summary","")})
            if not name or not version:unresolved.append({"source":source,"package":p})
    return matches,count,unresolved


def normalize_rustsec(doc):
    matches=[];unresolved=[]
    vulnerability_block=doc.get("vulnerabilities") or {}
    entries=vulnerability_block.get("list") or []
    for entry in entries:
        advisory=entry.get("advisory") or {}
        package=entry.get("package") or {}
        name=package.get("name") or advisory.get("package")
        version=package.get("version")
        advisory_id=advisory.get("id") or "UNKNOWN"
        aliases=advisory.get("aliases") or []
        if not name or not version:
            unresolved.append({"source":"cargo-audit","package":package,"advisory_id":advisory_id})
            continue
        matches.append({
            "ecosystem":"crates.io","package":name,"resolved_version":version,"version_match":True,
            "version_evidence":"exact-version-from-cargo-audit","severity_label":severity(advisory),
            "source":"RustSec","sources":["RustSec"],"advisory_ids":sorted(set([advisory_id,*aliases])),
            "modified":advisory.get("modified") or advisory.get("date"),
            "published":advisory.get("date"),"source_lockfile":"Cargo.lock",
            "summary":advisory.get("title") or advisory.get("description","")
        })
    # cargo-audit JSON can report an empty list without a vulnerabilities key.
    return matches,unresolved


def merge_matches(matches):
    """Merge cross-database aliases for the same exact package/version without losing source attribution."""
    merged=[]
    for item in matches:
        ids=set(item.get("advisory_ids") or [])
        target=None
        for existing in merged:
            same=(existing.get("ecosystem")==item.get("ecosystem")
                  and existing.get("package")==item.get("package")
                  and existing.get("resolved_version")==item.get("resolved_version"))
            if same and ids.intersection(existing.get("advisory_ids") or []):
                target=existing;break
        if target is None:
            merged.append(dict(item));continue
        target["advisory_ids"]=sorted(set(target.get("advisory_ids",[]))|ids)
        target["sources"]=sorted(set(target.get("sources",[target.get("source")]))|set(item.get("sources",[item.get("source")])))
        target["source"]="+".join(target["sources"])
        if target.get("severity_label")=="unknown" and item.get("severity_label")!="unknown":
            target["severity_label"]=item["severity_label"]
        if not target.get("summary"):target["summary"]=item.get("summary","")
    merged.sort(key=lambda x:(str(x["ecosystem"]),str(x["package"]),str(x["resolved_version"]),x["advisory_ids"]))
    return merged


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("input",type=pathlib.Path)
    ap.add_argument("--rustsec-input",type=pathlib.Path)
    ap.add_argument("--output",type=pathlib.Path,default=pathlib.Path("advisory-results.json"))
    a=ap.parse_args()
    doc=json.loads(a.input.read_text());matches,count,unresolved=normalize_osv(doc)
    if a.rustsec_input:
        rustsec_matches,rustsec_unresolved=normalize_rustsec(json.loads(a.rustsec_input.read_text()))
        matches.extend(rustsec_matches);unresolved.extend(rustsec_unresolved)
    matches=merge_matches(matches)
    out={"schema_version":"1.1","scanners":["OSV-Scanner"]+(["cargo-audit/RustSec"] if a.rustsec_input else []),
        "packages_with_exact_versions":count,"advisory_matches":len(matches),"matches":matches,
        "sources":sorted({source for item in matches for source in item.get("sources",[item.get("source")])}),
        "unresolved_package_records":unresolved,
        "coverage_note":"OSV and RustSec results are normalized and alias-correlated. Source freshness metadata is supplied separately. Exact version matches do not prove reachability or exploitability; the source set is not exhaustive global CVE coverage."}
    a.output.write_text(json.dumps(out,indent=2)+"\n")
    print(f"exact_osv_packages={count} advisory_matches={len(matches)} unresolved={len(unresolved)} sources={','.join(out['sources'])}")


if __name__=="__main__":main()
