#!/usr/bin/env python3
"""Apply deterministic severity, source and advisory-database freshness policy."""
import argparse, datetime as dt, json, pathlib, sys
SEVERITY={"critical":4,"high":3,"medium":2,"moderate":2,"low":1,"info":0,"informational":0}
def parse_time(value):
    if not value:return None
    try:
        x=dt.datetime.fromisoformat(str(value).replace("Z","+00:00"))
        return x if x.tzinfo else x.replace(tzinfo=dt.timezone.utc)
    except ValueError:return None
def evaluate(data,policy,now=None):
    now=now or dt.datetime.now(dt.timezone.utc)
    max_age=int(policy.get("max_database_age_days",7));allowed=set(policy.get("allowed_sources",["OSV"]))
    required=set(policy.get("required_sources",["OSV"]));threshold=SEVERITY.get(str(policy.get("fail_on_or_above","high")).lower(),3)
    sources=data.get("sources",[])
    if isinstance(sources,dict):sources=[dict(name=k,last_updated=v) for k,v in sources.items()]
    freshness=[];source_errors=[];seen=set()
    for source in sources:
        name=source.get("name","unknown");seen.add(name)
        updated=parse_time(source.get("last_updated") or source.get("database_last_modified"))
        age=(now-updated).total_seconds()/86400 if updated else None
        fresh=name in allowed and age is not None and -1<=age<=max_age
        freshness.append({"source":name,"last_updated":source.get("last_updated") or source.get("database_last_modified"),"age_days":round(age,2) if age is not None else None,"fresh":fresh})
        if name not in allowed:source_errors.append(f"Unapproved advisory source: {name}")
        elif not fresh:source_errors.append(f"Missing, invalid or stale database timestamp for {name}")
    for name in sorted(required-seen):source_errors.append(f"Required advisory source metadata missing: {name}")
    blockers=[];reviews=[];accepted=[]
    for match in data.get("matches",[]):
        package=match.get("package");version=str(match.get("resolved_version") or "")
        source=match.get("source") or match.get("database") or "unknown";severity=str(match.get("severity_label") or "unknown").lower()
        exact=bool(package and version and match.get("version_match") is not False)
        item={"package":package,"version":version,"severity":severity,"source":source,"exact_version":exact}
        if not exact:reviews.append({**item,"reason":"Exact resolved package version missing or explicitly mismatched"});continue
        if source not in allowed:reviews.append({**item,"reason":"Advisory source is not approved"});continue
        level=SEVERITY.get(severity)
        if level is None:reviews.append({**item,"reason":"Severity is unknown; manual review required"});continue
        if level>=threshold:blockers.append({**item,"decision":"block"})
        else:accepted.append({**item,"decision":"record"})
    return {"policy_version":"1.0","evaluated_at":now.isoformat(),"database_freshness":freshness,"source_errors":source_errors,
        "decisions":{"block":blockers,"review":reviews,"allow_with_record":accepted},"passed":not blockers and not reviews and not source_errors,
        "limitations":["Database freshness requires trusted upstream metadata; scan time is not database update time.","Exact version matching does not prove dependency reachability or exploitability.","No result can prove that every global advisory database contains every known vulnerability."]}
def main():
    ap=argparse.ArgumentParser();ap.add_argument("input");ap.add_argument("--policy",default="config/cve-policy.json");ap.add_argument("--source-metadata",help="JSON object containing trusted sources[].last_updated values");ap.add_argument("--output",default="cve-policy-result.json");a=ap.parse_args()
    data=json.loads(pathlib.Path(a.input).read_text());policy=json.loads(pathlib.Path(a.policy).read_text())
    if a.source_metadata:data["sources"]=json.loads(pathlib.Path(a.source_metadata).read_text()).get("sources",[])
    result=evaluate(data,policy);pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+"\n")
    print(f"passed={result['passed']} blockers={len(result['decisions']['block'])} review={len(result['decisions']['review'])} source_errors={len(result['source_errors'])}")
    return 0 if result["passed"] else 1
if __name__=="__main__":sys.exit(main())
