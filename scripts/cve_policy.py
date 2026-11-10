#!/usr/bin/env python3
"""Apply deterministic severity, source and freshness policy to normalized advisory JSON."""
import argparse, datetime as dt, json, pathlib, sys

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "info": 0, "informational": 0}

def parse_time(value):
    if not value: return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError: return None

def evaluate(data, policy, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    max_age = int(policy.get("max_database_age_days", 7))
    allowed = set(policy.get("allowed_sources", ["OSV", "RustSec", "GitHub Advisory Database", "NVD"]))
    threshold = SEVERITY.get(str(policy.get("fail_on_or_above", "high")).lower(), 3)
    sources = data.get("sources", [])
    if isinstance(sources, dict): sources = [dict(name=k, last_updated=v) for k, v in sources.items()]
    freshness, source_errors = [], []
    for source in sources:
        name = source.get("name", "unknown")
        updated = parse_time(source.get("last_updated") or source.get("database_last_modified"))
        age = (now - updated).total_seconds() / 86400 if updated else None
        ok = name in allowed and age is not None and age <= max_age and age >= -1
        freshness.append({"source": name, "last_updated": source.get("last_updated") or source.get("database_last_modified"), "age_days": round(age, 2) if age is not None else None, "fresh": ok})
        if name not in allowed: source_errors.append(f"Unapproved advisory source: {name}")
        elif not ok: source_errors.append(f"Missing, invalid or stale database timestamp for {name}")
    matches, errors, blockers = data.get("matches", []), [], []
    for match in matches:
        package, version = match.get("package"), str(match.get("resolved_version") or "")
        exact = bool(package and version and match.get("version_match") is not False)
        if not exact:
            errors.append({"package": package, "reason": "No exact resolved package version; not policy-evaluable"})
            continue
        severity = str(match.get("severity_label") or "unknown").lower()
        level = SEVERITY.get(severity)
        source = match.get("source") or match.get("database") or "unknown"
        item = {"package": package, "version": version, "severity": severity, "source": source, "exact_version": True}
        if level is None:
            item["decision"] = "review"
            errors.append({**item, "reason": "Unknown severity"})
        elif level >= threshold:
            item["decision"] = "block"
            blockers.append(item)
        else: item["decision"] = "allow_with_record"
    return {"policy_version": "1.0", "evaluated_at": now.isoformat(), "database_freshness": freshness,
            "source_errors": source_errors, "evaluated_matches": [m for m in matches if m.get("resolved_version") and m.get("version_match") is not False],
            "decisions": {"block": blockers, "review": errors, "source_errors": source_errors},
            "passed": not blockers and not errors and not source_errors,
            "limitations": ["Freshness depends on trustworthy upstream timestamps.", "An exact package version match is not proof of reachability or exploitability.", "Missing CVEs in a source are not evidence of absence."]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("input"); ap.add_argument("--policy", default="config/cve-policy.json"); ap.add_argument("--output", default="cve-policy-result.json"); a=ap.parse_args()
    data=json.loads(pathlib.Path(a.input).read_text()); policy=json.loads(pathlib.Path(a.policy).read_text())
    result=evaluate(data,policy); pathlib.Path(a.output).write_text(json.dumps(result,indent=2)+"\n")
    print(f"passed={result['passed']} blockers={len(result['decisions']['block'])} review={len(result['decisions']['review'])} stale_sources={len(result['source_errors'])}")
    return 0 if result["passed"] else 1
if __name__=="__main__": sys.exit(main())
