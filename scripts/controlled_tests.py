#!/usr/bin/env python3
"""Run a tiny allowlisted, non-destructive HTTP posture suite against explicitly authorized origins."""
import argparse, datetime as dt, hashlib, json, pathlib, ssl, sys, time, urllib.error, urllib.parse, urllib.request, uuid
from validate_scope import validate_scope

CHECKS = {"security_headers", "cookie_flags", "https_target_only"}
MAX_CHECKS, MAX_BODY = 3, 65536

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None

def run(scope_path, output, selected):
    scope=json.loads(pathlib.Path(scope_path).read_text(encoding="utf-8"))
    validated=validate_scope(scope)
    if "HTTP_POSTURE" not in validated["modules"]:
        raise ValueError("scope must explicitly authorize the HTTP_POSTURE module")
    base=scope["target_url"]
    parsed=urllib.parse.urlsplit(base)
    if not selected or len(selected)>MAX_CHECKS or not set(selected)<=CHECKS:
        raise ValueError("checks must be selected from the allowlist (maximum 3)")
    opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()),NoRedirect())
    request=urllib.request.Request(base,headers={"User-Agent":"ZEROFACTOR-controlled-check/1.0","Accept":"text/html,application/json"},method="GET")
    started=time.monotonic()
    try:
        with opener.open(request,timeout=min(8, validated["timeout_seconds"])) as response:
            body=response.read(MAX_BODY+1)
            if len(body)>MAX_BODY: body=body[:MAX_BODY]
            status=response.status; headers={k.lower():v for k,v in response.headers.items()}; cookie_values=response.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        status=e.code; headers={k.lower():v for k,v in e.headers.items()}; cookie_values=e.headers.get_all("Set-Cookie") or []; body=b""
    except Exception as exc: raise RuntimeError("Target request failed safely: "+type(exc).__name__) from exc
    elapsed_ms=round((time.monotonic()-started)*1000,2)
    missing=[]
    if "security_headers" in selected:
        for h in ("content-security-policy","x-content-type-options","referrer-policy","permissions-policy","strict-transport-security"):
            if h not in headers: missing.append(h)
    cookie_issues=[]
    if "cookie_flags" in selected:
        for value in cookie_values:
            low=value.lower()
            if value and ("secure" not in low or "httponly" not in low or "samesite" not in low): cookie_issues.append("cookie_missing_recommended_flags")
    checks=[]
    if "security_headers" in selected: checks.append({"test_id":"HTTP-SEC-HEADERS","result":"fail" if missing else "pass","observed":{"missing_headers":missing},"impact":[{"dimension":"security_posture","value":len(missing),"unit":"missing_security_headers","method":"response_header_presence","confidence":0.95}]})
    if "cookie_flags" in selected: checks.append({"test_id":"HTTP-COOKIE-FLAGS","result":"fail" if cookie_issues else "pass","observed":{"issues":cookie_issues},"impact":[{"dimension":"session_hardening","value":len(cookie_issues),"unit":"cookies_without_recommended_flags","method":"set_cookie_header_review","confidence":0.7}]})
    if "https_target_only" in selected: checks.append({"test_id":"HTTP-HTTPS-TARGET","result":"pass","observed":{"scheme":"https","status":status},"impact":[]})
    # Never persist response bodies: they may contain secrets or personal data.
    body_digest=hashlib.sha256(body).hexdigest()
    artifact_payload={"http_status":status,"body_bytes_observed":len(body),"body_sha256":body_digest,
                      "response_header_names":sorted(headers.keys()),"set_cookie_count":len(cookie_values)}
    artifact_bytes=json.dumps(artifact_payload,sort_keys=True,separators=(",",":")).encode()
    artifact_dir=pathlib.Path(output).with_suffix("").parent/"evidence-artifacts"; artifact_dir.mkdir(parents=True,exist_ok=True)
    artifact=artifact_dir/(uuid.uuid4().hex+".json"); artifact.write_bytes(artifact_bytes)
    digest=hashlib.sha256(artifact_bytes).hexdigest()
    target_fingerprint=hashlib.sha256((parsed.scheme+"://"+parsed.netloc).encode()).hexdigest()
    records=[]
    for c in checks:
        record={"evidence_id":str(uuid.uuid4()),"assessment_id":scope.get("assessment_id","controlled-http"),"test_id":c["test_id"],"classification":"reproduced" if c["result"]=="fail" else "static","scope":{"authorization_id":scope["authorization_id"],"target_fingerprint":target_fingerprint,"expires_at":scope["expires_at"]},"observed_at":dt.datetime.now(dt.timezone.utc).isoformat(),"result":c["result"],"finding_id":scope.get("finding_ids",{}).get(c["test_id"]),"impact":c["impact"],"observed":json.dumps({**c["observed"],"response_body_sha256":body_digest,"response_bytes_observed":len(body)},sort_keys=True),"integrity":{"sha256":digest,"artifact_uri":str(artifact)}}
        if record["finding_id"] is None: del record["finding_id"]
        records.append(record)
    result={"target_origin":parsed.scheme+"://"+parsed.netloc,"http_status":status,"duration_ms":elapsed_ms,"checks":checks,"evidence_records":records,"safety":{"methods":["GET"],"redirects_followed":False,"body_limit_bytes":MAX_BODY,"response_bodies_persisted":False,"no_exploit_payloads":True}}
    pathlib.Path(output).write_text(json.dumps(result,indent=2)+"\n")
    print(f"checks={len(checks)} failed={sum(x['result']=='fail' for x in checks)} evidence={len(records)}")
    return 1 if any(x["result"]=="fail" for x in checks) else 0

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--scope",required=True); ap.add_argument("--output",default="controlled-test-results.json"); ap.add_argument("--checks",nargs="+",choices=sorted(CHECKS),required=True); a=ap.parse_args()
    try:return run(a.scope,a.output,a.checks)
    except Exception as e: print(str(e),file=sys.stderr); return 2
if __name__=="__main__":sys.exit(main())
