#!/usr/bin/env python3
"""Perform one verified TLS handshake against an explicitly authorized HTTPS hostname."""
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import socket
import ssl
import sys
import urllib.parse
from validate_scope import validate_scope

def run(scope_path, output, connect=socket.create_connection, context_factory=ssl.create_default_context):
    scope=json.loads(pathlib.Path(scope_path).read_text(encoding="utf-8"))
    validated=validate_scope(scope)
    if "TLS" not in validated["modules"]:
        raise ValueError("scope must explicitly authorize the TLS module")
    parsed=urllib.parse.urlsplit(scope["target_url"])
    host=parsed.hostname
    port=parsed.port or 443
    if port != 443:
        raise ValueError("TLS module only permits the standard HTTPS port 443")
    context=context_factory()
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    started=dt.datetime.now(dt.timezone.utc)
    try:
        with connect((host,port),timeout=min(8,validated["timeout_seconds"])) as raw:
            with context.wrap_socket(raw,server_hostname=host) as secured:
                cert_der=secured.getpeercert(binary_form=True)
                cert=secured.getpeercert()
                cipher=secured.cipher()
                protocol=secured.version()
                if not cert_der or not cert:
                    raise ssl.SSLError("peer certificate metadata unavailable")
                certificate_sha256=hashlib.sha256(cert_der).hexdigest()
                not_after=cert.get("notAfter")
                not_before=cert.get("notBefore")
                cipher_name=cipher[0] if cipher else None
                result="pass" if protocol in ("TLSv1.2","TLSv1.3") and cipher_name else "fail"
                details={
                    "hostname":host,
                    "port":port,
                    "certificate_sha256":certificate_sha256,
                    "not_before":not_before,
                    "not_after":not_after,
                    "tls_version":protocol,
                    "cipher":cipher_name,
                    "certificate_verified":True,
                }
    except ssl.SSLError as exc:
        # Certificate and protocol verification failures are negative TLS observations.
        result="fail"
        details={"hostname":host,"port":port,"failure_class":type(exc).__name__,"certificate_verified":False}
    except Exception as exc:
        # Do not serialize exception text: TLS/network exceptions can include target data.
        result="inconclusive"
        details={"hostname":host,"port":port,"failure_class":type(exc).__name__,"certificate_verified":False}
    observed_at=dt.datetime.now(dt.timezone.utc).isoformat()
    payload={
        "module":"TLS",
        "result":result,
        "observed_at":observed_at,
        "duration_seconds":round((dt.datetime.now(dt.timezone.utc)-started).total_seconds(),3),
        "details":details,
        "safety":{"handshakes":1,"application_data_sent":False,"minimum_tls":"1.2","certificate_verification":"enabled"},
    }
    pathlib.Path(output).write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
    print(f"module=TLS result={result} host_fingerprint={hashlib.sha256(host.encode()).hexdigest()}")
    return 0 if result=="pass" else 1 if result=="fail" else 2

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--scope",required=True)
    parser.add_argument("--output",default="tls-check.json")
    args=parser.parse_args()
    try:
        return run(args.scope,args.output)
    except Exception as exc:
        print(f"invalid_tls_scope: {type(exc).__name__}",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
