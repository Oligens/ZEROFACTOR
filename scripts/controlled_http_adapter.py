#!/usr/bin/env python3
"""Scope-pinned, sequential, read-only HTTPS observations for the disposable lab VM.

No DNS resolution, credentials, cookies, request bodies, redirects, writes or
response-body persistence. Destination IPs must be explicit in the signed-off
scope and separately allowed by the VM firewall.
"""
import argparse
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import pathlib
import socket
import ssl
import uuid

from validate_scope import validate_scope

MAX_BODY_BYTES = 65536
ALLOWED_MODULES = {"AUTH", "FILE", "RATE", "RECOVERY", "HTTP_POSTURE"}


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a literal allowlisted IP while preserving SNI."""
    def __init__(self, hostname, destination_ip, timeout):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self.destination_ip = str(ipaddress.ip_address(destination_ip))

    def connect(self):
        raw = socket.create_connection((self.destination_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _route_result(module, route, status, retry_after, body_limit_hit):
    if body_limit_hit:
        return "inconclusive", "response_body_limit_exceeded"
    if status is None:
        return "inconclusive", "network_observation_unavailable"
    if module == "RATE":
        return ("pass", "rate_limit_signal_observed") if status == 429 or retry_after else (
            "inconclusive", "single_passive_observation_cannot_establish_rate_limit_absence")
    expected = route["expected_status"]
    if status in expected:
        return "pass", "response_matches_declared_route_policy"
    return "fail", "response_status_outside_declared_route_policy"


def observe(module, scope_path, output_path):
    scope = json.loads(pathlib.Path(scope_path).read_text(encoding="utf-8"))
    validated = validate_scope(scope)
    if not validated["live_network"]:
        raise ValueError("scope must explicitly set live_network=true")
    if module not in ALLOWED_MODULES or module not in validated["modules"]:
        raise ValueError("requested module is not authorized for live read-only observation")
    if module == "INPUT":
        raise ValueError("INPUT remains fixture-only; active submission probes are disabled")
    routes = [route for route in validated["allowed_routes"] if route.get("module") == module]
    if not routes:
        raise ValueError("scope contains no routes for the requested module")
    if len(routes) > validated["request_budget"] or len(routes) > 12:
        raise ValueError("route count exceeds the authorized request budget")

    hostname = validated["target_host"]
    destination_ip = validated["allowed_destination_ips"][0]
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    target_fingerprint = hashlib.sha256(validated["target_origin"].encode("utf-8")).hexdigest()
    checks, records = [], []

    for route in routes:
        # Re-check expiry before every connection; route list is sequential.
        validated = validate_scope(scope)
        method, path = route["method"], route["path"]
        status = None
        body_bytes = 0
        body_digest = hashlib.sha256(b"").hexdigest()
        header_names = []
        retry_after = False
        content_length = None
        content_type = None
        body_limit_hit = False
        try:
            conn = PinnedHTTPSConnection(hostname, destination_ip, validated["timeout_seconds"])
            conn.request(method, path, body=None, headers={
                "Host": hostname,
                "User-Agent": "ZEROFACTOR-Authorized-ReadOnly/1.0",
                "Accept": "*/*",
                "Connection": "close",
            })
            response = conn.getresponse()
            status = response.status
            header_names = sorted({name.lower() for name, _ in response.getheaders()})
            retry_after = response.getheader("Retry-After") is not None
            raw_length = response.getheader("Content-Length")
            content_length = int(raw_length) if raw_length and raw_length.isdigit() else None
            content_type = (response.getheader("Content-Type") or "")[:128] or None
            if method == "GET":
                body = response.read(min(route.get("max_response_bytes", MAX_BODY_BYTES), MAX_BODY_BYTES) + 1)
                body_limit = min(route.get("max_response_bytes", MAX_BODY_BYTES), MAX_BODY_BYTES)
                body_limit_hit = len(body) > body_limit
                if not body_limit_hit:
                    body_bytes = len(body)
                    body_digest = hashlib.sha256(body).hexdigest()
            response.close()
            conn.close()
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            status = None

        result, reason = _route_result(module, route, status, retry_after, body_limit_hit)
        check = {
            "case_id": route["id"],
            "result": result,
            "reason": reason,
            "status_code": status,
            "method": method,
            "body_bytes": body_bytes,
            "body_sha256": body_digest,
            "retry_after_present": retry_after,
            "header_names": header_names,
            "content_length": content_length,
            "content_type": content_type,
        }
        checks.append(check)
        records.append({
            "evidence_id": str(uuid.uuid4()),
            "module": module,
            "case_id": route["id"],
            "classification": "controlled_observation",
            "result": result,
            "reason": reason,
            "authorization_id": validated["authorization_id"],
            "assessment_id": validated["assessment_id"],
            "target_fingerprint": target_fingerprint,
            "expires_at": validated["expires_at"],
            "observed_at": observed_at,
            "route_id": route["id"],
            "method": method,
            "status_code": status,
            "body_bytes": body_bytes,
            "body_sha256": body_digest,
            "retry_after_present": retry_after,
            "header_names": header_names,
            "content_length": content_length,
            "content_type": content_type,
        })

    if any(check["result"] == "fail" for check in checks):
        overall = "fail"
    elif any(check["result"] == "inconclusive" for check in checks):
        overall = "inconclusive"
    else:
        overall = "pass"
    result = {
        "schema_version": 1,
        "module": module,
        "case_id": validated["assessment_id"],
        "assessment_id": validated["assessment_id"],
        "authorization_id": validated["authorization_id"],
        "expires_at": validated["expires_at"],
        "target_fingerprint": target_fingerprint,
        "result": overall,
        "evidence_kind": "controlled_observation",
        "observed_at": observed_at,
        "checks": checks,
        "evidence_records": records,
        "safety": {
            "network_connections": len(records),
            "target_files_read": 0,
            "target_files_written": 0,
            "credentials_used": 0,
            "redirects_followed": 0,
            "response_body_bytes_persisted": 0,
            "maximum_response_bytes": MAX_BODY_BYTES,
            "concurrency": 1,
        },
        "limitations": [
            "Only explicitly allowlisted GET/HEAD routes were observed.",
            "Response bodies were not retained; only bounded byte counts and SHA-256 digests were recorded.",
            "A failed policy comparison is a review candidate, not proof of exploitability.",
            "VM/firewall egress enforcement and independently validated gVisor isolation are mandatory.",
        ],
    }
    output = pathlib.Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description="Perform bounded, read-only HTTPS observations in an authorized lab.")
    parser.add_argument("--module", required=True, choices=sorted(ALLOWED_MODULES))
    parser.add_argument("--scope", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = observe(args.module, args.scope, args.output)
        print(json.dumps({"module": result["module"], "result": result["result"],
                          "observations": len(result["checks"]),
                          "network_connections": result["safety"]["network_connections"],
                          "redirects_followed": 0}))
        return 0 if result["result"] == "pass" else 1 if result["result"] == "fail" else 2
    except Exception as exc:
        print("controlled_http_error: " + type(exc).__name__ + ": " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
