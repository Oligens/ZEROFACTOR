#!/usr/bin/env python3
"""Fail-closed validation for explicit ZEROFACTOR controlled-test authorization scopes."""
import datetime as dt
import ipaddress
import json
import pathlib
import urllib.parse

ALLOWED_MODULES = {"HTTP_POSTURE", "AUTH", "INPUT", "FILE", "TLS", "RATE", "RECOVERY"}
LIVE_MODULES = {"HTTP_POSTURE", "AUTH", "FILE", "RATE", "RECOVERY"}
MAX_REQUESTS = 12
MAX_TIMEOUT_SECONDS = 30


def validate_scope(scope, now=None):
    if not isinstance(scope, dict):
        raise ValueError("scope must be a JSON object")
    required = ("authorization_id", "authorized", "owner", "target_url", "allowed_hosts", "expires_at", "modules")
    missing = [key for key in required if key not in scope]
    if missing:
        raise ValueError("missing required scope fields: " + ", ".join(missing))
    if scope["authorized"] is not True:
        raise ValueError("scope is not explicitly authorized")
    if not isinstance(scope["authorization_id"], str) or len(scope["authorization_id"].strip()) < 8:
        raise ValueError("authorization_id must contain at least 8 characters")
    if not isinstance(scope["owner"], str) or len(scope["owner"].strip()) < 3:
        raise ValueError("owner must identify the authorizing owner")
    assessment_id = scope.get("assessment_id", "assessment-" + scope["authorization_id"])
    if not isinstance(assessment_id, str) or not 1 <= len(assessment_id.strip()) <= 128:
        raise ValueError("assessment_id must be a non-empty identifier of at most 128 characters")
    try:
        expiry = dt.datetime.fromisoformat(str(scope["expires_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
    if expiry.tzinfo is None:
        raise ValueError("expires_at must include a timezone")
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=dt.timezone.utc)
    if expiry <= current:
        raise ValueError("authorization scope has expired")
    target = urllib.parse.urlsplit(str(scope["target_url"]))
    if target.scheme != "https" or not target.hostname:
        raise ValueError("target must be an HTTPS URL")
    if target.username or target.password or target.port not in (None, 443) or target.fragment:
        raise ValueError("credentials, non-standard ports and URL fragments are forbidden")
    hosts = scope["allowed_hosts"]
    if not isinstance(hosts, list) or not hosts or len(hosts) > 5:
        raise ValueError("allowed_hosts must contain between 1 and 5 exact hostnames")
    normalized = {str(host).strip().lower().rstrip(".") for host in hosts}
    if "" in normalized or target.hostname.lower().rstrip(".") not in normalized:
        raise ValueError("target hostname is not exactly allowlisted")
    modules = scope["modules"]
    if not isinstance(modules, list) or not modules or len(modules) != len(set(modules)):
        raise ValueError("modules must be a non-empty unique list")
    if not set(modules) <= ALLOWED_MODULES:
        raise ValueError("scope contains an unsupported module")
    budget = scope.get("request_budget", MAX_REQUESTS)
    timeout = scope.get("timeout_seconds", MAX_TIMEOUT_SECONDS)
    if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= MAX_REQUESTS:
        raise ValueError("request_budget must be between 1 and 12")
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError("timeout_seconds must be between 1 and 30")
    routes = scope.get("allowed_routes", [])
    if not isinstance(routes, list) or len(routes) > MAX_REQUESTS:
        raise ValueError("allowed_routes must be a list of at most 12 routes")
    route_ids = set()
    for route in routes:
        if not isinstance(route, dict) or not str(route.get("path", "")).startswith("/"):
            raise ValueError("each allowed route must have an absolute path")
        if route.get("method") not in ("GET", "HEAD"):
            raise ValueError("only GET and HEAD routes are permitted by default")
        route_id = route.get("id")
        if not isinstance(route_id, str) or not route_id or route_id in route_ids:
            raise ValueError("each allowed route requires a unique stable id")
        route_ids.add(route_id)
        if "?" in route["path"] or "#" in route["path"] or "\\" in route["path"]:
            raise ValueError("query strings, fragments and backslashes are forbidden in allowlisted paths")
        if route.get("module") is not None and route["module"] not in modules:
            raise ValueError("route module is not explicitly authorized by scope")
        if "max_response_bytes" in route and (
            not isinstance(route["max_response_bytes"], int) or isinstance(route["max_response_bytes"], bool)
            or not 0 <= route["max_response_bytes"] <= 65536
        ):
            raise ValueError("max_response_bytes must be between 0 and 65536")
    live_network = scope.get("live_network", False)
    if not isinstance(live_network, bool):
        raise ValueError("live_network must be a boolean")
    destination_ips = []
    if live_network:
        if not set(modules) & LIVE_MODULES:
            raise ValueError("no supported read-only live module is authorized")
        raw_ips = scope.get("allowed_destination_ips")
        if not isinstance(raw_ips, list) or not 1 <= len(raw_ips) <= 8:
            raise ValueError("live_network requires 1 to 8 explicit allowed_destination_ips")
        for raw_ip in raw_ips:
            try:
                address = ipaddress.ip_address(raw_ip)
            except ValueError as exc:
                raise ValueError("allowed_destination_ips must contain literal IP addresses") from exc
            if not address.is_global:
                raise ValueError("live adapter refuses private, loopback, link-local, reserved or non-global destination IPs")
            destination_ips.append(str(address))
        if len(set(destination_ips)) != len(destination_ips):
            raise ValueError("allowed_destination_ips must be unique")
        if not routes or len(routes) > budget:
            raise ValueError("live_network requires allowlisted routes within request_budget")
        for route in routes:
            route_module = route.get("module")
            if route_module not in LIVE_MODULES or route_module not in modules:
                raise ValueError("live route module must be explicitly authorized and supported")
            method = route["method"]
            if route_module == "FILE" and method != "HEAD":
                raise ValueError("live FILE observations are HEAD-only")
            if route_module in {"AUTH", "RATE", "RECOVERY", "HTTP_POSTURE"} and method != "GET":
                raise ValueError("live AUTH/RATE/RECOVERY/HTTP_POSTURE observations are GET-only")
            if route_module == "AUTH" and route.get("protected") is not True:
                raise ValueError("live AUTH routes must be explicitly marked protected")
            expected = route.get("expected_status")
            if route_module in {"AUTH", "FILE", "RECOVERY", "HTTP_POSTURE"} and (
                not isinstance(expected, list) or not expected or len(expected) > 5
                or not all(isinstance(x, int) and not isinstance(x, bool) and 100 <= x <= 599 for x in expected)
            ):
                raise ValueError("live route requires a bounded expected_status list")
        if "INPUT" in modules and any(r.get("module") == "INPUT" for r in routes):
            raise ValueError("INPUT remains fixture-only; live write/submit probes are disabled")
    return {
        "authorization_id": scope["authorization_id"],
        "assessment_id": assessment_id,
        "owner": scope["owner"],
        "target_origin": f"https://{target.netloc}",
        "target_host": target.hostname.lower().rstrip("."),
        "expires_at": expiry.astimezone(dt.timezone.utc).isoformat(),
        "modules": list(modules),
        "request_budget": budget,
        "timeout_seconds": timeout,
        "live_network": live_network,
        "allowed_destination_ips": destination_ips,
        "allowed_routes": routes,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True)
    args = parser.parse_args()
    try:
        scope = json.loads(pathlib.Path(args.scope).read_text(encoding="utf-8"))
        validated = validate_scope(scope)
        print(json.dumps({"valid": True, "scope": validated}, indent=2))
        return 0
    except Exception as exc:
        print(f"invalid_scope: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
