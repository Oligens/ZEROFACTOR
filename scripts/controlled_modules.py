#!/usr/bin/env python3
"""Offline, fixture-only evaluators for ZEROFACTOR controlled modules.

This module never opens a network connection and never reads target files. It
compares bounded synthetic observations with declared expectations and emits
redacted evidence metadata.
"""
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
import uuid

from validate_scope import validate_scope

MODULES = {"AUTH", "INPUT", "FILE", "RATE", "RECOVERY"}
MAX_FIXTURE_BYTES = 64 * 1024
MAX_CASES = 12


def _read_json(path, label):
    data = pathlib.Path(path).read_bytes()
    if len(data) > MAX_FIXTURE_BYTES:
        raise ValueError(f"{label} exceeds the 64 KiB fixture limit")
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def _bool(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _safe_id(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}", value):
        raise ValueError(f"{label} must be a safe 1–96 character identifier")
    return value


def _auth(fixture):
    observations = fixture.get("observations")
    if not isinstance(observations, list) or not 1 <= len(observations) <= 4:
        raise ValueError("AUTH requires 1 to 4 read-only observations")
    checks = []
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("AUTH observations must be objects")
        route_id = _safe_id(item.get("route_id"), "route_id")
        if "expected_unauthenticated_status" in item:
            expected = item["expected_unauthenticated_status"]
            if not isinstance(expected, list) or not expected or not set(expected) <= {401, 403}:
                raise ValueError("AUTH expected status must contain only 401/403")
            observed = item.get("observed_status")
            if not isinstance(observed, int) or isinstance(observed, bool) or not 100 <= observed <= 599:
                raise ValueError("AUTH observed_status must be an HTTP status")
            exposed = _bool(item.get("protected_data_exposed"), "protected_data_exposed")
            passed = observed in expected and not exposed
            checks.append({"case_id": route_id, "result": "pass" if passed else "fail",
                           "reason": "unauthenticated_access_denied" if passed else "unexpected_status_or_protected_data_exposure"})
        else:
            _safe_id(item.get("subject_id"), "subject_id")
            _safe_id(item.get("resource_owner"), "resource_owner")
            if item.get("role") not in {"owner", "analyst", "viewer"}:
                raise ValueError("AUTH role must be owner, analyst or viewer")
            if item.get("action") not in {"read", "list"}:
                raise ValueError("AUTH action must be read or list")
            expected = _bool(item.get("expected_allowed"), "expected_allowed")
            observed = _bool(item.get("observed_allowed"), "observed_allowed")
            passed = expected == observed
            checks.append({"case_id": route_id, "result": "pass" if passed else "fail",
                           "reason": "authorization_decision_matches_policy" if passed else "authorization_decision_mismatch"})
    return checks


def _input(fixture):
    constraints = fixture.get("constraints")
    observations = fixture.get("observations")
    if not isinstance(constraints, list) or not 1 <= len(constraints) <= 8:
        raise ValueError("INPUT requires 1 to 8 field constraints")
    if not isinstance(observations, list) or not 1 <= len(observations) <= 8:
        raise ValueError("INPUT requires 1 to 8 benign boundary observations")
    by_id = {}
    for rule in constraints:
        if not isinstance(rule, dict):
            raise ValueError("INPUT constraints must be objects")
        field_id = _safe_id(rule.get("field_id"), "field_id")
        if field_id in by_id:
            raise ValueError("INPUT field_id values must be unique")
        if rule.get("type") not in {"string", "integer", "boolean", "enum"}:
            raise ValueError("INPUT supports string, integer, boolean and enum constraints")
        by_id[field_id] = rule
    checks = []
    for case in observations:
        if not isinstance(case, dict):
            raise ValueError("INPUT observations must be objects")
        field_id = _safe_id(case.get("field_id"), "field_id")
        rule = by_id.get(field_id)
        if rule is None:
            raise ValueError("INPUT observation references an undeclared field")
        value_type = case.get("value_type")
        accepted = _bool(case.get("observed_accepted"), "observed_accepted")
        valid = value_type == rule["type"]
        if valid and rule["type"] == "string":
            length = case.get("length")
            valid = isinstance(length, int) and not isinstance(length, bool) and length >= 0
            if valid and rule.get("required") is True:
                valid = length > 0
            if valid and "max_length" in rule:
                valid = length <= rule["max_length"]
            if valid and "min_length" in rule:
                valid = length >= rule["min_length"]
        elif valid and rule["type"] == "integer":
            value = case.get("integer_value")
            valid = isinstance(value, int) and not isinstance(value, bool)
            if valid and "minimum" in rule:
                valid = value >= rule["minimum"]
            if valid and "maximum" in rule:
                valid = value <= rule["maximum"]
        elif valid and rule["type"] == "boolean":
            valid = isinstance(case.get("boolean_value"), bool)
        elif valid and rule["type"] == "enum":
            valid = case.get("enum_value") in rule.get("allowed_values", [])
        passed = valid == accepted
        checks.append({"case_id": _safe_id(case.get("case_id"), "case_id"),
                       "result": "pass" if passed else "fail",
                       "reason": "acceptance_matches_declared_constraint" if passed else "input_constraint_mismatch"})
    return checks


def _file(fixture):
    observations = fixture.get("observations")
    if not isinstance(observations, list) or not 1 <= len(observations) <= 4:
        raise ValueError("FILE requires 1 to 4 synthetic file metadata observations")
    checks = []
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("FILE observations must be objects")
        fixture_id = _safe_id(item.get("fixture_id"), "fixture_id")
        expected = item.get("expected_access")
        observed = item.get("observed_access")
        if expected not in {"allow", "deny"} or observed not in {"allow", "deny"}:
            raise ValueError("FILE access decisions must be allow or deny")
        size = item.get("declared_bytes")
        maximum = item.get("max_bytes")
        if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in (size, maximum)):
            raise ValueError("FILE sizes must be non-negative integers")
        content_ok = _bool(item.get("content_type_allowed"), "content_type_allowed")
        extension_ok = _bool(item.get("extension_allowed"), "extension_allowed")
        policy_ok = content_ok and extension_ok and size <= maximum
        passed = (expected == observed) and (observed == "deny" or policy_ok)
        checks.append({"case_id": fixture_id, "result": "pass" if passed else "fail",
                       "reason": "file_access_matches_policy" if passed else "file_access_or_metadata_policy_mismatch"})
    return checks


def _rate(fixture):
    observations = fixture.get("observations")
    if not isinstance(observations, list) or not 1 <= len(observations) <= 3:
        raise ValueError("RATE accepts 1 to 3 pre-existing sequential observations only")
    previous = -1
    throttled = False
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("RATE observations must be objects")
        elapsed = item.get("elapsed_ms")
        status = item.get("status")
        if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed < 0 or elapsed < previous:
            raise ValueError("RATE elapsed_ms values must be ordered non-negative integers")
        if previous >= 0 and elapsed - previous < 1000:
            raise ValueError("RATE observations must be at least 1000 ms apart")
        if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
            raise ValueError("RATE status must be an HTTP status")
        retry = _bool(item.get("retry_after_present", False), "retry_after_present")
        throttled = throttled or status == 429 or retry
        previous = elapsed
    documented_limit = fixture.get("documented_limit")
    if documented_limit is not None and (not isinstance(documented_limit, int) or isinstance(documented_limit, bool) or documented_limit < 1):
        raise ValueError("RATE documented_limit must be a positive integer")
    if throttled:
        result, reason = "pass", "rate_limit_signal_observed"
    elif documented_limit is not None and len(observations) > documented_limit:
        result, reason = "fail", "documented_threshold_exceeded_without_throttle_signal"
    else:
        result, reason = "inconclusive", "small_passive_sample_cannot_prove_rate_limit_absence"
    return [{"case_id": "rate-observation", "result": result, "reason": reason}]


def _recovery(fixture):
    pre_id = _safe_id(fixture.get("pre_snapshot_id"), "pre_snapshot_id")
    post_id = _safe_id(fixture.get("post_snapshot_id"), "post_snapshot_id")
    _safe_id(fixture.get("operator_action_id"), "operator_action_id")
    elapsed = fixture.get("elapsed_seconds")
    rto = fixture.get("rto_seconds")
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) and x >= 0 for x in (elapsed, rto)):
        raise ValueError("RECOVERY elapsed_seconds and rto_seconds must be non-negative numbers")
    health = fixture.get("post_health_checks")
    dependencies = fixture.get("dependency_checks", [])
    if not isinstance(health, list) or not health or not isinstance(dependencies, list):
        raise ValueError("RECOVERY requires post_health_checks and optional dependency_checks")
    if not all(isinstance(x, dict) and isinstance(x.get("healthy"), bool) for x in health + dependencies):
        raise ValueError("RECOVERY checks must contain boolean healthy values")
    passed_health = all(x["healthy"] for x in health + dependencies)
    passed = passed_health and elapsed <= rto
    return [{"case_id": "recovery-" + hashlib.sha256((pre_id + post_id).encode()).hexdigest()[:12],
             "result": "pass" if passed else "fail",
             "reason": "operator_observed_recovery_within_rto" if passed else "health_check_failed_or_recovery_objective_missed"}]


EVALUATORS = {"AUTH": _auth, "INPUT": _input, "FILE": _file, "RATE": _rate, "RECOVERY": _recovery}


def evaluate(module, scope_path, fixture_path, output_path, now=None):
    if module not in MODULES:
        raise ValueError("unsupported controlled module")
    scope = _read_json(scope_path, "scope")
    validated = validate_scope(scope, now=now)
    if module not in validated["modules"]:
        raise ValueError(f"scope must explicitly authorize the {module} module")
    fixture = _read_json(fixture_path, "fixture")
    if fixture.get("module") != module:
        raise ValueError("fixture module does not match requested module")
    case_id = _safe_id(fixture.get("case_id"), "case_id")
    checks = EVALUATORS[module](fixture)
    if not checks:
        overall = "inconclusive"
    elif any(c["result"] == "fail" for c in checks):
        overall = "fail"
    elif any(c["result"] == "inconclusive" for c in checks):
        overall = "inconclusive"
    else:
        overall = "pass"
    target_fingerprint = hashlib.sha256(validated["target_origin"].encode("utf-8")).hexdigest()
    observed_at = dt.datetime.now(dt.timezone.utc).isoformat()
    evidence = []
    for check in checks:
        evidence.append({
            "evidence_id": str(uuid.uuid4()),
            "module": module,
            "case_id": check["case_id"],
            "classification": "synthetic_fixture",
            "result": check["result"],
            "reason": check["reason"],
            "authorization_id": validated["authorization_id"],
            "authorization_expires_at": validated["expires_at"],
            "target_fingerprint": target_fingerprint,
            "observed_at": observed_at,
        })
    result = {
        "schema_version": 1,
        "module": module,
        "case_id": case_id,
        "result": overall,
        "evidence_kind": "synthetic_fixture",
        "observed_at": observed_at,
        "authorization_id": validated["authorization_id"],
        "authorization_expires_at": validated["expires_at"],
        "target_fingerprint": target_fingerprint,
        "checks": checks,
        "evidence_records": evidence,
        "safety": {
            "network_connections": 0,
            "target_files_read": 0,
            "target_files_written": 0,
            "credentials_used": 0,
            "fixture_limit_bytes": MAX_FIXTURE_BYTES,
            "maximum_cases": MAX_CASES,
        },
        "limitations": [
            "This result evaluates supplied synthetic observations only.",
            "It is not a live target test, penetration test, or proof of operational security.",
            "Dynamic execution remains gated on independently validated gVisor host isolation.",
        ],
    }
    output = pathlib.Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description="Evaluate a ZEROFACTOR module using offline synthetic fixtures only.")
    parser.add_argument("--module", required=True, choices=sorted(MODULES))
    parser.add_argument("--scope", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = evaluate(args.module, args.scope, args.fixture, args.output)
        print(json.dumps({"module": result["module"], "result": result["result"],
                          "checks": len(result["checks"]), "network_connections": 0}))
        return 0 if result["result"] == "pass" else 1 if result["result"] == "fail" else 2
    except Exception as exc:
        print("controlled_module_error: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
