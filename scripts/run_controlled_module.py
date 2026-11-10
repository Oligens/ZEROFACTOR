#!/usr/bin/env python3
"""Canonical offline module runner that emits Rust-ingestible provenance envelopes."""
import argparse
import datetime as dt
import hashlib
import json
import pathlib
import tempfile

from controlled_modules import evaluate
from validate_scope import validate_scope


def run(module, scope_path, fixture_path, output_path, now=None):
    scope = json.loads(pathlib.Path(scope_path).read_text(encoding="utf-8"))
    validated = validate_scope(scope, now=now)
    if module not in validated["modules"]:
        raise ValueError(f"scope must explicitly authorize the {module} module")
    with tempfile.TemporaryDirectory(prefix="zerofactor-fixture-") as temp_dir:
        temp_output = pathlib.Path(temp_dir) / "module-result.json"
        result = evaluate(module, scope_path, fixture_path, temp_output, now=now)
    fingerprint = hashlib.sha256(validated["target_origin"].encode("utf-8")).hexdigest()
    result["assessment_id"] = validated["assessment_id"]
    result["authorization_id"] = validated["authorization_id"]
    result["expires_at"] = validated["expires_at"]
    result["target_fingerprint"] = fingerprint
    for record in result["evidence_records"]:
        record["assessment_id"] = validated["assessment_id"]
        record["expires_at"] = validated["expires_at"]
    output = pathlib.Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description="Run an offline synthetic ZEROFACTOR module and emit an evidence envelope.")
    parser.add_argument("--module", required=True, choices=["AUTH", "INPUT", "FILE", "RATE", "RECOVERY"])
    parser.add_argument("--scope", required=True)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = run(args.module, args.scope, args.fixture, args.output)
        print(json.dumps({"module": result["module"], "result": result["result"],
                          "assessment_id": result["assessment_id"],
                          "evidence_records": len(result["evidence_records"]),
                          "network_connections": result["safety"]["network_connections"]}))
        return 0 if result["result"] == "pass" else 1 if result["result"] == "fail" else 2
    except Exception as exc:
        print("controlled_module_error: " + type(exc).__name__ + ": " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
