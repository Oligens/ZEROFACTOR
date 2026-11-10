#!/usr/bin/env python3
"""Fail-closed validation gate for required ZEROFACTOR assessment artifacts."""
import argparse
import json
import pathlib
import sys


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def validate(args):
    failures = []
    graph = load_json(args.graph)
    advisories = load_json(args.advisories)
    policy = load_json(args.policy_result)
    if not graph.get("lockfiles_found"):
        failures.append("No lockfiles were discovered; dependency coverage cannot be asserted")
    if not graph.get("graph_complete"):
        failures.append("Dependency graph is incomplete or contains inventory-only formats")
    if graph.get("errors"):
        failures.append("Dependency graph contains parser errors")
    if policy.get("passed") is not True:
        failures.append("Mandatory CVE policy did not pass")
    if policy.get("source_errors"):
        failures.append("Mandatory advisory-source freshness metadata is invalid or incomplete")
    if int(args.osv_exit_code) not in (0, 1):
        failures.append(f"OSV-Scanner execution failed with exit code {args.osv_exit_code}")
    rustsec_exit_code = int(getattr(args, "rustsec_exit_code", 0))
    if rustsec_exit_code not in (0, 1):
        failures.append(f"cargo-audit execution failed with exit code {rustsec_exit_code}")
    if not isinstance(advisories.get("matches"), list):
        failures.append("Normalized advisory result is missing its matches array")

    sbom_sets = []
    for label, path, kind in (
        ("SPDX", args.spdx, "spdx"),
        ("CycloneDX", args.cyclonedx, "cyclonedx"),
    ):
        document = load_json(path)
        if kind == "spdx":
            if document.get("spdxVersion") is None:
                failures.append("SPDX document has no spdxVersion")
            packages = document.get("packages") or []
            identities = {(p.get("name"), p.get("versionInfo")) for p in packages if p.get("name")}
        else:
            if document.get("bomFormat") != "CycloneDX":
                failures.append("CycloneDX document has an invalid bomFormat")
            packages = document.get("components") or []
            identities = {(p.get("name"), p.get("version")) for p in packages if p.get("name")}
        if not identities:
            failures.append(f"{label} SBOM contains no identifiable packages")
        sbom_sets.append((label, identities))

    if len(sbom_sets) == 2:
        left = sbom_sets[0][1]
        right = sbom_sets[1][1]
        if not (left & right):
            failures.append("SPDX and CycloneDX SBOMs have no package identities in common")

    return {
        "schema_version": "1.0",
        "status": "failed" if failures else "passed",
        "required_checks": {
            "dependency_graph": "failed" if not graph.get("graph_complete") else "passed",
            "cve_policy": "passed" if policy.get("passed") is True else "failed",
            "osv_scan": "passed" if int(args.osv_exit_code) in (0, 1) else "failed",
            "rustsec_scan": "passed" if rustsec_exit_code in (0, 1) else "failed",
            "spdx_sbom": "validated",
            "cyclonedx_sbom": "validated",
            "sbom_consistency": "validated" if len(sbom_sets) == 2 and sbom_sets[0][1] & sbom_sets[1][1] else "failed",
        },
        "failures": failures,
        "advisory_match_count": len(advisories.get("matches", [])),
        "dependency_package_count": len(graph.get("packages", [])),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--graph", required=True)
    parser.add_argument("--advisories", required=True)
    parser.add_argument("--policy-result", required=True)
    parser.add_argument("--osv-exit-code", required=True, type=int)
    parser.add_argument("--rustsec-exit-code", required=True, type=int)
    parser.add_argument("--spdx", required=True)
    parser.add_argument("--cyclonedx", required=True)
    parser.add_argument("--output", default="assessment-gate.json")
    args = parser.parse_args()
    result = validate(args)
    pathlib.Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(f"assessment_gate={result['status']} failures={len(result['failures'])}")
    for failure in result["failures"]:
        print(f"BLOCKER: {failure}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
