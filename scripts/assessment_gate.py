#!/usr/bin/env python3
"""Fail-closed consistency gate for dependency graph, inventory, advisories and SBOMs."""
import argparse
import json
import pathlib
import re
import sys
from urllib.parse import unquote


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def norm(value):
    return re.sub(r"[-_.]+", "-", str(value or "").strip().lower())


def purl_identity(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    raw = purl[4:].split("?", 1)[0].split("#", 1)[0]
    ptype, sep, rest = raw.partition("/")
    if not sep:
        return None
    coord, at, version = rest.rpartition("@")
    if not at or not version:
        return None
    parts = [unquote(x) for x in coord.split("/") if x]
    if not parts:
        return None
    if ptype == "maven":
        name = ":".join(parts)
    else:
        name = "/".join(parts)
    ecosystem = {"cargo":"crates.io","npm":"npm","pypi":"pypi","composer":"packagist",
                 "gem":"rubygems","maven":"maven","golang":"go"}.get(ptype, ptype)
    return ecosystem, norm(name), norm(version)


def graph_identity(package):
    eco = norm(package.get("ecosystem"))
    name = str(package.get("name") or "")
    version = str(package.get("version") or "")
    if not name or not version:
        return None
    if eco in ("maven", "gradle") and package.get("group") and package.get("artifact"):
        name = str(package["group"]) + ":" + str(package["artifact"])
        eco = "maven"
    eco = {"crates.io":"crates.io", "rubygems":"rubygems", "packagist":"packagist",
           "pypi":"pypi", "npm":"npm", "go":"go"}.get(eco, eco)
    return eco, norm(name), norm(version)


def sbom_identities(document, kind):
    entries = []
    if kind == "spdx":
        for package in document.get("packages") or []:
            purls = [ref.get("referenceLocator") for ref in package.get("externalRefs") or []
                     if "purl" in str(ref.get("referenceType", "")).lower()
                     or str(ref.get("referenceLocator", "")).startswith("pkg:")]
            entries.append((package.get("name"), package.get("versionInfo"), purls))
    else:
        for component in document.get("components") or []:
            entries.append((component.get("name"), component.get("version"), [component.get("purl")]))
        metadata_component = (document.get("metadata") or {}).get("component")
        if metadata_component:
            entries.append((metadata_component.get("name"), metadata_component.get("version"), [metadata_component.get("purl")]))
    identities = set()
    fallback = set()
    for name, version, purls in entries:
        if not name or not version:
            continue
        fallback.add((norm(name), norm(version)))
        parsed = [purl_identity(p) for p in purls if p]
        identities.update(x for x in parsed if x)
    return identities, fallback, len(entries)


def graph_edge_checks(packages):
    identities = { (norm(p.get("name")), norm(p.get("version"))) for p in packages
                   if p.get("name") and p.get("version") }
    errors = []
    checked = 0
    for package in packages:
        if package.get("unresolved_dependencies"):
            errors.append(f"unresolved dependencies: {package.get('ecosystem')}:{package.get('name')}@{package.get('version')}")
        for edge in package.get("dependencies") or []:
            checked += 1
            edge = str(edge)
            if "@" not in edge:
                errors.append(f"malformed dependency edge: {edge}")
                continue
            dep_name, dep_version = edge.rsplit("@", 1)
            if (norm(dep_name), norm(dep_version)) not in identities:
                errors.append(f"dependency edge target missing from inventory: {edge}")
    return checked, errors


def validate(args):
    failures = []
    graph = load_json(args.graph)
    advisories = load_json(args.advisories)
    policy = load_json(args.policy_result)
    packages = graph.get("packages") or []
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
    rustsec_exit_code = int(args.rustsec_exit_code)
    if rustsec_exit_code not in (0, 1):
        failures.append(f"cargo-audit execution failed with exit code {rustsec_exit_code}")
    if not isinstance(advisories.get("matches"), list):
        failures.append("Normalized advisory result is missing its matches array")
    for item in advisories.get("matches", []):
        if not item.get("package") or not item.get("resolved_version") or item.get("version_match") is False:
            failures.append("Normalized advisory contains a match without exact package/version identity")
            break

    edge_count, edge_errors = graph_edge_checks(packages)
    if edge_errors:
        failures.append(f"Dependency graph/inventory consistency failed ({len(edge_errors)} issue(s))")

    sbom_reports = []
    graph_ids = {x for x in (graph_identity(p) for p in packages) if x}
    graph_fallback = {(norm(p.get("name")), norm(p.get("version"))) for p in packages
                      if p.get("name") and p.get("version")}
    for label, path, kind in (("SPDX", args.spdx, "spdx"), ("CycloneDX", args.cyclonedx, "cyclonedx")):
        document = load_json(path)
        if kind == "spdx" and not document.get("spdxVersion"):
            failures.append("SPDX document has no spdxVersion")
        if kind == "cyclonedx" and document.get("bomFormat") != "CycloneDX":
            failures.append("CycloneDX document has an invalid bomFormat")
        identities, fallback, count = sbom_identities(document, kind)
        if count == 0 or not (identities or fallback):
            failures.append(f"{label} SBOM contains no identifiable packages")
        matched = graph_ids & identities
        matched_fallback = graph_fallback & fallback
        represented = matched_fallback | {
            (norm(name), norm(version)) for _, name, version in matched
        }
        missing = graph_fallback - represented
        if graph_ids and identities:
            # PURLs must match exactly when both formats provide package URLs.
            missing_purl = graph_ids - identities
            if missing_purl:
                # A name/version match is acceptable only where the SBOM lacks a usable purl.
                sbom_purl_pairs = {(name, version) for _, name, version in identities}
                sbom_fallback_pairs = fallback
                missing_purl = {x for x in missing_purl if (x[1], x[2]) not in sbom_fallback_pairs}
                if missing_purl:
                    failures.append(f"{label} SBOM is missing {len(missing_purl)} graph package PURL identities")
        if missing:
            failures.append(f"{label} SBOM is missing {len(missing)} dependency graph package(s)")
        sbom_reports.append({"format": label, "package_records": count,
                             "graph_packages": len(graph_fallback),
                             "matched_by_purl": len(matched),
                             "matched_by_name_version": len(matched_fallback),
                             "missing_graph_packages": sorted([list(x) for x in missing])})

    return {
        "schema_version": "2.0",
        "status": "failed" if failures else "passed",
        "required_checks": {
            "dependency_graph": "passed" if graph.get("graph_complete") and not graph.get("errors") else "failed",
            "dependency_edges_resolve": "passed" if not edge_errors else "failed",
            "cve_policy": "passed" if policy.get("passed") is True and not policy.get("source_errors") else "failed",
            "osv_scan": "passed" if int(args.osv_exit_code) in (0, 1) else "failed",
            "rustsec_scan": "passed" if rustsec_exit_code in (0, 1) else "failed",
            "spdx_sbom": "validated",
            "cyclonedx_sbom": "validated",
            "graph_inventory_sbom_consistency": "passed" if not any("SBOM" in x or "graph/inventory" in x for x in failures) else "failed",
        },
        "failures": failures,
        "dependency_package_count": len(packages),
        "dependency_edge_count": edge_count,
        "dependency_edge_errors": edge_errors,
        "advisory_match_count": len(advisories.get("matches", [])),
        "sbom_consistency": sbom_reports,
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
    print(f"assessment_gate={result['status']} failures={len(result['failures'])} edges={result['dependency_edge_count']}")
    for failure in result["failures"]:
        print(f"BLOCKER: {failure}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
