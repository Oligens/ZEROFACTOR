#!/usr/bin/env python3
"""Create and verify a deterministic SHA-256 evidence manifest for ZEROFACTOR runs."""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys

DEFAULT_ARTIFACTS = [
    "dependency-graph.json", "osv-results.json", "osv-scanner.exit-code",
    "rustsec-results.json", "rustsec-scanner.exit-code", "advisory-results.json",
    "osv-source-metadata.json", "rustsec-source-metadata.json", "source-metadata.json",
    "cve-policy-result.json", "sbom.spdx.json", "sbom.cdx.json", "assessment-gate.json",
]

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def build_manifest(paths, output):
    artifacts = []
    for raw in sorted(set(paths)):
        path = pathlib.Path(raw)
        if path.resolve() == pathlib.Path(output).resolve():
            continue
        if not path.is_file():
            raise FileNotFoundError(f"required evidence artifact missing: {raw}")
        artifacts.append({"path": path.as_posix(), "size_bytes": path.stat().st_size, "sha256": sha256(path)})
    if not artifacts:
        raise ValueError("no evidence artifacts supplied")
    payload = {
        "schema": "zerofactor-evidence-manifest/v1",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": os.getenv("GITHUB_REPOSITORY", "local"),
        "git_commit": os.getenv("GITHUB_SHA", "unknown"),
        "workflow": os.getenv("GITHUB_WORKFLOW", "local"),
        "workflow_run_id": os.getenv("GITHUB_RUN_ID", "local"),
        "workflow_run_attempt": os.getenv("GITHUB_RUN_ATTEMPT", "1"),
        "previous_manifest_sha256": os.getenv("ZEROFACTOR_PREVIOUS_EVIDENCE_HASH") or None,
        "hash_algorithm": "sha256",
        "artifacts": artifacts,
    }
    payload["chain_hash"] = hashlib.sha256(canonical(payload)).hexdigest()
    pathlib.Path(output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return payload

def verify_manifest(path):
    manifest = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if manifest.get("schema") != "zerofactor-evidence-manifest/v1" or manifest.get("hash_algorithm") != "sha256":
        raise ValueError("unsupported evidence manifest schema or hash algorithm")
    expected_chain = manifest.pop("chain_hash", None)
    actual_chain = hashlib.sha256(canonical(manifest)).hexdigest()
    if not expected_chain or expected_chain != actual_chain:
        raise ValueError("manifest chain_hash mismatch: manifest metadata was modified")
    errors = []
    for artifact in manifest.get("artifacts", []):
        target = pathlib.Path(artifact["path"])
        if not target.is_file():
            errors.append(f"missing artifact: {target}")
            continue
        if target.stat().st_size != artifact.get("size_bytes"):
            errors.append(f"size mismatch: {target}")
        if sha256(target) != artifact.get("sha256"):
            errors.append(f"SHA-256 mismatch: {target}")
    manifest["chain_hash"] = expected_chain
    return manifest, errors

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="evidence-manifest.json")
    parser.add_argument("--verify")
    parser.add_argument("artifacts", nargs="*")
    args = parser.parse_args()
    if args.verify:
        manifest, errors = verify_manifest(args.verify)
        print(f"evidence_manifest={'failed' if errors else 'verified'} artifacts={len(manifest.get('artifacts', []))} chain_hash={manifest.get('chain_hash')}")
        for error in errors:
            print("INTEGRITY_ERROR: " + error)
        return 1 if errors else 0
    payload = build_manifest(args.artifacts or DEFAULT_ARTIFACTS, args.output)
    print(f"evidence_manifest=created artifacts={len(payload['artifacts'])} chain_hash={payload['chain_hash']}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
