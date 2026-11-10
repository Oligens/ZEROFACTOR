#!/usr/bin/env python3
"""Fetch OSV database freshness from the upstream snapshot's HTTPS Last-Modified header."""
import argparse
import datetime as dt
import email.utils
import json
import pathlib
import urllib.parse
import urllib.request


DEFAULT_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
ALLOWED_HOST = "osv-vulnerabilities.storage.googleapis.com"


def fetch_metadata(url=DEFAULT_URL, timeout=20):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST:
        raise ValueError("OSV metadata URL must use the approved HTTPS upstream host")
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "ZEROFACTOR-metadata/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        final = urllib.parse.urlparse(response.geturl())
        if response.status != 200 or final.scheme != "https" or final.hostname != ALLOWED_HOST:
            raise ValueError("Unexpected response or redirect while fetching OSV metadata")
        last_modified = response.headers.get("Last-Modified")
        if not last_modified:
            raise ValueError("Upstream OSV snapshot did not provide Last-Modified")
        updated = email.utils.parsedate_to_datetime(last_modified)
        if updated is None or updated.tzinfo is None:
            raise ValueError("Upstream OSV Last-Modified header is invalid")
        return {
            "name": "OSV",
            "last_updated": updated.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "metadata_url": url,
            "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "metadata_method": "HTTPS HEAD Last-Modified from upstream snapshot"
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output", default="source-metadata.json")
    args = parser.parse_args()
    source = fetch_metadata(args.url)
    pathlib.Path(args.output).write_text(json.dumps({"sources": [source]}, indent=2) + "\n")
    print(f"OSV database last_updated={source['last_updated']} metadata_source={source['metadata_url']}")


if __name__ == "__main__":
    main()
