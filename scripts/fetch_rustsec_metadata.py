#!/usr/bin/env python3
"""Fetch RustSec advisory database freshness from the official GitHub repository."""
import argparse
import datetime as dt
import json
import pathlib
import urllib.parse
import urllib.request

API_URL = "https://api.github.com/repos/RustSec/advisory-db/commits?per_page=1"
ALLOWED_HOST = "api.github.com"


def fetch_metadata(url=API_URL, timeout=20):
    parsed=urllib.parse.urlparse(url)
    if parsed.scheme!="https" or parsed.hostname!=ALLOWED_HOST or parsed.path!="/repos/RustSec/advisory-db/commits":
        raise ValueError("RustSec metadata URL must target the official advisory-db GitHub API endpoint")
    request=urllib.request.Request(url,headers={"Accept":"application/vnd.github+json","User-Agent":"ZEROFACTOR-metadata/1.0","X-GitHub-Api-Version":"2022-11-28"})
    with urllib.request.urlopen(request,timeout=timeout) as response:
        final=urllib.parse.urlparse(response.geturl())
        if response.status!=200 or final.scheme!="https" or final.hostname!=ALLOWED_HOST:
            raise ValueError("Unexpected response or redirect while fetching RustSec metadata")
        data=json.loads(response.read().decode("utf-8"))
    if not isinstance(data,list) or not data:
        raise ValueError("RustSec API returned no advisory database commit")
    commit=data[0]
    date=((commit.get("commit") or {}).get("committer") or {}).get("date")
    revision=commit.get("sha")
    if not date or not revision:
        raise ValueError("RustSec latest commit metadata is incomplete")
    updated=dt.datetime.fromisoformat(date.replace("Z","+00:00"))
    if updated.tzinfo is None:
        raise ValueError("RustSec commit timestamp has no timezone")
    return {"name":"RustSec","last_updated":updated.astimezone(dt.timezone.utc).isoformat().replace("+00:00","Z"),
            "metadata_url":API_URL,"retrieved_at":dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00","Z"),
            "metadata_method":"official RustSec advisory-db latest commit timestamp","revision":revision}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",default="rustsec-source-metadata.json")
    args=parser.parse_args()
    source=fetch_metadata()
    pathlib.Path(args.output).write_text(json.dumps({"sources":[source]},indent=2)+"\n")
    print(f"RustSec database last_updated={source['last_updated']} revision={source['revision']}")


if __name__=="__main__":main()
