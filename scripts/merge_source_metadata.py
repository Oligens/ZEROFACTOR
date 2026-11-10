#!/usr/bin/env python3
"""Merge independently retrieved advisory-source freshness metadata."""
import argparse
import datetime as dt
import json
import pathlib


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("inputs",nargs="+")
    parser.add_argument("--output",default="source-metadata.json")
    args=parser.parse_args()
    sources=[]
    for filename in args.inputs:
        document=json.loads(pathlib.Path(filename).read_text())
        for source in document.get("sources",[]):
            name=source.get("name")
            timestamp=source.get("last_updated")
            if not name or not timestamp:
                raise ValueError("source metadata is missing name or last_updated")
            parsed=dt.datetime.fromisoformat(str(timestamp).replace("Z","+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("source metadata timestamp must include timezone: "+str(name))
            if any(existing["name"]==name for existing in sources):
                raise ValueError("duplicate advisory source metadata: "+str(name))
            sources.append(source)
    sources.sort(key=lambda item:item["name"])
    pathlib.Path(args.output).write_text(json.dumps({"sources":sources},indent=2)+"\n")
    print("advisory_sources="+",".join(item["name"] for item in sources))


if __name__=="__main__":main()
