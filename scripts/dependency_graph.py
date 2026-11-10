#!/usr/bin/env python3
"""Extract exact package versions and lockfile edges without installing or executing packages.
Supported: Cargo.lock, npm package-lock v2/v3, poetry.lock, uv.lock, Pipfile.lock.
Go go.sum is checksummed-version inventory only; it is not a dependency graph.
"""
import argparse, json, pathlib, re, sys, tomllib

def cargo(data):
    rows=data.get("package",[]); out=[]
    for p in rows:
        deps=[]; unresolved=[]
        for raw in p.get("dependencies",[]):
            m=re.match(r"^(.+?) ([^ ]+)(?: \\((.+)\\))?$",raw)
            if not m:
                unresolved.append(raw); continue
            name,ver,src=m.group(1),m.group(2),m.group(3)
            matches=[x for x in rows if x.get("name")==name and x.get("version")==ver and (src is None or x.get("source")==src)]
            if len(matches)==1: deps.append(matches[0]["name"]+"@"+matches[0]["version"])
            else: unresolved.append(raw)
        out.append(dict(ecosystem="crates.io",name=p["name"],version=p["version"],source=p.get("source","registry/local"),checksum=p.get("checksum"),dependencies=sorted(set(deps)),unresolved_dependencies=unresolved,graph_complete=not unresolved))
    return out

def npm(data):
    out=[]; packages=data.get("packages")
    if not isinstance(packages,dict): raise ValueError("package-lock v1 is not supported by native graph extraction; use OSV-Scanner")
    keys=set(packages)
    for loc,p in packages.items():
        if not loc or not isinstance(p,dict) or not p.get("version"): continue
        name=p.get("name")
        if not name:
            m=re.search(r"(?:^|/)node_modules/(.+)$",loc); name=m.group(1) if m else None
        if not name: continue
        deps=[]; unresolved=[]
        for dep in (p.get("dependencies") or {}):
            base=(loc+"/" if loc else "")+"node_modules/"+dep
            candidates=[k for k in keys if k==base or k.endswith("/"+base)]
            if candidates:
                candidate=sorted(candidates,key=len)[-1]; q=packages[candidate]
                if q.get("version"): deps.append((q.get("name") or dep)+"@"+q["version"])
                else: unresolved.append(dep)
            else: unresolved.append(dep)
        out.append(dict(ecosystem="npm",name=name,version=str(p["version"]),source=loc or ".",integrity=p.get("integrity"),dependencies=sorted(set(deps)),unresolved_dependencies=unresolved,graph_complete=not unresolved))
    return out

def python_toml(data,kind):
    out=[]
    for p in data.get("package",[]):
        if not isinstance(p,dict) or not p.get("name") or not p.get("version"): continue
        raw=p.get("dependencies",{}); deps=list(raw.keys()) if isinstance(raw,dict) else [x.get("name") for x in raw if isinstance(x,dict) and x.get("name")] if isinstance(raw,list) else []
        out.append(dict(ecosystem="PyPI",name=p["name"],version=str(p["version"]),source=kind,dependencies=sorted(set(str(x) for x in deps)),graph_complete=False))
    return out

def pipfile(data):
    out=[]
    for group in ("default","develop"):
        for name,p in (data.get(group) or {}).items():
            if isinstance(p,dict) and p.get("version"): out.append(dict(ecosystem="PyPI",name=name,version=str(p["version"]).lstrip("="),source="Pipfile.lock",dependencies=[],graph_complete=False))
    return out

def go_sum(path):
    out=[]
    for line in path.read_text(errors="replace").splitlines():
        parts=line.split()
        if len(parts)<3 or parts[1].endswith("/go.mod"): continue
        out.append(dict(ecosystem="Go",name=parts[0],version=parts[1],source="go.sum",checksum=parts[2],dependencies=[],graph_complete=False))
    return out

def extract(path):
    n=path.name
    if n=="Cargo.lock": return cargo(tomllib.loads(path.read_text()))
    if n in ("package-lock.json","npm-shrinkwrap.json"): return npm(json.loads(path.read_text()))
    if n in ("poetry.lock","uv.lock"): return python_toml(tomllib.loads(path.read_text()),n)
    if n=="Pipfile.lock": return pipfile(json.loads(path.read_text()))
    if n=="go.sum": return go_sum(path)
    return []

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("root",type=pathlib.Path); ap.add_argument("--output",type=pathlib.Path,default=pathlib.Path("dependency-graph.json")); a=ap.parse_args()
    root=a.root.resolve(); found=[]; seen=set(); errors=[]; files=[]
    names={"Cargo.lock","package-lock.json","npm-shrinkwrap.json","poetry.lock","uv.lock","Pipfile.lock","go.sum"}
    for p in root.rglob("*"):
        if any(x in {".git","node_modules","target",".venv","vendor"} for x in p.parts): continue
        if p.is_file() and p.name in names: files.append(p)
    for p in sorted(files):
        try:
            for row in extract(p):
                row["lockfile"]=str(p.relative_to(root)); key=(row["ecosystem"],row["name"],row["version"],row["lockfile"])
                if key not in seen: found.append(row); seen.add(key)
        except Exception as e: errors.append({"lockfile":str(p.relative_to(root)),"error":str(e)})
    complete=bool(files) and not errors and all(x.get("graph_complete",True) for x in found)
    result={"schema_version":"1.0","target":str(root),"lockfiles_found":len(files),"packages":found,"package_count":len(found),"graph_complete":complete,"limitations":["Lockfiles describe selected platform/features only.","Pipfile.lock and go.sum do not encode a complete dependency edge graph.","Private registries, conditional dependencies and omitted lockfiles may reduce coverage.","No package is installed and no project code is executed."],"errors":errors}
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(f"lockfiles={len(files)} packages={len(found)} graph_complete={complete} errors={len(errors)}")
    return 1 if errors else 0
if __name__=="__main__": sys.exit(main())
