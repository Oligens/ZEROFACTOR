#!/usr/bin/env python3
"""Extract lockfile package graphs without installing packages or executing project code.
Native edge reconstruction: Cargo.lock, npm package-lock v1-v3, Yarn classic v1, Poetry.lock and uv.lock.
Pipfile.lock and go.sum remain exact-version/checksum inventories only and are explicitly incomplete.
"""
import argparse,json,pathlib,re,sys,tomllib

def row(eco,name,version,source,deps=None,unresolved=None,**extra):
    unresolved=unresolved or []
    return dict(ecosystem=eco,name=name,version=str(version),source=source,dependencies=deps or [],
        unresolved_dependencies=unresolved,graph_complete=not unresolved,**extra)

def resolve_named(raw, packages, ecosystem):
    name=str(raw).strip()
    candidates=packages.get(name.lower().replace("_","-"),[])
    if len(candidates)==1:return candidates[0]
    return None

def cargo(data):
    packages=data.get("package",[]); index={}
    for p in packages:index.setdefault(p["name"].lower(),[]).append(p)
    out=[]
    for p in packages:
        deps=[];unresolved=[]
        for raw in p.get("dependencies",[]):
            m=re.match(r"^(.+?) ([^ ]+)(?: \((.+)\))?$",raw)
            if not m:unresolved.append(raw);continue
            name,version,source=m.group(1),m.group(2),m.group(3)
            hits=[x for x in index.get(name.lower(),[]) if x.get("version")==version and (source is None or x.get("source")==source)]
            if len(hits)==1:deps.append(hits[0]["name"]+"@"+hits[0]["version"])
            else:unresolved.append(raw)
        out.append(row("crates.io",p["name"],p["version"],p.get("source","registry/local"),sorted(set(deps)),unresolved,checksum=p.get("checksum")))
    return out

def npm(data):
    lock_version=int(data.get("lockfileVersion",1));out=[]
    if lock_version==1:
        def walk(tree,location):
            rows=[]
            for name,p in (tree or {}).items():
                if not isinstance(p,dict) or not p.get("version"):continue
                loc=(location+"/" if location else "")+"node_modules/"+name
                child_rows=walk(p.get("dependencies",{}),loc)
                child_by_path={x["source"]:x for x in child_rows}
                deps=[];unresolved=[]
                for dep in (p.get("dependencies") or {}):
                    direct_path=loc+"/node_modules/"+dep
                    hit=child_by_path.get(direct_path)
                    if hit:deps.append(hit["name"]+"@"+hit["version"])
                    else:unresolved.append(dep)
                rows.append(row("npm",name,p["version"],loc,sorted(set(deps)),unresolved,integrity=p.get("integrity")))
                rows.extend(child_rows)
            return rows
        return walk(data.get("dependencies",{}),"")
    packages=data.get("packages")
    if not isinstance(packages,dict):raise ValueError("unsupported npm lockfile structure")
    keys=set(packages)
    for loc,p in packages.items():
        if not loc or not isinstance(p,dict) or not p.get("version"):continue
        name=p.get("name")
        if not name:
            m=re.search(r"(?:^|/)node_modules/(.+)$",loc);name=m.group(1) if m else None
        if not name:continue
        deps=[];unresolved=[]
        for dep in (p.get("dependencies") or {}):
            parts=loc.split("/") if loc else []
            candidate=None
            while True:
                base="/".join(parts+["node_modules",dep])
                if base in keys:
                    candidate=base;break
                if not parts:break
                parts=parts[:-2] if len(parts)>=2 and parts[-2]=="node_modules" else parts[:-1]
            if candidate:
                q=packages[candidate]
                if q.get("version"):deps.append((q.get("name") or dep)+"@"+str(q["version"]))
                else:unresolved.append(dep)
            else:unresolved.append(dep)
        out.append(row("npm",name,p["version"],loc,sorted(set(deps)),unresolved,integrity=p.get("integrity")))
    return out

def yarn_classic(path):
    lines=path.read_text(errors="replace").splitlines();entries=[];current=None;in_deps=False
    def finish(item):
        if not item:return
        selectors=item["selectors"]
        for selector in selectors:
            split=selector.rfind("@")
            if split<=0:continue
            name=selector[:split].strip('"').strip("'")
            entries.append({"name":name,"version":item.get("version"),"dependencies":list(item["dependencies"].items()),"source":"yarn.lock"})
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            finish(current)
            raw=line.rstrip()[:-1]
            selectors=[(a or b or c).strip().strip('"').strip("'") for a,b,c in re.findall(r'"([^"]+)"|\'([^\']+)\'|([^,]+)',raw)]
            current={"selectors":selectors,"version":None,"dependencies":{}};in_deps=False;continue
        if current is None:continue
        stripped=line.strip()
        if stripped.startswith("version "):current["version"]=stripped.split(None,1)[1].strip('"\'')
        elif stripped=="dependencies:":in_deps=True
        elif len(line)-len(line.lstrip())<=2:in_deps=False
        elif in_deps:
            bits=stripped.split(None,1)
            if len(bits)==2:current["dependencies"][bits[0].strip('"\'')]=bits[1].strip('"\'')
    finish(current)
    versions={}
    for x in entries:versions.setdefault(x["name"].lower().replace("_","-"),[]).append(x)
    out=[]
    for x in entries:
        deps=[];unresolved=[]
        for dep,constraint in x["dependencies"]:
            hits=versions.get(dep.lower().replace("_","-"),[])
            if len(hits)==1 and hits[0].get("version"):
                locked=str(hits[0]["version"]);spec=str(constraint or "").strip()
                if spec in ("", "*", locked, "="+locked, "=="+locked):deps.append(hits[0]["name"]+"@"+locked)
                else:unresolved.append(dep+" ("+spec+"; locked "+locked+")")
            else:unresolved.append(dep)
        out.append(row("npm",x["name"],x["version"],x["source"],sorted(set(deps)),unresolved))
    return out

def python_toml(data,kind):
    raw=data.get("package",[]);index={}
    for p in raw:
        if isinstance(p,dict) and p.get("name") and p.get("version"):
            index.setdefault(str(p["name"]).lower().replace("_","-"),[]).append(p)
    out=[]
    for p in raw:
        if not isinstance(p,dict) or not p.get("name") or not p.get("version"):continue
        if "dependencies" not in p:
            deps=[];unresolved=["dependency_section_missing"]
            out.append(row("PyPI",p["name"],p["version"],kind,deps,unresolved));continue
        rawdeps=p.get("dependencies",{})
        pairs=list(rawdeps.items()) if isinstance(rawdeps,dict) else [(x.get("name"),x.get("version") or x.get("specifier") or "") for x in rawdeps if isinstance(x,dict) and x.get("name")] if isinstance(rawdeps,list) else []
        deps=[];unresolved=[]
        for dep,constraint in pairs:
            hit=resolve_named(dep,index,"PyPI")
            if hit:
                locked=str(hit["version"]);spec=str(constraint or "").strip()
                if spec in ("","*",locked,"="+locked,"=="+locked):deps.append(hit["name"]+"@"+locked)
                else:unresolved.append(str(dep)+" ("+spec+"; locked "+locked+")")
            else:unresolved.append(str(dep))
        out.append(row("PyPI",p["name"],p["version"],kind,sorted(set(deps)),unresolved))
    return out

def pipfile(data):
    out=[]
    for group in ("default","develop"):
        for name,p in (data.get(group) or {}).items():
            if isinstance(p,dict) and p.get("version"):out.append(row("PyPI",name,str(p["version"]).lstrip("="),"Pipfile.lock",[],["dependency_edges_not_encoded_by_lockfile"]))
    return out

def go_sum(path):
    out=[]
    for line in path.read_text(errors="replace").splitlines():
        parts=line.split()
        if len(parts)<3 or parts[1].endswith("/go.mod"):continue
        out.append(row("Go",parts[0],parts[1],"go.sum",[],["go.sum_contains_checksums_not_dependency_edges"],checksum=parts[2]))
    return out

def extract(path):
    n=path.name
    if n=="Cargo.lock":return cargo(tomllib.loads(path.read_text()))
    if n in ("package-lock.json","npm-shrinkwrap.json"):return npm(json.loads(path.read_text()))
    if n=="yarn.lock":return yarn_classic(path)
    if n in ("poetry.lock","uv.lock"):return python_toml(tomllib.loads(path.read_text()),n)
    if n=="Pipfile.lock":return pipfile(json.loads(path.read_text()))
    if n=="go.sum":return go_sum(path)
    return []

def main():
    ap=argparse.ArgumentParser();ap.add_argument("root",type=pathlib.Path);ap.add_argument("--output",type=pathlib.Path,default=pathlib.Path("dependency-graph.json"));a=ap.parse_args()
    root=a.root.resolve();found=[];seen=set();errors=[];files=[]
    names={"Cargo.lock","package-lock.json","npm-shrinkwrap.json","yarn.lock","poetry.lock","uv.lock","Pipfile.lock","go.sum"}
    for p in root.rglob("*"):
        if any(x in {".git","node_modules","target",".venv","vendor"} for x in p.parts):continue
        if p.is_file() and p.name in names:files.append(p)
    for p in sorted(files):
        try:
            for item in extract(p):
                item["lockfile"]=str(p.relative_to(root));key=(item["ecosystem"],item["name"],item["version"],item["lockfile"],item["source"])
                if key not in seen:found.append(item);seen.add(key)
        except Exception as e:errors.append({"lockfile":str(p.relative_to(root)),"error":str(e)})
    complete=bool(files) and not errors and bool(found) and all(x.get("graph_complete",False) for x in found)
    result={"schema_version":"1.1","target":str(root),"lockfiles_found":len(files),"packages":found,"package_count":len(found),"graph_complete":complete,
        "coverage":{"native_edge_formats":["Cargo.lock","npm package-lock v1-v3","Yarn classic v1","Poetry.lock","uv.lock"],"inventory_only_formats":["Pipfile.lock","go.sum"]},
        "limitations":["Yarn Berry, pnpm, Gradle, Maven, Composer, Bundler and other lockfile formats require their native ecosystem adapters and are not claimed complete here.","Python duplicate package versions or unresolved dependency names keep graph_complete false; dependency constraints are not fully evaluated against PEP 440.","Pipfile.lock and go.sum do not encode complete dependency edges.","Private registries, platform markers, optional dependencies and omitted lockfiles can reduce coverage.","No package is installed and no target project code is executed."],"errors":errors}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(f"lockfiles={len(files)} packages={len(found)} graph_complete={complete} errors={len(errors)}")
    return 1 if errors else 0
if __name__=="__main__":sys.exit(main())
