#!/usr/bin/env python3
"""Extract lockfile package graphs without installing packages or executing project code.
Native edge reconstruction: Cargo.lock, npm package-lock v1-v3, Yarn classic v1, Poetry.lock and uv.lock.
Pipfile.lock and go.sum remain exact-version/checksum inventories only and are explicitly incomplete.
"""
import argparse,json,pathlib,re,sys,tomllib
import yaml

def row(eco,name,version,source,deps=None,unresolved=None,**extra):
    unresolved=unresolved or []
    return dict(ecosystem=eco,name=name,version=str(version),source=source,dependencies=deps or [],
        unresolved_dependencies=unresolved,graph_complete=not unresolved,**extra)

def version_tuple(value):
    m=re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?",str(value).strip())
    return tuple(int(x or 0) for x in m.groups()) if m else None

def version_satisfies(spec, locked):
    spec=str(spec or "").strip()
    actual=version_tuple(locked)
    if not spec or spec=="*":return True
    if actual is None:return False
    for clause in spec.split(","):
        clause=clause.strip()
        if not clause or clause=="*":continue
        clause=re.sub(r"^(>=|<=|==|!=|>|<|=|~>|~|\^)\s+",r"\1",clause)
        if clause.startswith("~>"):
            base=version_tuple(clause[2:])
            if base is None or actual<base:return False
            parts=clause[2:].strip().split(".")
            upper=(base[0],base[1]+1,0) if len(parts)>=3 else (base[0]+1,0,0)
            if actual>=upper:return False
        elif clause.startswith("^") or clause.startswith("~"):
            base=version_tuple(clause[1:])
            if base is None or actual<base:return False
            if clause.startswith("^"):
                if base[0]>0:upper=(base[0]+1,0,0)
                elif base[1]>0:upper=(0,base[1]+1,0)
                else:upper=(0,0,base[2]+1)
            else:upper=(base[0],base[1]+1,0)
            if actual>=upper:return False
        elif clause.startswith(">="):
            bound=version_tuple(clause[2:])
            if bound is None or actual<bound:return False
        elif clause.startswith("<="):
            bound=version_tuple(clause[2:])
            if bound is None or actual>bound:return False
        elif clause.startswith(">"):
            bound=version_tuple(clause[1:])
            if bound is None or actual<=bound:return False
        elif clause.startswith("<"):
            bound=version_tuple(clause[1:])
            if bound is None or actual>=bound:return False
        elif clause.startswith("==") or clause.startswith("="):
            bound=version_tuple(clause.lstrip("="))
            if bound is None or actual!=bound:return False
        elif clause.startswith("!="):
            bound=version_tuple(clause[2:])
            if bound is None or actual==bound:return False
        else:
            bound=version_tuple(clause)
            if bound is None or actual!=bound:return False
    return True

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
            if m:
                name,version,source=m.group(1),m.group(2),m.group(3)
                hits=[x for x in index.get(name.lower(),[]) if x.get("version")==version and (source is None or x.get("source")==source)]
            else:
                # Newer Cargo.lock versions may omit version/source when the name is unambiguous.
                name=raw.strip();hits=index.get(name.lower(),[])
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
                if version_satisfies(spec,locked):deps.append(hits[0]["name"]+"@"+locked)
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
                if version_satisfies(spec,locked):deps.append(hit["name"]+"@"+locked)
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

def composer(data):
    packages=(data.get("packages") or [])+(data.get("packages-dev") or [])
    index={}
    for p in packages:
        if isinstance(p,dict) and p.get("name") and p.get("version"):index.setdefault(p["name"].lower(),[]).append(p)
    out=[]
    for p in packages:
        if not isinstance(p,dict) or not p.get("name") or not p.get("version"):continue
        deps=[];unresolved=[]
        for name,constraint in (p.get("require") or {}).items():
            if name.startswith(("php","ext-","lib-")):continue
            hits=index.get(name.lower(),[])
            if len(hits)==1 and version_satisfies(constraint,hits[0]["version"]):deps.append(hits[0]["name"]+"@"+str(hits[0]["version"]))
            else:unresolved.append(name+" ("+str(constraint)+")")
        out.append(row("Packagist",p["name"],p["version"],"composer.lock",sorted(set(deps)),unresolved,dist=(p.get("dist") or {}).get("reference")))
    return out

def gemfile_lock(path):
    packages=[];current=None;in_specs=False
    for line in path.read_text(errors="replace").splitlines():
        if line.strip()=="specs:":in_specs=True;current=None;continue
        if line and not line.startswith("      ") and not line.startswith("    ") and line.strip() in ("PLATFORMS","DEPENDENCIES","BUNDLED WITH","GIT","PATH","GEM"):in_specs=False
        if not in_specs:continue
        match=re.match(r"^    ([^ ]+) \(([^)]+)\)$",line)
        if match:
            current={"name":match.group(1),"version":match.group(2),"dependencies":[]};packages.append(current);continue
        dep=re.match(r"^      ([^ ]+) \(([^)]+)\)$",line)
        if dep and current:current["dependencies"].append((dep.group(1),dep.group(2)))
    index={}
    for p in packages:index.setdefault(p["name"].lower(),[]).append(p)
    out=[]
    for p in packages:
        deps=[];unresolved=[]
        for name,constraint in p["dependencies"]:
            hits=index.get(name.lower(),[])
            if len(hits)==1 and version_satisfies(constraint,hits[0]["version"]):deps.append(hits[0]["name"]+"@"+hits[0]["version"])
            else:unresolved.append(name+" ("+constraint+")")
        out.append(row("RubyGems",p["name"],p["version"],"Gemfile.lock",sorted(set(deps)),unresolved))
    return out

def gradle_lock(path):
    out=[]
    for line in path.read_text(errors="replace").splitlines():
        value=line.split("#",1)[0].strip()
        if not value or "=" not in value:continue
        coordinate=value.split("=",1)[0].strip();parts=coordinate.split(":")
        if len(parts)>=3:out.append(row("Maven",parts[-2],parts[-1],"gradle.lockfile",[],["lockfile_records_versions_not_dependency_edges"],group=":".join(parts[:-2])))
    return out

def go_sum(path):
    out=[]
    for line in path.read_text(errors="replace").splitlines():
        parts=line.split()
        if len(parts)<3 or parts[1].endswith("/go.mod"):continue
        out.append(row("Go",parts[0],parts[1],"go.sum",[],["go.sum_contains_checksums_not_dependency_edges"],checksum=parts[2]))
    return out


def package_key(value):
    """Split pnpm/Yarn package locator into normalized name and exact version."""
    value=str(value).strip().strip("'\"")
    value=value.lstrip("/")
    if "@npm:" in value:value=value.replace("@npm:","@",1)
    value=re.sub(r"\([^)]*\)$","",value)
    if value.startswith("@"):
        parts=value.split("/")
        if len(parts)<2:return None,None
        scope=parts[0];rest="/".join(parts[1:])
        if "@" in rest:
            artifact,version=rest.rsplit("@",1)
            return scope+"/"+artifact,version
        return None,None
    if "@" in value:
        name,version=value.rsplit("@",1)
        return name,version
    parts=value.split("/")
    if len(parts)>=2 and re.match(r"^\d",parts[-1]):
        return "/".join(parts[:-1]),parts[-1]
    return None,None


def resolve_locator(name, spec, index):
    normalized=str(name).lower().replace("_","-")
    candidates=index.get(normalized,[])
    spec=str(spec or "").strip()
    if spec.startswith(("workspace:","link:","file:","portal:")):
        return None
    wanted=spec.split("(",1)[0].split("_",1)[0]
    exact=[]
    for item in candidates:
        version=str(item.get("version",""))
        if wanted and (version==wanted or version.startswith(wanted+"-")):
            exact.append(item)
        elif version_satisfies(spec,version):
            exact.append(item)
    return exact[0] if len(exact)==1 else None


def pnpm_lock(path):
    data=yaml.safe_load(path.read_text()) or {}
    lock_version=str(data.get("lockfileVersion",""))
    packages=data.get("packages") or {}
    snapshots=data.get("snapshots") or {}
    records={}
    for locator,meta in packages.items():
        name,version=package_key(locator)
        if not name or not version:continue
        records[(name,version)]={"name":name,"version":version,"meta":meta or {},"source":str(locator)}
    # pnpm v9 snapshots contain the resolved dependency edges; older locks keep them in packages.
    edge_data=snapshots if snapshots else packages
    index={}
    for item in records.values():index.setdefault(item["name"].lower().replace("_","-"),[]).append(item)
    out=[]
    for key,item in records.items():
        meta=edge_data.get(item["source"],item["meta"]) or {}
        deps=[];unresolved=[]
        for section in ("dependencies","optionalDependencies"):
            for dep,spec in (meta.get(section) or {}).items():
                target=resolve_locator(dep,spec,index)
                if target:deps.append(target["name"]+"@"+target["version"])
                else:unresolved.append(str(dep)+" ("+str(spec)+")")
        out.append(row("npm",item["name"],item["version"],"pnpm-lock.yaml:"+item["source"],sorted(set(deps)),unresolved,
                       lockfile_version=lock_version))
    # Importer declarations must resolve to a locked package or the graph is explicitly incomplete.
    for importer,meta in (data.get("importers") or {}).items():
        for section in ("dependencies","devDependencies","optionalDependencies"):
            for dep,entry in (meta.get(section) or {}).items():
                spec=entry.get("version") if isinstance(entry,dict) else entry
                target=resolve_locator(dep,spec,index)
                if not target:
                    out.append(row("npm",dep,str(spec or "unknown"),"pnpm-importer:"+str(importer),[],["importer_dependency_unresolved"]))
    if not out and lock_version:
        raise ValueError("pnpm lockfile has no package snapshots")
    return out


def yarn_berry(path):
    data=yaml.safe_load(path.read_text()) or {}
    if not isinstance(data,dict) or "__metadata" not in data:
        raise ValueError("not a Yarn Berry lockfile (missing __metadata)")
    records=[];selector_map={}
    for selector,meta in data.items():
        if selector=="__metadata" or not isinstance(meta,dict):continue
        resolution=str(meta.get("resolution",""))
        name,version=package_key(resolution)
        if not name:
            # The descriptor key may contain multiple selectors; use its first descriptor.
            first=str(selector).split(",")[0].strip().strip("'\"")
            name,version=package_key(first)
        if not name or not version:continue
        item={"name":name,"version":version,"meta":meta,"source":str(selector)}
        records.append(item)
        for descriptor in str(selector).split(","):
            selector_map[descriptor.strip().strip("'\"")]=item
    index={}
    for item in records:index.setdefault(item["name"].lower().replace("_","-"),[]).append(item)
    out=[]
    for item in records:
        deps=[];unresolved=[]
        for section in ("dependencies","optionalDependencies"):
            for dep,spec in (item["meta"].get(section) or {}).items():
                descriptor=str(dep)+"@"+str(spec)
                target=selector_map.get(descriptor)
                if target is None:target=resolve_locator(dep,spec,index)
                if target:deps.append(target["name"]+"@"+target["version"])
                else:unresolved.append(descriptor)
        out.append(row("npm",item["name"],item["version"],"yarn.lock:"+item["source"],sorted(set(deps)),unresolved,
                       resolution=item["meta"].get("resolution")))
    if not out:raise ValueError("Yarn Berry lockfile contains no package records")
    return out


def maven_tree(path):
    """Parse a pre-generated Maven dependency:tree text report; never execute Maven/project code."""
    out=[];stack=[]
    coordinate=re.compile(r"^([^:]+):([^:]+):([^:]+):([^:]+)(?::([^:]+))?$")
    for line in path.read_text(errors="replace").splitlines():
        value=re.sub(r"^\s*\[INFO\]\s?","",line).rstrip()
        if not value or value.startswith(("---","BUILD ","[WARNING]","[ERROR]")):continue
        match=re.match(r"^(?P<prefix>(?:\|  |   )*)(?:\+- |\\- )(?P<coord>.+)$",value)
        if match:
            depth=len(match.group("prefix"))//3+1;raw=match.group("coord").strip()
        else:
            # Maven's root coordinate is printed without a tree branch.
            if stack or not re.match(r"^[^ ]+:[^ ]+:[^ ]+:[^ ]+:[^ ]+$",value):continue
            depth=0;raw=value
        parts=raw.split(":")
        if len(parts)<4:continue
        group,artifact,packaging,version=parts[:4]
        scope=parts[4] if len(parts)>4 else "compile"
        if version in ("(absent)","(unknown)") or version.endswith(")") and "(" in version:continue
        name=group+":"+artifact
        item=row("Maven",name,version,"maven-dependency-tree.txt",[],[],group=group,artifact=artifact,packaging=packaging,scope=scope)
        out.append(item)
        if depth>0:
            while len(stack)>depth:stack.pop()
            if stack:stack[-1]["dependencies"].append(name+"@"+version)
            stack.append(item)
        else:stack=[item]
    if not out:raise ValueError("Maven dependency tree report has no resolved coordinates")
    return out


def gradle_report(path):
    """Parse a pre-generated Gradle dependencies report; unresolved/dynamic selectors remain incomplete."""
    out=[];stack=[]
    branch=re.compile(r"^(?P<prefix>(?:\|    |     )*)(?:\+--- |\\--- )(?P<coord>.+)$")
    coord_re=re.compile(r"^([^: ]+):([^: ]+):([^ ]+)(?: -> ([^ ]+))?(?:\\s+\\(.*\\))?$")
    for line in path.read_text(errors="replace").splitlines():
        value=line.rstrip()
        match=branch.match(value)
        if not match:continue
        depth=len(match.group("prefix"))//5+1;raw=match.group("coord").strip()
        if raw.startswith("project "):
            name=raw.split("project ",1)[1]
            item=row("Gradle",name,"project","gradle-dependencies.txt",[],["project_component_not_resolved_to_external_artifact"])
        else:
            parsed=coord_re.match(raw)
            if not parsed:continue
            group,artifact,requested,selected=parsed.groups()
            version=selected or requested
            unresolved=[]
            if version.endswith("+") or version.lower() in ("latest.release","latest.integration","unspecified"):
                unresolved.append("dynamic_or_unspecified_version:"+version)
            item=row("Gradle",group+":"+artifact,version,"gradle-dependencies.txt",[],unresolved,
                     group=group,artifact=artifact,requested_version=requested,selected_version=version)
        out.append(item)
        while len(stack)>=depth:stack.pop()
        if stack:stack[-1]["dependencies"].append(item["name"]+"@"+item["version"])
        stack.append(item)
    if not out:raise ValueError("Gradle dependencies report has no resolved coordinates")
    return out

def extract(path):
    n=path.name
    if n=="Cargo.lock":return cargo(tomllib.loads(path.read_text()))
    if n in ("package-lock.json","npm-shrinkwrap.json"):return npm(json.loads(path.read_text()))
    if n=="composer.lock":return composer(json.loads(path.read_text()))
    if n=="Gemfile.lock":return gemfile_lock(path)
    if n=="gradle.lockfile":return gradle_lock(path)
    if n=="pnpm-lock.yaml":return pnpm_lock(path)
    if n=="maven-dependency-tree.txt":return maven_tree(path)
    if n=="gradle-dependencies.txt":return gradle_report(path)
    if n=="yarn.lock":return yarn_classic(path)
    if n in ("poetry.lock","uv.lock"):return python_toml(tomllib.loads(path.read_text()),n)
    if n=="Pipfile.lock":return pipfile(json.loads(path.read_text()))
    if n=="go.sum":return go_sum(path)
    return []

def main():
    ap=argparse.ArgumentParser();ap.add_argument("root",type=pathlib.Path);ap.add_argument("--output",type=pathlib.Path,default=pathlib.Path("dependency-graph.json"));a=ap.parse_args()
    root=a.root.resolve();found=[];seen=set();errors=[];files=[]
    names={"Cargo.lock","package-lock.json","npm-shrinkwrap.json","yarn.lock","poetry.lock","uv.lock","Pipfile.lock","go.sum","composer.lock","Gemfile.lock","gradle.lockfile","pnpm-lock.yaml","maven-dependency-tree.txt","gradle-dependencies.txt"}
    for p in root.rglob("*"):
        if any(x in {".git","node_modules","target",".venv","vendor"} for x in p.parts):continue
        if p.is_file() and p.name in names:files.append(p)
    for p in sorted(files):
        try:
            if p.name=="gradle.lockfile" and any(x.name=="gradle-dependencies.txt" for x in files):
                continue
            for item in extract(p):
                item["lockfile"]=str(p.relative_to(root));key=(item["ecosystem"],item["name"],item["version"],item["lockfile"],item["source"])
                if key not in seen:found.append(item);seen.add(key)
        except Exception as e:errors.append({"lockfile":str(p.relative_to(root)),"error":str(e)})
    complete=bool(files) and not errors and bool(found) and all(x.get("graph_complete",False) for x in found)
    if any(p.name=="gradle.lockfile" for p in files) and not any(p.name=="gradle-dependencies.txt" for p in files):complete=False
    if any(p.name=="pom.xml" for p in root.rglob("pom.xml")) and not any(p.name=="maven-dependency-tree.txt" for p in files):complete=False
    result={"schema_version":"1.1","target":str(root),"lockfiles_found":len(files),"packages":found,"package_count":len(found),"graph_complete":complete,
        "coverage":{"native_edge_formats":["Cargo.lock","npm package-lock v1-v3","pnpm-lock.yaml","Yarn classic v1","Yarn Berry v2+","Maven dependency:tree text report","Gradle dependencies text report","Poetry.lock","uv.lock","composer.lock","Gemfile.lock"],"inventory_only_formats":["Pipfile.lock","go.sum","gradle.lockfile"]},
        "limitations":["Maven and Gradle dependency reports must be generated externally and supplied as maven-dependency-tree.txt or gradle-dependencies.txt; ZEROFACTOR never runs target build tools.","Python duplicate package versions or unresolved dependency names keep graph_complete false; dependency constraints are not fully evaluated against PEP 440.","Pipfile.lock and go.sum do not encode complete dependency edges.","Private registries, platform markers, optional dependencies and omitted lockfiles can reduce coverage.","No package is installed and no target project code is executed."],"errors":errors}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(f"lockfiles={len(files)} packages={len(found)} graph_complete={complete} errors={len(errors)}")
    return 1 if errors else 0
if __name__=="__main__":sys.exit(main())
