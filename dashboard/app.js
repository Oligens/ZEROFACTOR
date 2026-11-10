const $=id=>document.getElementById(id);
const safe=v=>String(v??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const KEY="zerofactor.local.workspace.v1";
let state=load(),current=null;
function load(){try{const x=JSON.parse(localStorage.getItem(KEY));if(x&&Array.isArray(x.projects))return x;}catch{}return {projects:[{id:crypto.randomUUID(),name:"Default project",assessments:[]}],activeRole:"owner"};}
function save(){localStorage.setItem(KEY,JSON.stringify(state));}
function project(){return state.projects.find(p=>p.id===$("projectSelect").value)||state.projects[0];}
function canWrite(){return state.activeRole==="owner"||state.activeRole==="analyst";}
function canAdmin(){return state.activeRole==="owner";}
function renderWorkspace(preferred){
 if(!state.projects.length)state.projects.push({id:crypto.randomUUID(),name:"Default project",assessments:[]});
 const selected=preferred||$("projectSelect").value;
 $("projectSelect").innerHTML=state.projects.map(p=>'<option value="'+safe(p.id)+'">'+safe(p.name)+'</option>').join("");
 $("projectSelect").value=state.projects.some(p=>p.id===selected)?selected:state.projects[0].id;$("roleSelect").value=state.activeRole;
 $("createProject").disabled=!canAdmin();$("deleteProject").disabled=!canAdmin()||state.projects.length<2;renderHistory();
}
function renderHistory(){const p=project();if(!p){$("historyRows").textContent="No project selected.";return;}
 $("historyRows").innerHTML=(p.assessments||[]).map((a,i)=>'<button class="history-item" data-index="'+i+'"><b>'+safe(a.label)+'</b><span>'+safe(a.createdAt)+' · '+safe(a.findings)+' findings</span></button>').join("")||"No assessments yet.";
 $("historyRows").querySelectorAll("button").forEach(b=>b.addEventListener("click",()=>{const a=project().assessments[Number(b.dataset.index)];if(a){current=a.report;render(current);$("notice").textContent="History: "+a.label;}}));
}
$("projectSelect").addEventListener("change",e=>{current=null;renderWorkspace(e.target.value);$("notice").textContent="Project selected: "+project().name;});
$("roleSelect").addEventListener("change",e=>{state.activeRole=e.target.value;save();renderWorkspace();$("notice").textContent="Local profile changed to "+state.activeRole+". This is not authenticated authorization.";});
$("createProject").addEventListener("click",()=>{if(!canAdmin())return;const name=prompt("Project name");if(!name?.trim())return;const id=crypto.randomUUID();state.projects.push({id,name:name.trim(),assessments:[]});save();renderWorkspace(id);$("notice").textContent="Project created locally.";});
$("deleteProject").addEventListener("click",()=>{if(!canAdmin()||state.projects.length<2)return;const p=project();if(!confirm("Delete project and its local assessment history?"))return;state.projects=state.projects.filter(x=>x.id!==p.id);save();current=null;renderWorkspace();$("notice").textContent="Local project deleted.";});
$("reportFile").addEventListener("change",async e=>{const f=e.target.files?.[0];if(!f)return;if(!canWrite()){$("notice").textContent="Viewer profile: import disabled.";return;}try{const d=JSON.parse(await f.text());current=d;render(d);const p=project();p.assessments.unshift({label:f.name,createdAt:new Date().toISOString(),findings:(d.findings||[]).length,report:d});save();renderHistory();$("notice").textContent="Loaded and saved locally to "+p.name+": "+(d.target||f.name);}catch(err){$("notice").textContent="Invalid JSON: "+err.message;}finally{e.target.value="";}});
function render(d){
 const fs=Array.isArray(d.findings)?d.findings:[],ds=Array.isArray(d.dependencies)?d.dependencies:[],cs=Array.isArray(d.checks)?d.checks:[];
 $("files").textContent=d.files_examined??"—";$("findings").textContent=fs.length;$("deps").textContent=ds.length;
 $("coverage").textContent=Number.isFinite(d.coverage)?(d.coverage*100).toFixed(1)+"%":"—";$("zfi").textContent=d.zfi==null?"N/A":Number(d.zfi).toFixed(1);
 const lv=["critical","high","medium","low","info"],counts=Object.fromEntries(lv.map(s=>[s,fs.filter(f=>String(f.severity).toLowerCase()===s).length])),mx=Math.max(1,...Object.values(counts));
 $("severity").className="bars";$("severity").innerHTML=lv.map(s=>'<div class="barline"><span>'+s+'</span><div class="track"><div class="fill" style="width:'+(counts[s]/mx*100)+'%"></div></div><b>'+counts[s]+'</b></div>').join("");
 $("checks").className="check-list";$("checks").innerHTML=cs.map(c=>'<div class="check"><span>'+safe(c.description||c.id)+'</span><span class="tag">'+(c.tested?"TESTED":"NOT TESTED")+'</span></div>').join("")||"No check data";
 $("findingRows").innerHTML=fs.map(f=>'<tr><td class="severity '+safe(String(f.severity).toLowerCase())+'">'+safe(f.severity)+'</td><td>'+safe(f.title)+'</td><td>'+safe(f.status)+'</td><td>'+safe(f.path)+(f.line?":"+safe(f.line):"")+'</td></tr>').join("")||'<tr><td colspan="4">No findings recorded</td></tr>';
 $("depRows").innerHTML=ds.map(x=>'<tr><td>'+safe(x.ecosystem)+'</td><td>'+safe(x.name)+'</td><td>'+safe(x.version_spec||x.version)+'</td><td>'+safe(x.manifest||x.lockfile)+'</td></tr>').join("")||'<tr><td colspan="4">No dependencies parsed</td></tr>';
 $("warnings").innerHTML=(Array.isArray(d.warnings)?d.warnings:[]).map(w=>'<li>'+safe(w)+'</li>').join("")||"<li>No warnings recorded.</li>";
}
renderWorkspace();