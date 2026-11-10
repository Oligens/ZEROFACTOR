const $=id=>document.getElementById(id);
const safe=v=>String(v??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
$("reportFile").addEventListener("change",async e=>{const f=e.target.files?.[0];if(!f)return;try{const d=JSON.parse(await f.text());render(d);$("notice").textContent="Loaded: "+(d.target||f.name);}catch(err){$("notice").textContent="Invalid JSON: "+err.message;}});
function render(d){
 const fs=Array.isArray(d.findings)?d.findings:[],ds=Array.isArray(d.dependencies)?d.dependencies:[],cs=Array.isArray(d.checks)?d.checks:[];
 $("files").textContent=d.files_examined??"—";$("findings").textContent=fs.length;$("deps").textContent=ds.length;
 $("coverage").textContent=Number.isFinite(d.coverage)?(d.coverage*100).toFixed(1)+"%":"—";$("zfi").textContent=d.zfi==null?"N/A":Number(d.zfi).toFixed(1);
 const lv=["critical","high","medium","low","info"],counts=Object.fromEntries(lv.map(s=>[s,fs.filter(f=>String(f.severity).toLowerCase()===s).length])),mx=Math.max(1,...Object.values(counts));
 $("severity").className="bars";$("severity").innerHTML=lv.map(s=>'<div class="barline"><span>'+s+'</span><div class="track"><div class="fill" style="width:'+(counts[s]/mx*100)+'%"></div></div><b>'+counts[s]+'</b></div>').join("");
 $("checks").className="check-list";$("checks").innerHTML=cs.map(c=>'<div class="check"><span>'+safe(c.description||c.id)+'</span><span class="tag">'+(c.tested?"TESTED":"NOT TESTED")+'</span></div>').join("")||"No check data";
 $("findingRows").innerHTML=fs.map(f=>'<tr><td class="severity '+safe(String(f.severity).toLowerCase())+'">'+safe(f.severity)+'</td><td>'+safe(f.title)+'</td><td>'+safe(f.status)+'</td><td>'+safe(f.path)+(f.line?":"+safe(f.line):"")+'</td></tr>').join("")||'<tr><td colspan="4">No findings recorded</td></tr>';
 $("depRows").innerHTML=ds.map(x=>'<tr><td>'+safe(x.ecosystem)+'</td><td>'+safe(x.name)+'</td><td>'+safe(x.version_spec)+'</td><td>'+safe(x.manifest)+'</td></tr>').join("")||'<tr><td colspan="4">No dependencies parsed</td></tr>';
 $("warnings").innerHTML=(Array.isArray(d.warnings)?d.warnings:[]).map(w=>'<li>'+safe(w)+'</li>').join("")||"<li>No warnings recorded.</li>";
}
