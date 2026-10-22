const API = location.origin.startsWith("http") && location.port === "5000" ? "" : "http://localhost:5000";
let alerts = [], selected = null;
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const post = (url, body) => fetch(API + url, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body || {})}).then(r => r.json());

async function load() {
  const d = await fetch(API + "/api/alerts").then(r => r.json());
  alerts = d.alerts;
  $("mode").textContent = d.llm_enabled ? "🤖 LLM agent (Claude)" : "📋 Offline playbook mode";
  $("blocklist").textContent = d.blocklist.length ? d.blocklist.join(", ") : "none";
  const n = s => alerts.filter(a => a.severity === s).length;
  $("stats").innerHTML = [["Total Logs", d.total_logs], ["Alerts", alerts.length], ["Critical", n("Critical")],
    ["High", n("High")], ["Medium", n("Medium")], ["Contained", alerts.filter(a => a.status === "contained").length]]
    .map(([k, v]) => `<div class="stat"><b>${v}</b><span>${k}</span></div>`).join("");
  $("alerts").innerHTML = alerts.map(a => `<tr data-id="${a.id}" class="${a.id === selected ? "sel" : ""}">
    <td>${a.id}</td><td><span class="sev ${a.severity}">${a.severity}</span></td><td>${esc(a.rule)}</td>
    <td>${esc(a.src_ip)}</td><td>${a.status}</td></tr>`).join("");
  document.querySelectorAll("#alerts tr").forEach(tr => tr.onclick = () => { selected = tr.dataset.id; load(); });
  renderDetail();
}

function renderDetail() {
  const a = alerts.find(x => x.id === selected);
  if (!a) return;
  const steps = (a.steps || []).map(s => `<div class="step"><b>🔧 ${s.tool}</b><br>${esc(JSON.stringify(s.result))}</div>`).join("");
  $("detail").innerHTML = `<h2>${a.id} — ${esc(a.rule)}</h2>
    <p><span class="sev ${a.severity}">${a.severity}</span> &nbsp; ${esc(a.mitre)}</p>
    <p>${esc(a.description)}<br><span class="muted">IP: ${esc(a.src_ip)} · User: ${esc(a.user)}</span></p>
    <details><summary class="muted">Evidence (${a.evidence.length})</summary><pre>${esc(JSON.stringify(a.evidence, null, 1))}</pre></details>
    <p><button id="inv">🔍 Investigate with Agent</button>
    <button id="blk" class="danger" ${a.status === "contained" ? "disabled" : ""}>⛔ Approve: Block IP</button></p>
    ${steps}${a.report ? `<pre>${esc(a.report)}</pre>` : ""}`;
  $("inv").onclick = async () => { $("inv").textContent = "Investigating..."; $("inv").disabled = true; await post("/api/investigate/" + a.id); load(); };
  $("blk").onclick = async () => { await post("/api/block", {ip: a.src_ip}); load(); };
}

$("gen").onclick = async () => { selected = null; $("detail").innerHTML = "<h2>Investigation</h2><p class='muted'>Select an alert.</p>"; await post("/api/generate"); load(); };
$("file").onchange = async e => {
  try { await post("/api/upload", JSON.parse(await e.target.files[0].text())); load(); }
  catch { alert("Invalid JSON file"); }
};
load();
