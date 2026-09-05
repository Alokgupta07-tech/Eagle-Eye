"use strict";
/* SENTINEL report view — pure client-rendered from /v1/reports/{run_id}. */
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function j(url, opts) { const r = await fetch(url, opts); return r.json(); }

function card(v, l, cls = "") { return `<div class="card ${cls}"><div class="v">${v}</div><div class="l">${l}</div></div>`; }
function pill(x) { return `<span class="pill ${String(x).toLowerCase()}">${esc(x ?? "—")}</span>`; }

function tileColor(c) {
  if (c.successful > 0) return "t-red";
  if (c.inconclusive > 0 || c.blocked > 0) return "t-amber";
  return "t-green"; }

function render(rep) {
  const s = rep.summary;
  const res = s.resistance_rate == null ? "—" : (s.resistance_rate * 100).toFixed(1) + "%";
  $("#root").innerHTML = `
  <div class="cards">
    ${card(s.total, "attacks executed")}
    ${card(res, "resistance rate", "cyan")}
    ${card(s.resisted, "resisted")}
    ${card(s.successful, "compromised", "bad")}
    ${card(s.blocked_at_gate, "blocked @ gate", "warn")}
    ${card(s.redacted, "redacted", "warn")}
    ${card(s.inconclusive, "inconclusive", "warn")}
    ${card("v" + (s.baseline_version ?? "?"), "baseline")}
  </div>

  ${rep.capabilities_warning ? `<div class="warnbanner">⚠ ${esc(rep.capabilities_warning)}</div>` : ""}

  <div class="panel">
    <div class="ptitle">▣ CATEGORY HEAT GRID <span class="tick">// target: ${esc(rep.target.name)} · run ${esc(rep.run.id.slice(0, 8))} · ${esc(rep.run.started_at)}</span></div>
    <div class="grid">
      ${rep.by_category.map(c => `
      <div class="tile ${tileColor(c)}">
        <h4>${esc(c.category)}</h4>
        <div style="margin-bottom:6px"><span class="pill review">${esc(c.owasp_llm || "LLM—")}</span>
        ${c.mitre_atlas ? `<span class="pill none" title="MITRE ATLAS">${esc(c.mitre_atlas.split(":")[0])}</span>` : ""}
        <span class="pill none" style="float:right">${esc(c.severity)}</span></div>
        <div class="nums">
          <span>total ${c.total} · resisted ${c.resisted} · gate-blocked ${c.blocked}</span>
          <span>compromised ${c.successful} · inconclusive ${c.inconclusive}</span>
          <span>peak fused score ${Number(c.worst_score).toFixed(1)}</span>
        </div>
      </div>`).join("")}
    </div>
  </div>

  ${s.suggested_remediations.length ? `
  <div class="panel">
    <div class="ptitle">▣ REMEDIATION PRIORITIES <span class="tick">// categories the target failed</span></div>
    <div class="pad"><table>
      <tr><th>category</th><th>severity</th><th>recommended fix</th></tr>
      ${s.suggested_remediations.map(r => `<tr><td>${esc(r.category)}</td>
        <td>${esc(r.severity)}</td><td>${esc(r.remediation)}</td></tr>`).join("")}
    </table></div>
  </div>` : ""}

  <div class="panel">
    <div class="ptitle">▣ EXECUTIONS <span class="tick">// one row per attack · every row sealed</span></div>
    <div class="pad" style="max-height:420px;overflow:auto"><table>
      <tr><th>category</th><th>mutation</th><th>band</th><th>fused</th><th>conf</th>
          <th>verdict</th><th>action</th><th>drift</th><th>ms</th><th>seq</th></tr>
      ${rep.executions.map(e => {
        const prov = rep.provenance.find(p => p.pattern_id === e.pattern_id) || {};
        return `<tr><td>${esc(prov.category || "—")}</td>
        <td>${esc(prov.mutation || "seed")}</td>
        <td>${pill(e.band)}</td><td>${Number(e.fused_score).toFixed(1)}</td>
        <td>${e.confidence}</td><td>${pill(e.verdict)}</td><td>${pill(e.action)}</td>
        <td>${e.drift_score ?? "—"}</td><td>${e.latency_ms}</td><td>#${e.audit_seq}</td></tr>`; }).join("")}
    </table></div>
  </div>

  <div class="panel">
    <div class="ptitle">▣ PROVENANCE <span class="tick">// every attack traceable · no blocklists</span></div>
    <div class="pad" style="max-height:200px;overflow:auto"><table>
      <tr><th>category</th><th>mutation</th><th>source repo</th><th>pinned sha</th></tr>
      ${[...new Map(rep.provenance.map(p => [p.pattern_id, p])).values()].map(p =>
        `<tr><td>${esc(p.category)}</td><td>${esc(p.mutation || "seed")}</td>
         <td>${esc(p.source_repo)}</td><td>${esc((p.source_sha || "").slice(0, 12))}…</td></tr>`).join("")}
    </table></div>
  </div>

  <div class="panel">
    <div class="ptitle">▣ LIMITATIONS <span class="tick">// declared, not hidden (P7)</span></div>
    <div class="pad">${rep.limitations.map(l => `<div class="ln dim" style="padding:3px 0">— ${esc(l)}</div>`).join("")}</div>
  </div>

  <div class="panel pad">
    <div class="ptitle" style="border:none;margin-bottom:8px">▣ AUDIT CHAIN INTEGRITY</div>
    <button class="cyan" id="verifyBtn">▶ VERIFY HASH CHAIN</button>
    <div class="stamp" id="stamp">not yet verified</div>
  </div>`;

  $("#verifyBtn").onclick = async () => {
    const v = await j("/audit/verify?run_id=" + encodeURIComponent(rep.run.id));
    const st = $("#stamp");
    if (v.valid) { st.className = "stamp ok";
      st.textContent = `✔ CHAIN INTACT — ${v.checked} records verified (${v.run_records} in this run)`; }
    else { st.className = "stamp bad";
      st.textContent = `✖ TAMPER DETECTED — first bad record at seq ${v.first_bad_seq}`; } };
}

function barClass(rate) { return rate >= 0.8 ? "good" : rate >= 0.5 ? "mid" : "poor"; }

async function renderLeaderboard(cid, mountSelector) {
  const data = await j("/v1/reports/compare/" + encodeURIComponent(cid));
  if (data.error || !data.leaderboard) return;
  const html = `
  <div class="panel">
    <div class="ptitle">▣ LIVE VULNERABILITY LEADERBOARD <span class="tick">// same validated corpus, every target · comparison ${esc(cid)}</span></div>
    <div class="pad" style="padding:6px 12px">
      ${data.leaderboard.map((b, i) => {
        const rr = b.resistance_rate == null ? null : Math.round(b.resistance_rate * 100);
        return `
        <div class="lb-row">
          <div class="lb-name"><span class="rank">#${i + 1}</span>${esc(b.target_name || b.target_id)}
            <a href="/report.html?run_id=${b.run_id}" style="color:var(--cy)">[report]</a></div>
          <div class="lb-track"><div class="lb-fill ${barClass(b.resistance_rate ?? 0)}"
            style="width:${rr ?? 0}%"></div></div>
          <div class="lb-val">${rr == null ? "…" : rr + "%"}</div>
          <div class="lb-meta">resistance ${rr ?? "—"}% · gate-block ${Math.round((b.gate_block_rate || 0) * 100)}% ·
            compromised ${b.compromised}/${b.total} · status ${esc(b.status)}${b.top_failing_category
              ? " · weakest: " + esc(b.top_failing_category) : ""}</div>
        </div>`; }).join("")}
    </div>
  </div>`;
  const mount = document.querySelector(mountSelector);
  if (mount) mount.insertAdjacentHTML("afterbegin", html);
}

(async () => {
  const params = new URLSearchParams(location.search);
  const compare = params.get("compare");
  if (compare) {
    $("#loading").remove();
    await renderLeaderboard(compare, "#root");
    const again = setInterval(async () => {
      const data = await j("/v1/reports/compare/" + encodeURIComponent(compare));
      if (data.leaderboard && data.leaderboard.every(b => b.status === "done")) clearInterval(again);
      $("#root").innerHTML = ""; await renderLeaderboard(compare, "#root"); }, 5000);
    return;
  }
  let runId = params.get("run_id");
  const runs = (await j("/v1/runs")).runs || [];
  const sel = $("#verdict");
  sel.innerHTML = runs.map(r =>
    `<option value="${r.id}">${r.id.slice(0, 8)} · ${r.status} · total ${r.total}</option>`).join("");
  if (runs.length) { sel.onchange = () => { location.search = "?run_id=" + sel.value; }; }
  if (!runId) { const latest = (await j("/v1/runs/latest")).run;
    if (!latest) { $("#loading").innerHTML = "<div class='pad'>No runs yet. " +
      "Seed the corpus, then POST /v1/runs — or run scripts/demo_setup.py</div>"; return; }
    runId = latest.id; }
  sel.value = runId;
  const rep = await j("/v1/reports/" + runId);
  if (rep.error) { $("#loading").innerHTML = `<div class='pad'>${esc(rep.error)}</div>`; return; }
  $("#loading").remove();
  render(rep);
  if (rep.run.comparison_id) renderLeaderboard(rep.run.comparison_id, "#root");
})();
