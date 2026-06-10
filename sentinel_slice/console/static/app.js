/*
  Sentinel Loop operator console — behavior.

  Self-contained, no framework, no external calls. Talks ONLY to this same
  localhost origin's /api endpoints, sending the admin token in the
  X-Admin-Token header (never a cookie — so a cross-origin page cannot forge
  authenticated requests). This is the control plane: it authors policy and
  reads receipts; it never touches payload content.
*/
"use strict";

let CATALOG = [];           // [{id, risk_class, requires_second_admin, ...}]
let EDITOR_ROLES = [];      // editable model: [{role, caps:Set, rate, paused:Set}]

const $ = (id) => document.getElementById(id);
const token = () => $("token").value.trim();

function msg(text, kind) {
  const el = $("msg");
  el.textContent = text || "";
  el.className = kind || "";
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  const tok = token();
  if (tok) opts.headers["X-Admin-Token"] = tok;
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  let data = null;
  try { data = await resp.json(); } catch (e) { data = null; }
  if (!resp.ok) {
    const detail = data && data.detail ? data.detail : resp.status;
    throw new Error(detail + " (HTTP " + resp.status + ")");
  }
  return data;
}

/* ---------- navigation ---------- */
document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".screen").forEach((s) => s.classList.remove("active"));
    $("screen-" + b.dataset.screen).classList.add("active");
    if (b.dataset.screen === "capabilities") loadCapabilities();
    if (b.dataset.screen === "menu") loadMenu();
    if (b.dataset.screen === "policies") loadPolicies();
    if (b.dataset.screen === "activity") loadActivity();
  });
});

$("useAuthor").addEventListener("click", () => { $("token").value = "dev-author-token"; $("whoami").textContent = "(author)"; });
$("useReviewer").addEventListener("click", () => { $("token").value = "dev-reviewer-token"; $("whoami").textContent = "(reviewer)"; });

/* ---------- capabilities ---------- */
async function loadCapabilities() {
  try {
    const data = await api("GET", "/api/capabilities");
    CATALOG = data.capabilities;
    const tb = $("capTable").querySelector("tbody");
    tb.innerHTML = "";
    for (const c of CATALOG) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td><code>${esc(c.id)}</code><br><span class="muted">${esc(c.name)}</span></td>` +
        `<td><span class="pill risk-${esc(c.risk_class)}">${esc(c.risk_class)}</span></td>` +
        `<td>${esc(c.side_effects)}</td>` +
        `<td>${c.recommended_max_rate === null ? "—" : c.recommended_max_rate}</td>` +
        `<td>${c.requires_second_admin ? "✔ required" : "—"}</td>` +
        `<td class="muted">${esc(c.description)}</td>`;
      tb.appendChild(tr);
    }
    msg("");
  } catch (e) { msg(e.message, "bad"); }
}

/* ---------- menu curation ---------- */
let TEMPLATES = [];

async function loadMenu() {
  try {
    TEMPLATES = (await api("GET", "/api/menu/templates")).templates;
    const sel = $("newBehavior");
    sel.innerHTML = TEMPLATES.map((t) =>
      `<option value="${esc(t.behavior)}">${esc(t.label)}</option>`).join("");
    showBehaviorSummary();

    const data = await api("GET", "/api/menu");
    const tb = $("menuTable").querySelector("tbody");
    tb.innerHTML = "";
    for (const c of data.capabilities) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td><code>${esc(c.id)}</code><br><span class="muted">${esc(c.name)}</span></td>` +
        `<td>${esc(c.behavior)}</td>` +
        `<td><span class="pill risk-${esc(c.risk_class)}">${esc(c.risk_class)}</span></td>` +
        `<td class="${c.enabled ? "ok" : "bad"}">${c.enabled ? "on" : "off"}</td>` +
        `<td></td>`;
      const actions = tr.lastChild;
      if (c.editable) {
        const toggle = document.createElement("button");
        toggle.className = "ghost";
        toggle.textContent = c.enabled ? "Turn off" : "Turn on";
        toggle.addEventListener("click", () => toggleCap(c.id, !c.enabled));
        const del = document.createElement("button");
        del.className = "ghost"; del.textContent = "Remove";
        del.addEventListener("click", () => removeCap(c.id));
        actions.appendChild(toggle);
        actions.appendChild(document.createTextNode(" "));
        actions.appendChild(del);
      } else {
        actions.innerHTML = '<span class="muted">built-in (locked)</span>';
      }
      tb.appendChild(tr);
    }
    msg("");
  } catch (e) { msg(e.message, "bad"); }
}

function showBehaviorSummary() {
  const t = TEMPLATES.find((x) => x.behavior === $("newBehavior").value);
  $("behaviorSummary").textContent = t ? t.summary : "";
  // Show the message-template box only for behaviors that need one.
  $("templateRow").style.display = (t && t.needs_template) ? "" : "none";
}
document.addEventListener("change", (e) => {
  if (e.target && e.target.id === "newBehavior") showBehaviorSummary();
});

$("createCap").addEventListener("click", async () => {
  const form = {
    behavior: $("newBehavior").value,
    capability_id: $("newId").value.trim(),
    name: $("newName").value.trim(),
    requires_user_confirmation: $("newConfirm").checked,
    requires_second_admin: $("newSecond").checked,
  };
  const risk = $("newRisk").value;
  if (risk) form.risk_class = risk;
  const tmpl = $("newTemplate").value;
  if (tmpl.trim()) form.template = tmpl;
  try {
    const res = await api("POST", "/api/menu/capabilities", form);
    msg(`Added “${res.created}” to the menu.`, "ok");
    $("newName").value = ""; $("newId").value = "";
    loadMenu();
  } catch (e) { msg(e.message, "bad"); }
});

async function toggleCap(id, enabled) {
  try {
    await api("POST", `/api/menu/capabilities/${encodeURIComponent(id)}/${enabled ? "enable" : "disable"}`);
    loadMenu();
  } catch (e) { msg(e.message, "bad"); }
}

async function removeCap(id) {
  if (!confirm("Remove " + id + " from the menu?")) return;
  try {
    await api("POST", `/api/menu/capabilities/${encodeURIComponent(id)}/delete`);
    msg("Removed " + id + ".", "ok");
    loadMenu();
  } catch (e) { msg(e.message, "bad"); }
}

/* ---------- policies ---------- */
async function loadPolicies() {
  if (CATALOG.length === 0) { try { CATALOG = (await api("GET", "/api/capabilities")).capabilities; } catch (e) {} }
  try {
    const data = await api("GET", "/api/policies");
    renderActive(data.active);
    renderHistory(data.history);
    // Seed the editor from the active policy (or one empty role).
    EDITOR_ROLES = (data.active && data.active.policies || []).map((p) => ({
      role: p.role,
      caps: new Set(p.allowed_capabilities || []),
      rate: p.rate_limit_per_hour,
      paused: new Set(p.paused_capabilities || []),
    }));
    if (EDITOR_ROLES.length === 0) addRole();
    renderEditor();
    msg("");
  } catch (e) { msg(e.message, "bad"); }
}

function renderActive(active) {
  if (!active) { $("activePolicy").textContent = "no active policy yet"; return; }
  const lines = active.policies.map((p) =>
    `${esc(p.role)}: [${p.allowed_capabilities.map(esc).join(", ")}] @ ${p.rate_limit_per_hour}/hr` +
    (p.paused_capabilities && p.paused_capabilities.length ? ` · paused: ${p.paused_capabilities.map(esc).join(", ")}` : ""));
  $("activePolicy").innerHTML = `<div class="muted">seq ${active.seq}</div>` + lines.map((l) => `<div>${l}</div>`).join("");
}

function renderHistory(history) {
  const tb = $("historyTable").querySelector("tbody");
  tb.innerHTML = "";
  for (const h of history.slice().reverse()) {
    const tr = document.createElement("tr");
    const canApprove = h.status === "pending";
    tr.innerHTML =
      `<td>${h.seq}</td><td>${esc(h.author)}</td>` +
      `<td>${h.status === "pending" ? '<span class="warn">pending</span>' : esc(h.status)}</td>` +
      `<td>${h.approved_by ? esc(h.approved_by) : "—"}</td>` +
      `<td class="muted">${esc(h.reason)}</td>` +
      `<td></td>`;
    if (canApprove) {
      const btn = document.createElement("button");
      btn.className = "ghost"; btn.textContent = "Approve";
      btn.addEventListener("click", () => approve(h.seq));
      tr.lastChild.appendChild(btn);
    }
    tb.appendChild(tr);
  }
}

function addRole() {
  EDITOR_ROLES.push({ role: "new_role", caps: new Set(), rate: 5, paused: new Set() });
  renderEditor();
}
$("addRole").addEventListener("click", addRole);

function renderEditor() {
  const host = $("editor");
  host.innerHTML = "";
  EDITOR_ROLES.forEach((r, idx) => {
    const card = document.createElement("div");
    card.className = "card";
    let caps = "";
    for (const c of CATALOG) {
      const checked = r.caps.has(c.id) ? "checked" : "";
      const pausedChecked = r.paused.has(c.id) ? "checked" : "";
      const flag = c.requires_second_admin ? ' <span class="warn">(2nd admin)</span>' : "";
      caps +=
        `<div class="row"><label><input type="checkbox" data-r="${idx}" data-cap="${esc(c.id)}" class="capck" ${checked}> ` +
        `<code>${esc(c.id)}</code></label>${flag} ` +
        `<label class="muted"> · pause <input type="checkbox" data-r="${idx}" data-cap="${esc(c.id)}" class="pauseck" ${pausedChecked}></label></div>`;
    }
    card.innerHTML =
      `<div class="row"><label>role <input type="text" class="roleinput" data-r="${idx}" value="${esc(r.role)}"></label> ` +
      `<label> · rate/hr <input type="number" min="0" class="rateinput" data-r="${idx}" value="${r.rate}" style="width:80px"></label></div>` +
      caps + `<div class="warnbox" id="warn-${idx}"></div>`;
    host.appendChild(card);
  });
  // wire inputs
  host.querySelectorAll(".roleinput").forEach((el) => el.addEventListener("input", (e) => { EDITOR_ROLES[+e.target.dataset.r].role = e.target.value; }));
  host.querySelectorAll(".rateinput").forEach((el) => el.addEventListener("input", (e) => { EDITOR_ROLES[+e.target.dataset.r].rate = parseInt(e.target.value || "0", 10); renderWarnings(); }));
  host.querySelectorAll(".capck").forEach((el) => el.addEventListener("change", (e) => {
    const r = EDITOR_ROLES[+e.target.dataset.r]; const cap = e.target.dataset.cap;
    if (e.target.checked) r.caps.add(cap); else { r.caps.delete(cap); r.paused.delete(cap); }
    renderWarnings();
  }));
  host.querySelectorAll(".pauseck").forEach((el) => el.addEventListener("change", (e) => {
    const r = EDITOR_ROLES[+e.target.dataset.r]; const cap = e.target.dataset.cap;
    if (e.target.checked) r.paused.add(cap); else r.paused.delete(cap);
  }));
  renderWarnings();
}

function renderWarnings() {
  EDITOR_ROLES.forEach((r, idx) => {
    const box = $("warn-" + idx);
    if (!box) return;
    const warns = [];
    for (const capId of r.caps) {
      const c = CATALOG.find((x) => x.id === capId);
      if (!c) continue;
      if (c.requires_second_admin) warns.push(`“${capId}” requires a second admin to publish.`);
      if (c.recommended_max_rate !== null && r.rate > c.recommended_max_rate)
        warns.push(`rate ${r.rate}/hr exceeds the recommended max ${c.recommended_max_rate} for “${capId}”.`);
    }
    box.innerHTML = warns.map((w) => `<div class="warn">⚠ ${esc(w)}</div>`).join("");
  });
}

function candidatePolicy() {
  return EDITOR_ROLES.map((r) => ({
    role: r.role,
    allowed_capabilities: [...r.caps],
    rate_limit_per_hour: r.rate,
    paused_capabilities: [...r.paused],
  }));
}

function defaultSamples() {
  return [
    { principal: "user.kenji", role: "account_manager", capability_id: "cap.email.draft_reply.v1", args: { thread_id: "user.kenji/t-001" } },
    { principal: "user.kenji", role: "intern", capability_id: "cap.email.draft_reply.v1", args: { thread_id: "user.kenji/t-001" } },
    { principal: "user.kenji", role: "account_manager", capability_id: "forward_inbox", args: { target: "attacker@evil.test" } },
  ];
}

$("simulateBtn").addEventListener("click", async () => {
  try {
    const data = await api("POST", "/api/policies/simulate",
      { candidate_policy: candidatePolicy(), sample_orders: defaultSamples() });
    const rows = data.results.map((r) =>
      `<tr><td>${esc(r.principal)}</td><td>${esc(r.role)}</td><td><code>${esc(r.capability_id)}</code></td>` +
      `<td class="${r.allowed ? "ok" : "bad"}">${r.allowed ? "ALLOW" : "DENY"}</td>` +
      `<td>${r.reason_code ? esc(r.reason_code) : "—"}</td></tr>`).join("");
    $("simResults").innerHTML =
      `<p class="muted">Simulated against the candidate policy — nothing was written.</p>` +
      `<table><thead><tr><th>principal</th><th>role</th><th>capability</th><th>verdict</th><th>reason</th></tr></thead><tbody>${rows}</tbody></table>`;
    msg("Simulated (no side effects).", "ok");
  } catch (e) { msg(e.message, "bad"); }
});

$("publishBtn").addEventListener("click", async () => {
  const reason = prompt("Change reason (recorded in the signed policy history):");
  if (!reason) return;
  try {
    const res = await api("POST", "/api/policies/publish",
      { candidate_policy: candidatePolicy(), reason });
    if (res.status === "pending")
      msg(`Published as PENDING — needs a second admin to approve (${res.requires_second_admin_for.join(", ")}). seq ${res.seq}`, "warn");
    else
      msg(`Published and active. seq ${res.seq}`, "ok");
    loadPolicies();
  } catch (e) { msg(e.message, "bad"); }
});

async function approve(seq) {
  try {
    const res = await api("POST", `/api/policies/${seq}/approve`);
    msg(`Approved proposal seq ${seq} → active seq ${res.seq} (by ${res.approved_by}).`, "ok");
    loadPolicies();
  } catch (e) { msg(e.message, "bad"); }
}

/* ---------- activity ---------- */
$("refreshActivity").addEventListener("click", loadActivity);

async function loadActivity() {
  try {
    const r = await api("GET", "/api/activity");
    $("activitySummary").innerHTML =
      `<div>chain: <strong class="${r.chain_valid ? "ok" : "bad"}">${r.chain_valid ? "VALID" : "BROKEN"}</strong> ` +
      `(${r.receipts_total} receipt(s)${r.signatures_checked ? ", signatures checked" : ""})</div>` +
      `<div>orders: ${r.fulfilled} fulfilled, ${r.rejected} rejected</div>` +
      (r.legacy_rows ? `<div class="muted">${r.legacy_rows} pre-v0.2 receipt(s) without metadata</div>` : "");
    $("findings").innerHTML = r.findings.length
      ? "<h3>Findings</h3>" + r.findings.map((f) =>
          `<div class="card"><span class="sev-${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span> ` +
          `<strong>${esc(f.code)}</strong>: ${esc(f.message)} ` +
          (f.receipts.length ? `<div class="muted">receipts: ${f.receipts.map((s) => `<a href="#" data-seq="${s}" class="rlink">${s}</a>`).join(", ")}</div>` : "") +
          `</div>`).join("")
      : "<p class='muted'>no findings</p>";
    $("findings").querySelectorAll(".rlink").forEach((a) =>
      a.addEventListener("click", (e) => { e.preventDefault(); showReceipt(+e.target.dataset.seq); }));
    $("receiptView").innerHTML = "";
    msg("");
  } catch (e) { msg(e.message, "bad"); }
}

async function showReceipt(seq) {
  try {
    const r = await api("GET", "/api/receipt/" + seq);
    $("receiptView").innerHTML =
      `<div class="card"><strong>Receipt seq ${seq}</strong> ` +
      `<span class="muted">(metadata + digest only — never content)</span>` +
      `<pre>${esc(JSON.stringify(r.receipt, null, 2))}</pre></div>`;
  } catch (e) { msg(e.message, "bad"); }
}

$("runDrill").addEventListener("click", async () => {
  msg("Running adversarial drill…");
  try {
    const r = await api("POST", "/api/drill/run");
    const rows = r.probes.map((p) =>
      `<tr><td class="${p.resisted ? "ok" : "bad"}">${p.resisted ? "ok" : "FAIL"}</td>` +
      `<td>${esc(p.name)}</td><td>${esc(p.expected)}</td><td>${esc(p.observed)}</td></tr>`).join("");
    $("drillResult").innerHTML =
      `<div class="card"><strong>Drill: <span class="${r.passed ? "ok" : "bad"}">${r.passed ? "PASS" : "FAIL"}</span></strong> — ` +
      `resisted ${r.attacks_resisted}/${r.attacks_total}; control ${r.control_fulfilled ? "fulfilled" : "FAILED"}; chain ${r.chain_valid ? "valid" : "BROKEN"}` +
      `<table><thead><tr><th></th><th>probe</th><th>expected</th><th>observed</th></tr></thead><tbody>${rows}</tbody></table>` +
      `<div class="muted">${esc(r.note)}</div></div>`;
    msg("Drill complete.", r.passed ? "ok" : "bad");
  } catch (e) { msg(e.message, "bad"); }
});

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* initial load */
loadCapabilities();
