/* TrustVault SPA.
 * Talks to Postgres through PostgREST (RLS decides what the signed-in user
 * may see) and to the edge functions for file bytes. All permission logic
 * lives server-side; this code only reflects it in the UI.
 */
"use strict";

const sb = supabase.createClient(window.TRUSTVAULT.supaUrl, window.TRUSTVAULT.supaAnonKey);
const SUPA = window.TRUSTVAULT.supaUrl;
let me = null; // my profile row

/* ---------------- small helpers ---------------- */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&" + "amp;",
    "<": "&" + "lt;",
    ">": "&" + "gt;",
    '"': "&" + "quot;",
    "'": "&" + "#39;",
  }[c]));
const fmtBytes = (n) => {
  if (n == null) return "";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
};
const fmtDate = (iso) =>
  iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "";
const route = () => (location.hash || "#/docs").replace("#/", "").split("?")[0];

function toast(msg, isErr = false) {
  const t = document.createElement("div");
  t.className = "toast" + (isErr ? " err" : "");
  t.textContent = msg;
  $("#toast-root").appendChild(t);
  requestAnimationFrame(() => t.classList.add("show"));
  setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.remove(), 300); }, 3400);
}

async function token() {
  const { data: { session } } = await sb.auth.getSession();
  return session?.access_token ?? "";
}

/* ---------------- auth ---------------- */
async function loadProfile() {
  const { data: { user } } = await sb.auth.getUser();
  if (!user) { me = null; return; }
  const { data } = await sb.from("profiles").select("*").eq("id", user.id).maybeSingle();
  me = data;
}

async function login(email, password) {
  const { error } = await sb.auth.signInWithPassword({ email, password });
  if (error) return error.message;
  Object.assign(docFilters, { title: "", category: "", ownerId: "", from: "", to: "" });
  await loadProfile();
  location.hash = "#/docs";
  render();
  return null;
}

async function logout() {
  await sb.auth.signOut();
  me = null;
  render();
}

/* ---------------- edge function calls ---------------- */
async function callEdge(name, body, isForm = false) {
  const t = await token();
  const r = await fetch(`${SUPA}/functions/v1/${name}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${t}`,
      ...(isForm ? {} : { "Content-Type": "application/json" }),
    },
    body: isForm ? body : JSON.stringify(body),
  });
  const data = await r.json().catch(() => null);
  if (!r.ok) throw new Error(data?.error ?? `request failed (${r.status})`);
  return data;
}

async function downloadDoc(doc, version) {
  const t = await token();
  const r = await fetch(`${SUPA}/functions/v1/serve-doc`, {
    method: "POST",
    headers: { Authorization: `Bearer ${t}`, "Content-Type": "application/json" },
    body: JSON.stringify({ document_id: doc.id, ...(version ? { version } : {}) }),
  });
  if (!r.ok) {
    let msg = `download failed (${r.status})`;
    try { const j = await r.json(); if (j.error) msg = j.error; } catch {}
    toast(msg, true);
    return;
  }
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = doc.filename || "document";
  a.click();
  URL.revokeObjectURL(a.href);
  toast(`Downloaded “${doc.title}” — this was recorded in the audit trail.`);
}

/* ---------------- modal plumbing ---------------- */
function openModal(html, { wide = false } = {}) {
  const root = $("#modal-root");
  root.innerHTML = "";
  const ov = document.createElement("div");
  ov.className = "overlay";
  ov.innerHTML = `<div class="modal${wide ? " wide" : ""}">${html}</div>`;
  root.appendChild(ov);
  ov.addEventListener("mousedown", (e) => { if (e.target === ov) closeModal(); });
  document.addEventListener("keydown", modalEsc);
  return ov;
}
function modalEsc(e) { if (e.key === "Escape") closeModal(); }
function closeModal() {
  $("#modal-root").innerHTML = "";
  document.removeEventListener("keydown", modalEsc);
}

/* ---------------- shell ---------------- */
function render() {
  const nav = $("#nav");
  const userbox = $("#userbox");
  if (!me) {
    nav.innerHTML = "";
    userbox.innerHTML = "";
    renderLogin();
    return;
  }
  const tabs = [
    ["docs", "Documents"],
    ["audit", "Audit trail"],
    ["users", "Users"],
  ];
  nav.innerHTML = tabs
    .filter(([k]) => k !== "audit" && k !== "users" || me.role === "admin")
    .map(([k, label]) => `<div class="tab${route() === k ? " active" : ""}" data-nav="${k}">${label}</div>`)
    .join("");
  $$(".tab", nav).forEach((t) =>
    t.addEventListener("click", () => { location.hash = `#/${t.dataset.nav}`; render(); }));

  const initials = (me.full_name || me.email)
    .split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase();
  userbox.innerHTML = `
    <span class="role-badge role-${me.role}">${esc(me.role)}</span>
    <span>${esc(me.full_name || me.email)}</span>
    <span class="avatar">${esc(initials)}</span>
    <a class="linklike" id="logout">Sign out</a>`;
  $("#logout").addEventListener("click", logout);

  const view = $("#view");
  view.innerHTML = "";
  if (route() === "audit" && me.role === "admin") renderAudit(view);
  else if (route() === "users" && me.role === "admin") renderUsers(view);
  else renderDocs(view);
}

function renderLogin() {
  $("#view").innerHTML = `
    <div class="login-wrap">
      <div class="card">
        <p class="login-title">Sign in to TrustVault</p>
        <p class="login-sub">Documents are only reachable by people granted them. Every access is logged.</p>
        <div id="login-error"></div>
        <div class="field"><label>Email</label><input id="li-email" type="email" autocomplete="username"></div>
        <div class="field"><label>Password</label><input id="li-pass" type="password" autocomplete="current-password"></div>
        <button class="primary" id="li-btn" style="width:100%">Sign in</button>
        <div class="demo-accounts">
          <details>
            <summary>Demo accounts (see README for passwords)</summary>
            <table>
              <tr><td class="mono">admin@trustvault.demo</td><td>administrator</td></tr>
              <tr><td class="mono">alice@trustvault.demo</td><td>document owner</td></tr>
              <tr><td class="mono">bob@trustvault.demo</td><td>document owner</td></tr>
              <tr><td class="mono">carol@trustvault.demo</td><td>viewer</td></tr>
              <tr><td class="mono">dave@trustvault.demo</td><td>viewer</td></tr>
            </table>
          </details>
        </div>
      </div>
    </div>`;
  const go = async () => {
    const err = await login($("#li-email").value.trim(), $("#li-pass").value);
    if (err) $("#login-error").innerHTML = `<div class="error-note">${esc(err)}</div>`;
  };
  $("#li-btn").addEventListener("click", go);
  $("#view").addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
}

/* ---------------- documents page ---------------- */
const docFilters = { title: "", category: "", ownerId: "", from: "", to: "" };
let directory = [];

async function fetchDirectory() {
  const { data } = await sb.from("profiles").select("id,email,full_name,role,is_active").order("email");
  directory = data ?? [];
}

function myAccess(doc) {
  if (doc.owner_id === me.id) return "owner";
  const g = (doc.grants ?? []).find((x) => x.user_id === me.id && !x.revoked_at);
  return g ? g.permission : null;
}

async function renderDocs(view) {
  await fetchDirectory();
  const canUpload = me.role === "admin" || me.role === "owner";
  view.innerHTML = `
    <div class="page-head">
      <h1>Documents</h1>
      <span class="sub">You only see documents you own or have been granted.</span>
      <span class="spacer"></span>
      ${canUpload ? `<button class="primary" id="btn-upload">Upload document</button>` : ""}
    </div>
    <div class="card">
      <div class="toolbar">
        <div class="field"><label>Title contains</label><input id="f-title" value="${esc(docFilters.title)}" placeholder="e.g. contract"></div>
        <div class="field"><label>Category</label><input id="f-cat" value="${esc(docFilters.category)}" placeholder="e.g. Legal"></div>
        <div class="field"><label>Owner</label><select id="f-owner"><option value="">any owner</option>
          ${directory.map((p) => `<option value="${p.id}" ${docFilters.ownerId === p.id ? "selected" : ""}>${esc(p.full_name || p.email)}</option>`).join("")}
        </select></div>
        <div class="field"><label>From</label><input id="f-from" type="date" value="${esc(docFilters.from)}"></div>
        <div class="field"><label>To</label><input id="f-to" type="date" value="${esc(docFilters.to)}"></div>
        <div class="field"><label>&nbsp;</label><button id="f-apply">Search</button></div>
      </div>
    </div>
    <div class="card" style="padding:0" id="docs-card"></div>`;

  const refresh = async () => {
    docFilters.title = $("#f-title").value.trim();
    docFilters.category = $("#f-cat").value.trim();
    docFilters.ownerId = $("#f-owner").value;
    docFilters.from = $("#f-from").value;
    docFilters.to = $("#f-to").value;
    await loadDocsTable($("#docs-card"));
  };
  $("#f-apply").addEventListener("click", refresh);
  ["f-title", "f-cat"].forEach((id) =>
    $(`#${id}`).addEventListener("keydown", (e) => { if (e.key === "Enter") refresh(); }));
  if (canUpload) $("#btn-upload").addEventListener("click", () => openUploadModal());
  await refresh();
}

async function loadDocsTable(card) {
  let q = sb
    .from("documents")
    .select("*, owner:profiles!documents_owner_id_fkey(id,full_name,email), grants(id,user_id,permission,revoked_at,granted_by,granted_at)");
  if (docFilters.title) q = q.ilike("title", `%${docFilters.title}%`);
  if (docFilters.category) q = q.ilike("category", `%${docFilters.category}%`);
  if (docFilters.ownerId) q = q.eq("owner_id", docFilters.ownerId);
  if (docFilters.from) q = q.gte("created_at", `${docFilters.from}T00:00:00`);
  if (docFilters.to) q = q.lte("created_at", `${docFilters.to}T23:59:59`);
  const { data, error } = await q.order("updated_at", { ascending: false }).limit(200);

  if (error) {
    card.innerHTML = `<div class="empty">${esc(error.message)}</div>`;
    return;
  }
  if (!data.length) {
    card.innerHTML = `<div class="empty">No documents match. ${me.role === "viewer" ? "Owners can share documents with you." : ""}</div>`;
    return;
  }
  card.innerHTML = `
    <table>
      <thead><tr>
        <th>Title</th><th>Category</th><th>Owner</th><th>Size</th><th>Ver.</th><th>Updated</th><th>My access</th><th></th>
      </tr></thead>
      <tbody>
        ${data.map((d) => {
          const acc = myAccess(d);
          return `<tr class="clickable" data-doc='${esc(JSON.stringify(d))}'>
            <td><b>${esc(d.title)}</b>${d.status === "deleted" ? ` <span class="chip chip-off">deleted</span>` : ""}</td>
            <td><span class="chip chip-cat">${esc(d.category)}</span></td>
            <td>${esc(d.owner?.full_name || d.owner?.email || "")}</td>
            <td class="muted">${fmtBytes(d.size_bytes)}</td>
            <td class="muted">${d.current_version}</td>
            <td class="muted nowrap">${fmtDate(d.updated_at)}</td>
            <td>${acc === "owner" ? `<span class="chip chip-owner">owner</span>`
                : acc === "edit" ? `<span class="chip chip-edit">edit</span>`
                : acc === "read" ? `<span class="chip chip-read">read</span>`
                : `<span class="chip chip-off">—</span>`}</td>
            <td><button class="small" data-open='${esc(JSON.stringify(d))}'>Open</button></td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>`;
  $$("[data-open]", card).forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      openDocModal(JSON.parse(b.dataset.open));
    }));
  $$("tr.clickable", card).forEach((tr) =>
    tr.addEventListener("click", () => openDocModal(JSON.parse(tr.dataset.doc))));
}

/* ---------------- upload modal ---------------- */
function openUploadModal() {
  const ov = openModal(`
    <div class="modal-head"><h2>Upload a document</h2><button class="modal-close" data-x>✕</button></div>
    <div id="up-error"></div>
    <div class="field" style="margin-bottom:12px"><label style="font-size:12.5px;color:var(--ink-soft)">File (PDF, PNG, JPEG, DOCX, XLSX, PPTX, TXT, CSV, MD — max 25 MB)</label><input type="file" id="up-file"></div>
    <div class="field" style="margin-bottom:12px"><label style="font-size:12.5px;color:var(--ink-soft)">Title</label><input id="up-title" style="width:100%"></div>
    <div class="grid-2">
      <div class="field"><label style="font-size:12.5px;color:var(--ink-soft)">Category</label><input id="up-cat" placeholder="e.g. Legal"></div>
      <div class="field"><label style="font-size:12.5px;color:var(--ink-soft)">Description</label><input id="up-desc"></div>
    </div>
    <div style="margin-top:16px;text-align:right"><button class="primary" id="up-go">Upload</button></div>
    <p class="hint">The upload, its validation and this audit entry are recorded server-side.</p>
  `);
  $("[data-x]", ov).addEventListener("click", closeModal);
  $("#up-go", ov).addEventListener("click", async (e) => {
    const btn = e.currentTarget;
    const file = $("#up-file", ov).files[0];
    if (!file) return $("#up-error", ov).innerHTML = `<div class="error-note">Choose a file first.</div>`;
    if (!$("#up-title", ov).value.trim()) return $("#up-error", ov).innerHTML = `<div class="error-note">A title is required.</div>`;
    btn.disabled = true;
    btn.textContent = "Uploading…";
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("title", $("#up-title", ov).value.trim());
      form.append("category", $("#up-cat", ov).value.trim() || "general");
      form.append("description", $("#up-desc", ov).value.trim());
      await callEdge("upload-doc", form, true);
      closeModal();
      toast("Uploaded. The audit trail records who uploaded what and when.");
      render();
    } catch (err) {
      $("#up-error", ov).innerHTML = `<div class="error-note">${esc(err.message)}</div>`;
      btn.disabled = false;
      btn.textContent = "Upload";
    }
  });
}

/* ---------------- document details modal ---------------- */
async function openDocModal(doc) {
  const isOwner = doc.owner_id === me.id;
  const isAdmin = me.role === "admin";
  const acc = myAccess(doc);
  const canManage = (isOwner || isAdmin) && doc.status === "active";
  const canEditMeta = canManage || acc === "edit";
  const canVersion = (isOwner || isAdmin || acc === "edit") && doc.status === "active";

  const ov = openModal(`
    <div class="modal-head">
      <h2>${esc(doc.title)}</h2>
      <span class="chip chip-cat">${esc(doc.category)}</span>
      <button class="modal-close" data-x>✕</button>
    </div>
    <dl class="kv">
      <dt>Owner</dt><dd>${esc(doc.owner?.full_name || doc.owner?.email || "")}</dd>
      <dt>File</dt><dd class="mono">${esc(doc.filename)} — ${fmtBytes(doc.size_bytes)} — ${esc(doc.mime_type)}</dd>
      <dt>SHA-256</dt><dd class="mono">${esc(doc.sha256)}</dd>
      <dt>Uploaded</dt><dd>${fmtDate(doc.created_at)}</dd>
      <dt>Updated</dt><dd>${fmtDate(doc.updated_at)}</dd>
      <dt>Status</dt><dd>${doc.status === "active" ? `<span class="chip chip-active">active</span>` : `<span class="chip chip-off">deleted</span>`}</dd>
      ${doc.description ? `<dt>Description</dt><dd>${esc(doc.description)}</dd>` : ""}
    </dl>
    <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
      <button class="primary" id="d-download">Download</button>
      ${canVersion ? `<button id="d-newver">Upload new version</button>` : ""}
      ${canEditMeta ? `<button id="d-edit">Edit details</button>` : ""}
      ${canManage && doc.status === "active" ? `<button class="ghost-danger" id="d-softdel">Delete</button>` : ""}
      ${canManage && doc.status === "deleted" ? `<button id="d-restore">Restore</button>` : ""}
      ${canManage ? `<button class="ghost-danger" id="d-purge">Purge permanently</button>` : ""}
    </div>

    <div class="modal-section" id="d-versions"><h3>Versions</h3><div class="empty">Loading…</div></div>
    <div class="modal-section" id="d-grants"><h3>Who has access</h3><div class="empty">Loading…</div></div>
    <div id="d-suggest"></div>
  `, { wide: true });

  $("[data-x]", ov).addEventListener("click", closeModal);
  $("#d-download", ov).addEventListener("click", () => downloadDoc(doc));
  $("#d-softdel", ov)?.addEventListener("click", async () => {
    const { error } = await sb.from("documents").update({ status: "deleted", deleted_at: new Date().toISOString() }).eq("id", doc.id);
    if (error) return toast(error.message, true);
    closeModal(); toast("Soft-deleted (recoverable). Audited."); render();
  });
  $("#d-restore", ov)?.addEventListener("click", async () => {
    const { error } = await sb.from("documents").update({ status: "active", deleted_at: null }).eq("id", doc.id);
    if (error) return toast(error.message, true);
    closeModal(); toast("Restored. Audited."); render();
  });
  $("#d-purge", ov)?.addEventListener("click", async () => {
    if (!confirm(`Permanently destroy “${doc.title}” and all its versions? This cannot be undone.`)) return;
    try {
      await callEdge("vault-admin", { action: "purge_document", document_id: doc.id });
      closeModal(); toast("Purged. The audit entry is the only remaining record."); render();
    } catch (err) { toast(err.message, true); }
  });
  $("#d-edit", ov)?.addEventListener("click", () => {
    openEditMetaModal(doc);
  });
  $("#d-newver", ov)?.addEventListener("click", () => {
    openVersionModal(doc);
  });

  // versions
  const { data: versions } = await sb
    .from("document_versions")
    .select("*").eq("document_id", doc.id).order("version_no", { ascending: false });
  const vWrap = $("#d-versions", ov);
  if (!versions?.length) vWrap.innerHTML = `<div class="empty">No versions.</div>`;
  else vWrap.innerHTML = `
    <table>
      <thead><tr><th>Ver.</th><th>File</th><th>Size</th><th>By</th><th>When</th><th>Note</th><th></th></tr></thead>
      <tbody>${versions.map((v) => {
        const canGet = v.version_no === doc.current_version || isOwner || isAdmin || acc === "edit";
        return `<tr>
          <td class="mono">${v.version_no}${v.version_no === doc.current_version ? ' <span class="chip chip-read">current</span>' : ""}</td>
          <td class="mono">${esc(v.filename)}</td>
          <td class="muted">${fmtBytes(v.size_bytes)}</td>
          <td class="muted">${esc(directory.find((p) => p.id === v.uploaded_by)?.email ?? "")}</td>
          <td class="muted nowrap">${fmtDate(v.created_at)}</td>
          <td class="muted">${esc(v.note || "")}</td>
          <td>${canGet ? `<button class="small" data-ver="${v.version_no}">Get</button>` : ""}</td>
        </tr>`;
      }).join("")}</tbody>
    </table>`;
  $$("[data-ver]", vWrap).forEach((b) =>
    b.addEventListener("click", () => downloadDoc(doc, parseInt(b.dataset.ver, 10))));

  // grants
  const { data: grants } = await sb
    .from("grants").select("*").eq("document_id", doc.id).order("granted_at", { ascending: false });
  const gWrap = $("#d-grants", ov);
  const live = (grants ?? []).filter((g) => !g.revoked_at);
  const revoked = (grants ?? []).filter((g) => g.revoked_at);
  const userName = (id) => {
    const p = directory.find((x) => x.id === id);
    return p ? `${p.full_name || p.email} (${p.email})` : id;
  };
  gWrap.innerHTML = `
    ${canManage ? `
    <div class="inline-form" style="margin-bottom:12px">
      <div><label style="font-size:12px;color:var(--ink-soft)">Person</label>
        <select id="g-user"><option value="">choose…</option>
          ${directory.filter((p) => p.id !== doc.owner_id && p.is_active).map((p) => `<option value="${p.id}">${esc(p.full_name || p.email)} (${esc(p.email)})</option>`).join("")}
        </select></div>
      <div><label style="font-size:12px;color:var(--ink-soft)">Permission</label>
        <select id="g-perm"><option value="read">read</option><option value="edit">edit</option></select></div>
      <button class="primary" id="g-add">Grant access</button>
      <button id="g-suggest">Suggest people</button>
    </div>
    <p class="hint">“Suggest” lists people who already see this owner's documents in the same category — a hint only. Access widens only when you confirm it here, and both the suggestion and the grant are audited.</p>
    <div id="g-suggest-out"></div>` : ""}
    ${live.length ? `<table>
      <thead><tr><th>Person</th><th>Permission</th><th>Granted</th><th>Granted by</th><th></th></tr></thead>
      <tbody>${live.map((g) => `<tr>
        <td>${esc(userName(g.user_id))}</td>
        <td><span class="chip chip-${g.permission}">${g.permission}</span></td>
        <td class="muted nowrap">${fmtDate(g.granted_at)}</td>
        <td class="muted">${esc(userName(g.granted_by))}</td>
        <td>${canManage ? `<button class="small ghost-danger" data-revoke="${g.id}">Revoke</button>` : ""}</td>
      </tr>`).join("")}</tbody></table>`
      : `<div class="empty">Nobody else has access.</div>`}
    ${revoked.length ? `<details style="margin-top:10px"><summary class="muted" style="cursor:pointer;font-size:13px">Revoked grants (${revoked.length})</summary>
      <table><tbody>${revoked.map((g) => `<tr>
        <td>${esc(userName(g.user_id))}</td><td class="muted">${g.permission}</td>
        <td class="muted">revoked ${fmtDate(g.revoked_at)} by ${esc(userName(g.revoked_by))}</td>
      </tr>`).join("")}</tbody></table></details>` : ""}
  `;

  if (canManage) {
    $("#g-add", gWrap)?.addEventListener("click", async () => {
      const user_id = $("#g-user", gWrap).value;
      const permission = $("#g-perm", gWrap).value;
      if (!user_id) return toast("Choose a person first.", true);
      const { error } = await sb.from("grants").insert({ document_id: doc.id, user_id, permission, granted_by: me.id });
      if (error) return toast(error.message, true);
      toast("Access granted. Audited, and effective immediately for that person.");
      openDocModal(doc);
    });
    $("#g-suggest", gWrap)?.addEventListener("click", async () => {
      const { data, error } = await sb.rpc("suggest_access", { p_document: doc.id });
      if (error) return toast(error.message, true);
      const out = $("#g-suggest-out", gWrap);
      if (!data?.length) { out.innerHTML = `<p class="hint">No suggestions — nobody else currently sees this owner's documents in “${esc(doc.category)}”.</p>`; return; }
      out.innerHTML = `<table><tbody>${data.map((s) => `<tr>
        <td>${esc(s.full_name || s.email)} <span class="muted mono">${esc(s.email)}</span></td>
        <td class="muted" style="font-size:13px">${esc(s.reason)}</td>
        <td><button class="small" data-sg="${s.user_id}" data-sgp="read">Add read</button>
            <button class="small" data-sg="${s.user_id}" data-sgp="edit">Add edit</button></td>
      </tr>`).join("")}</tbody></table>`;
      $$("[data-sg]", out).forEach((b) =>
        b.addEventListener("click", async () => {
          const { error: e2 } = await sb.from("grants").insert({
            document_id: doc.id, user_id: b.dataset.sg, permission: b.dataset.sgp, granted_by: me.id });
          if (e2) return toast(e2.message, true);
          toast("Access granted. Audited.");
          openDocModal(doc);
        }));
    });
    $$("[data-revoke]", gWrap).forEach((b) =>
      b.addEventListener("click", async () => {
        const { error } = await sb
          .from("grants").update({ revoked_at: new Date().toISOString(), revoked_by: me.id }).eq("id", b.dataset.revoke);
        if (error) return toast(error.message, true);
        toast("Revoked. Their very next request is refused.");
        openDocModal(doc);
      }));
  }
}

function openEditMetaModal(doc) {
  const ov = openModal(`
    <div class="modal-head"><h2>Edit details</h2><button class="modal-close" data-x>✕</button></div>
    <div class="field" style="margin-bottom:12px"><label style="font-size:12.5px;color:var(--ink-soft)">Title</label><input id="e-title" style="width:100%" value="${esc(doc.title)}"></div>
    <div class="grid-2">
      <div class="field"><label style="font-size:12.5px;color:var(--ink-soft)">Category</label><input id="e-cat" value="${esc(doc.category)}"></div>
      <div class="field"><label style="font-size:12.5px;color:var(--ink-soft)">Description</label><input id="e-desc" value="${esc(doc.description)}"></div>
    </div>
    <p class="hint">Edit permission covers title, category and description only — the server enforces that.</p>
    <div style="margin-top:14px;text-align:right"><button class="primary" id="e-go">Save</button></div>`);
  $("[data-x]", ov).addEventListener("click", closeModal);
  $("#e-go", ov).addEventListener("click", async (e) => {
    const { error } = await sb.from("documents").update({
      title: $("#e-title", ov).value.trim(),
      category: $("#e-cat", ov).value.trim() || "general",
      description: $("#e-desc", ov).value.trim(),
    }).eq("id", doc.id);
    if (error) return toast(error.message, true);
    closeModal(); toast("Saved. Audited."); render();
  });
}

function openVersionModal(doc) {
  const ov = openModal(`
    <div class="modal-head"><h2>New version — ${esc(doc.title)}</h2><button class="modal-close" data-x>✕</button></div>
    <div id="v-error"></div>
    <div class="field" style="margin-bottom:12px"><label style="font-size:12.5px;color:var(--ink-soft)">File (must be ${esc(doc.mime_type)})</label><input type="file" id="v-file"></div>
    <div class="field" style="margin-bottom:12px"><label style="font-size:12.5px;color:var(--ink-soft)">Note (optional)</label><input id="v-note" placeholder="what changed"></div>
    <div style="text-align:right"><button class="primary" id="v-go">Upload version</button></div>
    <p class="hint">Earlier versions stay downloadable (for people with edit access) and every download is audited.</p>`);
  $("[data-x]", ov).addEventListener("click", closeModal);
  $("#v-go", ov).addEventListener("click", async () => {
    const file = $("#v-file", ov).files[0];
    if (!file) return $("#v-error", ov).innerHTML = `<div class="error-note">Choose a file.</div>`;
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("document_id", doc.id);
      form.append("note", $("#v-note", ov).value.trim());
      await callEdge("upload-doc", form, true);
      closeModal(); toast("New version uploaded. Audited."); render();
    } catch (err) {
      $("#v-error", ov).innerHTML = `<div class="error-note">${esc(err.message)}</div>`;
    }
  });
}

/* ---------------- audit page (admin) ---------------- */
async function renderAudit(view) {
  view.innerHTML = `
    <div class="page-head">
      <h1>Audit trail</h1>
      <span class="sub">Append-only and hash-chained — including refused attempts.</span>
      <span class="spacer"></span>
      <button id="verify-btn">Verify chain integrity</button>
    </div>
    <div id="verify-out"></div>
    <div class="card">
      <div class="toolbar">
        <div class="field"><label>Action</label><select id="a-action"><option value="">all actions</option></select></div>
        <div class="field"><label>Actor email contains</label><input id="a-actor" placeholder="e.g. carol"></div>
        <div class="field"><label>Document title contains</label><input id="a-doc" placeholder="e.g. Acme"></div>
        <div class="field"><label>&nbsp;</label><button id="a-apply">Filter</button></div>
      </div>
    </div>
    <div class="card" style="padding:0" id="audit-card"></div>`;
  $("#verify-btn").addEventListener("click", async () => {
    const { data, error } = await sb.rpc("verify_audit_chain");
    const out = $("#verify-out");
    if (error) return (out.innerHTML = `<div class="banner bad">${esc(error.message)}</div>`);
    out.innerHTML = data.ok
      ? `<div class="banner ok">Hash chain verified: ${data.checked} entries, every hash recomputes correctly — the log is internally consistent.</div>`
      : `<div class="banner bad">CHAIN BROKEN at seq ${data.first_bad_seq} — entries at or after this point were altered or removed.</div>`;
  });

  const refresh = async () => {
    let q = sb.from("audit_log").select("*").order("seq", { ascending: false }).limit(300);
    const action = $("#a-action").value;
    const actor = $("#a-actor").value.trim();
    const doc = $("#a-doc").value.trim();
    if (action) q = q.eq("action", action);
    if (actor) q = q.ilike("actor_email", `%${actor}%`);
    if (doc) q = q.ilike("document_title", `%${doc}%`);
    const { data, error } = await q;
    const card = $("#audit-card");
    if (error) return (card.innerHTML = `<div class="empty">${esc(error.message)}</div>`);
    if (!data.length) return (card.innerHTML = `<div class="empty">No entries.</div>`);
    const actions = [...new Set(data.map((d) => d.action))].sort();
    const sel = $("#a-action");
    if (sel.options.length <= 1) {
      sel.innerHTML = `<option value="">all actions</option>` +
        actions.map((a) => `<option ${a === action ? "selected" : ""}>${esc(a)}</option>`).join("");
    }
    card.innerHTML = `
      <table>
        <thead><tr><th>Seq</th><th>When</th><th>Actor</th><th>Action</th><th>Document</th><th>Target</th><th>Detail</th><th>IP</th></tr></thead>
        <tbody>${data.map((a) => `<tr>
          <td class="mono">${a.seq}</td>
          <td class="muted nowrap">${fmtDate(a.ts)}</td>
          <td>${esc(a.actor_email || "—")}</td>
          <td>${a.action.includes("denied") || a.action.includes("blocked")
            ? `<span class="chip chip-denied">${esc(a.action)}</span>` : `<span class="chip chip-cat">${esc(a.action)}</span>`}</td>
          <td>${esc(a.document_title || "—")}</td>
          <td class="muted">${esc(a.target_email || "—")}</td>
          <td class="mono" style="font-size:11.5px;max-width:300px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(JSON.stringify(a.detail ?? {}))}">${esc(JSON.stringify(a.detail ?? {}))}</td>
          <td class="mono muted">${esc(a.ip || "—")}</td>
        </tr>`).join("")}</tbody>
      </table>`;
  };
  $("#a-apply").addEventListener("click", refresh);
  await refresh();
}

/* ---------------- users page (admin) ---------------- */
async function renderUsers(view) {
  await fetchDirectory();
  view.innerHTML = `
    <div class="page-head">
      <h1>Users</h1>
      <span class="sub">Deactivating a user severs every live grant immediately.</span>
    </div>
    <div class="card">
      <h3 style="margin:0 0 10px;font-size:14px">Create a user</h3>
      <div class="inline-form">
        <div><label style="font-size:12px;color:var(--ink-soft)">Email</label><input id="u-email"></div>
        <div><label style="font-size:12px;color:var(--ink-soft)">Full name</label><input id="u-name"></div>
        <div><label style="font-size:12px;color:var(--ink-soft)">Role</label><select id="u-role"><option>viewer</option><option>owner</option><option>admin</option></select></div>
        <div><label style="font-size:12px;color:var(--ink-soft)">Password</label><input id="u-pass" type="password" placeholder="min 10 chars"></div>
        <button class="primary" id="u-create">Create</button>
      </div>
      <div id="u-msg" style="margin-top:10px"></div>
    </div>
    <div class="card" style="padding:0" id="users-card"></div>`;
  $("#u-create").addEventListener("click", async () => {
    try {
      await callEdge("vault-admin", {
        action: "create_user",
        email: $("#u-email").value.trim(),
        full_name: $("#u-name").value.trim(),
        role: $("#u-role").value,
        password: $("#u-pass").value,
      });
      $("#u-msg").innerHTML = `<div class="ok-note">User created. Audited.</div>`;
      renderUsers($("#view"));
    } catch (err) {
      $("#u-msg").innerHTML = `<div class="error-note">${esc(err.message)}</div>`;
    }
  });
  const card = $("#users-card");
  card.innerHTML = `
    <table>
      <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th></th></tr></thead>
      <tbody>${directory.map((p) => `<tr>
        <td class="mono">${esc(p.email)}</td>
        <td>${esc(p.full_name || "")}</td>
        <td><span class="chip role-${p.role}" style="border-radius:20px">${esc(p.role)}</span></td>
        <td>${p.is_active ? `<span class="chip chip-active">active</span>` : `<span class="chip chip-off">deactivated</span>`}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="small" data-reset="${p.id}">Reset password</button>
          ${p.id === me.id ? "" : p.is_active
            ? `<button class="small ghost-danger" data-deact="${p.id}">Deactivate</button>`
            : `<button class="small" data-act="${p.id}">Activate</button>`}
        </td>
      </tr>`).join("")}</tbody>
    </table>`;
  $$("[data-deact]", card).forEach((b) =>
    b.addEventListener("click", async () => {
      if (!confirm("Deactivate this user? All their live grants are revoked immediately.")) return;
      try { await callEdge("vault-admin", { action: "deactivate_user", user_id: b.dataset.deact }); toast("Deactivated. All grants revoked."); renderUsers($("#view")); }
      catch (err) { toast(err.message, true); }
    }));
  $$("[data-act]", card).forEach((b) =>
    b.addEventListener("click", async () => {
      try { await callEdge("vault-admin", { action: "activate_user", user_id: b.dataset.act }); toast("Activated."); renderUsers($("#view")); }
      catch (err) { toast(err.message, true); }
    }));
  $$("[data-reset]", card).forEach((b) =>
    b.addEventListener("click", async () => {
      const np = prompt("New password (min 10 characters):");
      if (!np) return;
      try { await callEdge("vault-admin", { action: "reset_password", user_id: b.dataset.reset, new_password: np }); toast("Password reset. Audited."); }
      catch (err) { toast(err.message, true); }
    }));
}

/* ---------------- boot ---------------- */
(async function boot() {
  await loadProfile();
  render();
  sb.auth.onAuthStateChange(async (event) => {
    if (event === "SIGNED_IN" || event === "SIGNED_OUT" || event === "TOKEN_REFRESHED") {
      await loadProfile();
      render();
    }
  });
})();
