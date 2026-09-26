"use strict";
(() => {
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const state = {
    me: null,
    endpoints: [],
    prev: new Map(),     // name -> {t, rx, tx} for rate calculation
    rates: new Map(),    // name -> {rx, tx} bytes/s
    status: null,
    tab: "endpoints",
    drawer: null,        // endpoint name
    filter: "",
    pollTimer: null,
    modalSubmit: null,
  };

  // ---------- API ----------
  class ApiError extends Error {
    constructor(status, body) {
      super((body && body.error) || `HTTP ${status}`);
      this.status = status;
      this.fields = (body && body.fields) || {};
    }
  }

  async function api(method, path, body) {
    const opts = { method, headers: { "X-Requested-With": "udp6proxy" }, credentials: "same-origin" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    if (!res.ok) {
      if (res.status === 401 && path !== "/api/v1/auth/login") showLogin();
      throw new ApiError(res.status, data);
    }
    return data;
  }

  // ---------- formatting ----------
  function bytes(n) {
    if (!n) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
  }
  const rate = (n) => (n > 0 ? `${bytes(n)}/s` : "");
  const num = (n) => (n || 0).toLocaleString();
  function ago(ts) {
    if (!ts || ts.startsWith("0001")) return "—";
    const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
    if (s < 5) return "just now";
    if (s < 60) return `${Math.floor(s)}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }
  const date = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const listenOf = (e) => `${e.listenAddress || "0.0.0.0"}:${e.localPort}`;
  const remoteOf = (e) => (e.remoteAddress.includes(":") ? `[${e.remoteAddress}]:${e.remotePort}` : `${e.remoteAddress}:${e.remotePort}`);

  // ---------- toasts ----------
  function toast(msg, isErr = false) {
    const el = document.createElement("div");
    el.className = "toast" + (isErr ? " err" : "");
    el.textContent = msg;
    $("#toasts").appendChild(el);
    setTimeout(() => el.remove(), isErr ? 5000 : 2600);
  }

  // ---------- auth ----------
  function showLogin() {
    stopPolling();
    state.me = null;
    $("#app-view").classList.add("hidden");
    $("#drawer").classList.add("hidden");
    closeModal();
    $("#login-view").classList.remove("hidden");
    $("#login-form [name=username]").focus();
  }

  async function showApp() {
    $("#login-view").classList.add("hidden");
    $("#app-view").classList.remove("hidden");
    $("#user-btn").textContent = state.me.username + " ▾";
    route();
    startPolling();
  }

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    const btn = $("button[type=submit]", f);
    btn.disabled = true;
    $("#login-error").textContent = "";
    try {
      state.me = await api("POST", "/api/v1/auth/login", { username: f.username.value.trim(), password: f.password.value });
      f.password.value = "";
      await showApp();
    } catch (e) {
      $("#login-error").textContent = e.message;
    } finally {
      btn.disabled = false;
    }
  });

  // ---------- routing ----------
  function route() {
    const tab = (location.hash.match(/^#\/(\w+)/) || [])[1] || "endpoints";
    state.tab = ["endpoints", "tokens", "users"].includes(tab) ? tab : "endpoints";
    $$("#tabs a").forEach((a) => a.classList.toggle("active", a.dataset.tab === state.tab));
    $$(".page").forEach((p) => p.classList.toggle("hidden", p.id !== "page-" + state.tab));
    refresh();
  }
  window.addEventListener("hashchange", () => state.me && route());

  // ---------- polling ----------
  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(() => {
      if (!document.hidden && state.tab === "endpoints") refresh();
    }, 3000);
  }
  function stopPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && state.me) refresh(); });

  async function refresh() {
    try {
      if (state.tab === "endpoints") await loadEndpoints();
      else if (state.tab === "tokens") await loadTokens();
      else if (state.tab === "users") await loadUsers();
      loadStatus();
    } catch (e) {
      if (e.status !== 401) toast(e.message, true);
    }
  }

  async function loadStatus() {
    try {
      const s = await api("GET", "/api/v1/status");
      state.status = s;
      const pill = $("#server-pill");
      pill.textContent = `${s.backend} · ${s.version} · up ${s.uptime}`;
      pill.classList.toggle("bad", !!s.reloadError);
      const banner = $("#banner");
      if (s.reloadError) {
        banner.textContent = `Cannot read the ${s.backend} store — running with the last known configuration. ${s.reloadError}`;
        banner.classList.remove("hidden");
      } else banner.classList.add("hidden");
    } catch { /* ignore */ }
  }

  // ---------- endpoints ----------
  async function loadEndpoints() {
    const eps = await api("GET", "/api/v1/endpoints");
    const now = Date.now();
    for (const e of eps) {
      const st = e.status && e.status.stats;
      if (!st) { state.rates.delete(e.name); state.prev.delete(e.name); continue; }
      const p = state.prev.get(e.name);
      if (p && st.rxBytes >= p.rx && st.txBytes >= p.tx) {
        const dt = (now - p.t) / 1000;
        state.rates.set(e.name, { rx: (st.rxBytes - p.rx) / dt, tx: (st.txBytes - p.tx) / dt });
      }
      state.prev.set(e.name, { t: now, rx: st.rxBytes, tx: st.txBytes });
    }
    state.endpoints = eps;
    renderEndpoints();
    if (state.drawer) renderDrawer();
  }

  function stateOf(e) {
    return (e.status && e.status.state) || (e.disabled ? "disabled" : "pending");
  }

  function renderSummary() {
    const eps = state.endpoints;
    let running = 0, errors = 0, sessions = 0, rx = 0, tx = 0, dropped = 0, rrx = 0, rtx = 0;
    for (const e of eps) {
      const s = stateOf(e);
      if (s === "running") running++;
      if (s === "error") errors++;
      const st = e.status && e.status.stats;
      if (st) { sessions += st.sessions; rx += st.rxBytes; tx += st.txBytes; dropped += st.dropped; }
      const r = state.rates.get(e.name);
      if (r) { rrx += r.rx; rtx += r.tx; }
    }
    const card = (k, v, s = "") => `<div class="card"><div class="k">${k}</div><div class="v">${v}</div><div class="s">${s}</div></div>`;
    $("#summary").innerHTML =
      card("Endpoints", `${running}<span class="muted"> / ${eps.length}</span>`, errors ? `<span class="badge err">${errors} failing</span>` : "running") +
      card("Active sessions", num(sessions), "IPv4 clients") +
      card("Traffic in", bytes(rx), rate(rrx) || "idle") +
      card("Traffic out", bytes(tx), `${rate(rtx) || "idle"}${dropped ? ` · ${num(dropped)} dropped` : ""}`);
  }

  function renderEndpoints() {
    renderSummary();
    const f = state.filter.toLowerCase();
    const eps = state.endpoints.filter((e) => !f || [e.name, e.description, e.remoteAddress, String(e.localPort)].some((x) => (x || "").toLowerCase().includes(f)));
    $("#endpoints-empty").classList.toggle("hidden", state.endpoints.length > 0);
    $("#endpoints-table").classList.toggle("hidden", state.endpoints.length === 0);
    $("#endpoints-table tbody").innerHTML = eps.map((e) => {
      const s = stateOf(e);
      const st = (e.status && e.status.stats) || {};
      const r = state.rates.get(e.name) || {};
      const title = s === "error" ? e.status.error : s;
      return `<tr class="clickable ${e.disabled ? "is-disabled" : ""}" data-name="${esc(e.name)}">
        <td><div class="name-cell"><span class="dot ${s}" title="${esc(title)}"></span><div>
          <div class="n">${esc(e.name)}${e.wireguard ? '<span class="badge">WG</span>' : ""}${s === "error" ? '<span class="badge err">error</span>' : ""}${e.disabled ? '<span class="badge off">disabled</span>' : ""}</div>
          ${e.description ? `<div class="d">${esc(e.description)}</div>` : ""}</div></div></td>
        <td class="mono">${esc(listenOf(e))}</td>
        <td class="arrow">→</td>
        <td class="mono">${esc(remoteOf(e))}</td>
        <td class="num">${st.sessions ?? "—"}</td>
        <td class="num">${st.rxBytes !== undefined ? bytes(st.rxBytes) : "—"}<span class="rate">${rate(r.rx)}</span></td>
        <td class="num">${st.txBytes !== undefined ? bytes(st.txBytes) : "—"}<span class="rate">${rate(r.tx)}</span></td>
        <td class="num">${st.dropped !== undefined ? num(st.dropped) : "—"}</td>
        <td class="actions">
          <label class="switch" title="${e.disabled ? "Enable" : "Disable"}"><input type="checkbox" data-action="toggle" ${e.disabled ? "" : "checked"} aria-label="Enabled"><span></span></label>
          <button class="btn sm" data-action="edit">Edit</button>
          <button class="btn sm danger" data-action="delete">Delete</button>
        </td></tr>`;
    }).join("");
  }

  $("#filter").addEventListener("input", (ev) => { state.filter = ev.target.value; renderEndpoints(); });

  $("#endpoints-table tbody").addEventListener("click", async (ev) => {
    const tr = ev.target.closest("tr");
    if (!tr) return;
    const e = state.endpoints.find((x) => x.name === tr.dataset.name);
    if (!e) return;
    const action = ev.target.closest("[data-action]")?.dataset.action;
    if (action === "toggle") {
      ev.stopPropagation();
      const input = ev.target;
      input.disabled = true;
      try {
        await api("PATCH", `/api/v1/endpoints/${encodeURIComponent(e.name)}`, { disabled: !input.checked });
        toast(`${e.name} ${input.checked ? "enabled" : "disabled"}`);
        await loadEndpoints();
      } catch (err) {
        input.checked = !input.checked;
        toast(err.message, true);
      } finally { input.disabled = false; }
      return;
    }
    if (action === "edit") return endpointForm(e);
    if (action === "delete") return confirmDelete(e);
    if (ev.target.closest(".switch")) return;
    openDrawer(e.name);
  });

  function endpointFields(e) {
    return `
      <label>Name<input name="name" value="${esc(e.name)}" required maxlength="63" placeholder="wg-frankfurt" autocomplete="off"></label>
      <label>Description<input name="description" value="${esc(e.description)}" maxlength="200"><span class="hint">Optional note shown in the list.</span></label>
      <fieldset><legend>Listen (IPv4)</legend>
        <div class="row3">
          <label>Address<input name="listenAddress" value="${esc(e.listenAddress)}" placeholder="0.0.0.0"><span class="hint">Empty = all interfaces</span></label>
          <label>Port<input name="localPort" type="number" min="1" max="65535" value="${esc(e.localPort)}" required></label>
        </div>
      </fieldset>
      <fieldset><legend>Forward to (IPv6)</legend>
        <div class="row3">
          <label>Address or hostname<input name="remoteAddress" value="${esc(e.remoteAddress)}" placeholder="2001:db8::1" required></label>
          <label>Port<input name="remotePort" type="number" min="1" max="65535" value="${esc(e.remotePort)}" required></label>
        </div>
      </fieldset>
      <div class="row2">
        <label>Idle timeout (s)<input name="idleTimeout" type="number" min="0" max="86400" value="${esc(e.idleTimeout || 0)}"><span class="hint">Session lifetime without traffic. 0 = 180</span></label>
        <div>
          <label class="check"><input type="checkbox" name="wireguard" ${e.wireguard ? "checked" : ""}><span>WireGuard only<span class="hint">Drop anything that isn't a well-formed WireGuard packet.</span></span></label>
          <label class="check"><input type="checkbox" name="enabled" ${e.disabled ? "" : "checked"}><span>Enabled</span></label>
        </div>
      </div>`;
  }

  function readEndpointForm(form) {
    const v = (n) => form.elements[n].value.trim();
    const int = (n) => (v(n) === "" ? 0 : Number(v(n)));
    return {
      name: v("name"),
      description: v("description"),
      listenAddress: v("listenAddress"),
      localPort: int("localPort"),
      remoteAddress: v("remoteAddress"),
      remotePort: int("remotePort"),
      idleTimeout: int("idleTimeout"),
      wireguard: form.elements.wireguard.checked,
      disabled: !form.elements.enabled.checked,
    };
  }

  function endpointForm(existing) {
    const isNew = !existing;
    const e = existing || { name: "", description: "", listenAddress: "", localPort: "", remoteAddress: "", remotePort: 51820, wireguard: true, disabled: false, idleTimeout: 0 };
    openModal(isNew ? "New endpoint" : `Edit ${e.name}`, endpointFields(e), isNew ? "Create" : "Save", async (form) => {
      const body = readEndpointForm(form);
      if (isNew) await api("POST", "/api/v1/endpoints", body);
      else await api("PUT", `/api/v1/endpoints/${encodeURIComponent(e.name)}`, body);
      toast(isNew ? `Endpoint ${body.name} created` : `Endpoint ${body.name} saved`);
      if (!isNew && state.drawer === e.name) state.drawer = body.name;
      await loadEndpoints();
    });
  }

  function confirmDelete(e) {
    openModal(`Delete ${e.name}?`,
      `<p>This stops the listener on <code>${esc(listenOf(e))}</code> and disconnects ${(e.status && e.status.stats && e.status.stats.sessions) || 0} active session(s). This cannot be undone.</p>`,
      "Delete", async () => {
        await api("DELETE", `/api/v1/endpoints/${encodeURIComponent(e.name)}`);
        toast(`Endpoint ${e.name} deleted`);
        if (state.drawer === e.name) closeDrawer();
        await loadEndpoints();
      }, true);
  }

  // ---------- drawer ----------
  function openDrawer(name) {
    state.drawer = name;
    $("#drawer").classList.remove("hidden");
    renderDrawer();
  }
  function closeDrawer() {
    state.drawer = null;
    $("#drawer").classList.add("hidden");
  }

  async function renderDrawer() {
    const e = state.endpoints.find((x) => x.name === state.drawer);
    if (!e) return closeDrawer();
    const s = stateOf(e);
    const st = (e.status && e.status.stats) || {};
    $("#drawer-title").innerHTML = `${esc(e.name)} ${e.wireguard ? '<span class="badge">WireGuard</span>' : ""}`;
    $("#drawer-sub").textContent = e.description || "";
    let sessions = [];
    if (s === "running") {
      try { sessions = await api("GET", `/api/v1/endpoints/${encodeURIComponent(e.name)}/sessions`); } catch { /* ignore */ }
    }
    if (state.drawer !== e.name) return;
    const card = (k, v) => `<div class="card"><div class="k">${k}</div><div class="v">${v}</div></div>`;
    $("#drawer-body").innerHTML = `
      ${s === "error" ? `<div class="error-box">${esc(e.status.error)}</div>` : ""}
      <dl class="kv">
        <dt>Status</dt><dd><span class="dot ${s}"></span> ${esc(s)} ${e.status ? `<span class="muted">since ${esc(ago(e.status.since))}</span>` : ""}</dd>
        <dt>Listen</dt><dd class="mono">${esc(listenOf(e))}</dd>
        <dt>Remote</dt><dd class="mono">${esc(remoteOf(e))}${st.remote && st.remote !== remoteOf(e) ? ` <span class="muted">→ ${esc(st.remote)}</span>` : ""}</dd>
        <dt>Idle timeout</dt><dd>${e.idleTimeout || 180}s</dd>
        <dt>Sessions total</dt><dd>${num(st.sessionsTotal)}</dd>
      </dl>
      <div class="stat-grid">
        ${card("Packets in", num(st.rxPackets))}${card("Packets out", num(st.txPackets))}${card("Dropped", num(st.dropped))}
        ${card("Bytes in", bytes(st.rxBytes))}${card("Bytes out", bytes(st.txBytes))}${card("Errors", num(st.errors))}
      </div>
      <h3>Active sessions (${sessions.length})</h3>
      ${sessions.length ? `<div class="table-wrap"><table class="table">
        <thead><tr><th>Client (IPv4)</th><th>Upstream (IPv6)</th><th class="num">In</th><th class="num">Out</th><th class="num">Last seen</th></tr></thead>
        <tbody>${sessions.map((x) => `<tr>
          <td class="mono">${esc(x.client)}</td><td class="mono">${esc(x.upstream)}</td>
          <td class="num">${bytes(x.rxBytes)}</td><td class="num">${bytes(x.txBytes)}</td><td class="num">${esc(ago(x.lastSeen))}</td></tr>`).join("")}
        </tbody></table></div>` : `<p class="muted">No clients connected.</p>`}
      <p><button class="btn" data-action="drawer-edit">Edit endpoint</button></p>`;
  }

  // ---------- tokens ----------
  async function loadTokens() {
    const toks = await api("GET", "/api/v1/tokens");
    $("#tokens-table tbody").innerHTML = toks.length ? toks.map((t) => `<tr data-id="${esc(t.id)}">
      <td><strong>${esc(t.name)}</strong></td><td class="mono">${esc(t.hint)}</td><td>${esc(t.username)}</td>
      <td>${esc(date(t.created))}</td><td>${esc(ago(t.lastUsed))}</td>
      <td>${t.expires ? (new Date(t.expires) < new Date() ? '<span class="badge err">expired</span>' : esc(date(t.expires))) : '<span class="muted">never</span>'}</td>
      <td class="actions"><button class="btn sm danger" data-action="revoke">Revoke</button></td></tr>`).join("")
      : `<tr><td colspan="7" class="muted">No tokens yet.</td></tr>`;
    $$("#tokens-table [data-action=revoke]").forEach((b) => b.addEventListener("click", () => {
      const id = b.closest("tr").dataset.id;
      const t = toks.find((x) => x.id === id);
      openModal(`Revoke “${t.name}”?`, `<p>Anything using this token will immediately lose access.</p>`, "Revoke", async () => {
        await api("DELETE", `/api/v1/tokens/${encodeURIComponent(id)}`);
        toast("Token revoked");
        await loadTokens();
      }, true);
    }));
  }

  function newToken() {
    openModal("New API token", `
      <label>Name<input name="name" required maxlength="64" autocomplete="off"><span class="hint">What will use it, e.g. “laptop CLI”.</span></label>
      <label>Expires after (days)<input name="ttlDays" type="number" min="0" max="3650" value="90"><span class="hint">0 = never</span></label>`,
    "Create", async (form) => {
      const t = await api("POST", "/api/v1/tokens", { name: form.elements.name.value.trim(), ttlDays: Number(form.elements.ttlDays.value || 0) });
      await loadTokens();
      showSecret(t.token);
      return false; // keep modal open (content replaced)
    });
  }

  function showSecret(token) {
    const origin = location.origin;
    openModal("Token created", `
      <p>Copy it now — it won't be shown again.</p>
      <div class="secret"><code id="secret">${esc(token)}</code><button type="button" class="btn sm" data-action="copy">Copy</button></div>
      <p class="muted">Use it with the CLI:</p>
      <div class="secret"><code>udp6proxy login --server ${esc(origin)} --token ${esc(token)}</code></div>`,
    "Done", async () => {}, false, true);
  }

  // ---------- users ----------
  async function loadUsers() {
    const users = await api("GET", "/api/v1/users");
    $("#users-table tbody").innerHTML = users.map((u) => `<tr data-name="${esc(u.username)}">
      <td><strong>${esc(u.username)}</strong>${u.username === state.me.username ? ' <span class="badge">you</span>' : ""}</td>
      <td>${esc(date(u.created))}</td>
      <td class="actions"><button class="btn sm" data-action="reset">Set password</button>
      ${u.username === state.me.username ? "" : '<button class="btn sm danger" data-action="del">Delete</button>'}</td></tr>`).join("");
    $$("#users-table [data-action]").forEach((b) => b.addEventListener("click", () => {
      const name = b.closest("tr").dataset.name;
      if (b.dataset.action === "reset") {
        openModal(`Set password for ${name}`, `<label>New password<input name="password" type="password" minlength="8" required autocomplete="new-password"><span class="hint">At least 8 characters.</span></label>`,
          "Save", async (form) => {
            await api("PUT", `/api/v1/users/${encodeURIComponent(name)}/password`, { password: form.elements.password.value });
            toast("Password updated");
          });
      } else {
        openModal(`Delete ${name}?`, `<p>The user and all of their API tokens will be removed.</p>`, "Delete", async () => {
          await api("DELETE", `/api/v1/users/${encodeURIComponent(name)}`);
          toast(`User ${name} deleted`);
          await loadUsers();
        }, true);
      }
    }));
  }

  function newUser() {
    openModal("New user", `
      <label>Username<input name="username" required maxlength="32" autocomplete="off"></label>
      <label>Password<input name="password" type="password" minlength="8" required autocomplete="new-password"><span class="hint">At least 8 characters.</span></label>`,
    "Create", async (form) => {
      await api("POST", "/api/v1/users", { username: form.elements.username.value.trim(), password: form.elements.password.value });
      toast("User created");
      await loadUsers();
    });
  }

  function changePassword() {
    openModal("Change password", `
      <label>Current password<input name="current" type="password" required autocomplete="current-password"></label>
      <label>New password<input name="new" type="password" minlength="8" required autocomplete="new-password"><span class="hint">At least 8 characters. You'll need to sign in again.</span></label>`,
    "Change", async (form) => {
      await api("POST", "/api/v1/me/password", { current: form.elements.current.value, new: form.elements.new.value });
      toast("Password changed — please sign in again");
      showLogin();
    });
  }

  // ---------- modal ----------
  function openModal(title, bodyHTML, submitLabel, onSubmit, danger = false, noCancel = false) {
    $("#modal-title").textContent = title;
    $("#modal-body").innerHTML = bodyHTML;
    $("#modal-error").textContent = "";
    const submit = $("#modal-submit");
    submit.textContent = submitLabel;
    submit.className = "btn " + (danger ? "danger-solid" : "primary");
    $("#modal [data-action=close-modal]").classList.toggle("hidden", noCancel);
    state.modalSubmit = onSubmit;
    $("#modal").classList.remove("hidden");
    const first = $("#modal-body input:not([type=checkbox])");
    (first || submit).focus();
  }
  function closeModal() {
    $("#modal").classList.add("hidden");
    state.modalSubmit = null;
  }

  $("#modal-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!state.modalSubmit) return closeModal();
    const form = ev.target;
    $$("[aria-invalid]", form).forEach((el) => el.removeAttribute("aria-invalid"));
    $$(".field-error", form).forEach((el) => el.remove());
    $("#modal-error").textContent = "";
    const submit = $("#modal-submit");
    submit.disabled = true;
    const fn = state.modalSubmit;
    try {
      const keep = await fn(form);
      if (keep !== false && state.modalSubmit === fn) closeModal();
    } catch (e) {
      let placed = false;
      for (const [field, msg] of Object.entries(e.fields || {})) {
        const input = form.elements[field];
        if (!input || !input.closest) continue;
        input.setAttribute("aria-invalid", "true");
        const span = document.createElement("span");
        span.className = "field-error";
        span.textContent = msg;
        input.closest("label").appendChild(span);
        placed = true;
      }
      $("#modal-error").textContent = placed && e.message === "validation failed" ? "Please fix the highlighted fields." : e.message;
    } finally {
      submit.disabled = false;
    }
  });

  // ---------- global actions ----------
  document.addEventListener("click", async (ev) => {
    const el = ev.target.closest("[data-action]");
    const menu = $("#user-menu");
    if (!ev.target.closest(".menu")) menu.classList.add("hidden");
    if (!el) return;
    switch (el.dataset.action) {
      case "new-endpoint": return endpointForm(null);
      case "new-token": return newToken();
      case "new-user": return newUser();
      case "close-modal": return closeModal();
      case "close-drawer": return closeDrawer();
      case "drawer-edit": {
        const e = state.endpoints.find((x) => x.name === state.drawer);
        return e && endpointForm(e);
      }
      case "copy": {
        const text = $("#secret").textContent;
        try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed — select and copy manually", true); }
        return;
      }
      case "change-password": menu.classList.add("hidden"); return changePassword();
      case "logout":
        await api("POST", "/api/v1/auth/logout").catch(() => {});
        return showLogin();
    }
  });
  $("#user-btn").addEventListener("click", () => $("#user-menu").classList.toggle("hidden"));
  $("#modal").addEventListener("mousedown", (ev) => { if (ev.target.id === "modal") closeModal(); });
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    if (!$("#modal").classList.contains("hidden")) closeModal();
    else if (state.drawer) closeDrawer();
  });

  // ---------- boot ----------
  (async () => {
    try {
      state.me = await api("GET", "/api/v1/me");
      await showApp();
    } catch {
      showLogin();
    }
  })();
})();
