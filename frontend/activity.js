/* NeuroSwarm · Activity map (portable, multi-host).
   Shows, per organization, what agents did on each enrolled machine, inside the folders each machine opted in to share.
   Data: GET /api/v1/activity (ACTIVITY-CONTRACT v1). No product, team or path is assumed. CSP-safe: no inline handlers. */
(() => {
  const root = document.getElementById("activity-map");
  if (!root) return;
  const app = document.getElementById("app-view");
  root.innerHTML = `<div class="ap-skeleton" role="status" aria-label="Loading agent activity"><span></span><span></span><span></span><span></span></div>`;
  const H = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const CAT_ORDER = ["file_edit", "shell", "file_read", "think", "plan", "web", "coordination", "visual", "other"];
  const CAT_ALIAS = { shell_exec: "shell", web_research: "web", visual_asset: "visual", reasoning: "think" };
  const CAT_LABEL = { file_edit: "Edit files", file_read: "Read files", shell: "Run commands", web: "Web & browser",
    coordination: "Coordinate", plan: "Plan", think: "Reason", visual: "Images", other: "Other" };
  const SUBSTANTIVE = new Set(["file_edit", "shell", "file_read", "web", "visual"]);
  const VIEWS = [["overview", "Overview"], ["timeline", "Timeline"], ["sessions", "Sessions"], ["folders", "Folders"]];
  const WINDOWS = [[900, "15 min"], [3600, "1 h"], [21600, "6 h"], [86400, "24 h"]];
  const _initParams = new URLSearchParams(window.location.search);
  const _initView = VIEWS.some(([v]) => v === _initParams.get("am_view")) ? _initParams.get("am_view") : (_initParams.get("am_session") ? "sessions" : "overview");
  const _initSpan = WINDOWS.some(([w]) => String(w) === _initParams.get("am_span")) ? Number(_initParams.get("am_span")) : 3600;
  const state = { host: _initParams.get("am_host") || "all", agent: _initParams.get("am_agent") || "all", data: null,
                  open: new Set(_initParams.get("am_session") ? [_initParams.get("am_session")] : []),
                  opener: null, view: _initView, query: (_initParams.get("am_q") || "").trim(),
                  span: _initSpan, print: "", known: null, fresh: new Set(), intro: true,
                  highlightSession: _initParams.get("am_session") || "", fromTaskId: _initParams.get("task") || "", linksBySession: {} };

  function syncActivityUrl() {
    if (!window.history?.replaceState) return;
    const u = new URL(window.location.href);
    if (state.view && state.view !== "overview") u.searchParams.set("am_view", state.view); else u.searchParams.delete("am_view");
    if (state.host && state.host !== "all") u.searchParams.set("am_host", state.host); else u.searchParams.delete("am_host");
    if (state.agent && state.agent !== "all") u.searchParams.set("am_agent", state.agent); else u.searchParams.delete("am_agent");
    if (state.query) u.searchParams.set("am_q", state.query); else u.searchParams.delete("am_q");
    if (state.span && state.span !== 3600) u.searchParams.set("am_span", String(state.span)); else u.searchParams.delete("am_span");
    if (state.highlightSession) u.searchParams.set("am_session", state.highlightSession); else u.searchParams.delete("am_session");
    window.history.replaceState(null, "", u.pathname + (u.search ? u.search : "") + u.hash);
  }

  function liveHrefForSession(s, filePath = "", taskId = "") {
    syncActivityUrl();
    const cur = new URL(window.location.href);
    cur.searchParams.delete("return_to");
    const fromUrl = "/" + (cur.searchParams.toString() ? "?" + cur.searchParams.toString() : "") + "#activity";
    const qs = new URLSearchParams();
    if (taskId) qs.set("task", taskId);
    if (s.session_id) qs.set("session", s.session_id);
    if (s.host_id) qs.set("host", s.host_id);
    if (s.agent_name) qs.set("agent", s.agent_name);
    if (s.harness) qs.set("runtime", s.harness);
    if (filePath) qs.set("file", filePath);
    qs.set("from", fromUrl);
    return `/live?${qs.toString()}`;
  }

  function renderSessionLinksBar(s, d, filePath = "") {
    const linked = Array.isArray(state.linksBySession[s.session_id]) ? state.linksBySession[s.session_id] : [];
    const primaryTask = linked.length === 1 ? linked[0].task_id : "";
    const liveHref = liveHrefForSession(s, filePath, primaryTask);
    const taskChips = linked.length
      ? linked
          .map(
            (lk) => `<button type="button" class="link-hop-btn" data-focus-task="${H(lk.task_id)}" title="Open linked assignment (${H(lk.basis)})">Assignment: ${H(lk.title.length > 42 ? lk.title.slice(0, 41) + "…" : lk.title)} ↗</button>`
          )
          .join("")
      : `<span class="link-none-chip" data-session-link="unknown">Assignment link: Unknown</span>`;
    return `<div class="link-strip ${linked.length ? "is-linked" : "is-unknown"}" data-session-link-bar="${H(s.session_id)}">
      ${taskChips}
      <a href="${H(liveHref)}" class="link-hop-btn is-file">Open in Live NOC ↗</a>
    </div>`;
  }
  const reduceMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const stepKey = (s, st) => JSON.stringify([s.host_id, s.session_id, st.src || [st.time, st.label]]);

  const ago = ts => {
    const s = Math.max(0, Date.now() / 1000 - Number(ts || 0));
    if (!ts) return "unknown";
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  };
  const clock = iso => String(iso || "").slice(11, 16);
  const cat = c => CAT_ALIAS[c] || (CAT_LABEL[c] ? c : "other");
  const agentKey = s => `${s.host_id || ""}|${s.agent_id || s.agent_name || s.harness}`;
  /* Names that share a long prefix ("team-research-alpha", "team-research-beta") are shown by what differs ("alpha"). */
  let SHORT = new Map();
  function buildShortNames(names) {
    SHORT = new Map();
    const groups = new Map();
    for (const n of new Set(names)) { const g = n.split(/[-_ .]/)[0]; groups.set(g, [...(groups.get(g) || []), n]); }
    for (const list of groups.values()) {
      if (list.length < 2) continue;
      let p = list.reduce((a, b) => { let i = 0; while (i < a.length && a[i] === b[i]) i++; return a.slice(0, i); });
      p = p.slice(0, Math.max(p.search(/[-_ .][^-_ .]*$/) + 1, 0));
      if (p.length >= 6 && list.every(n => n.length - p.length >= 2)) for (const n of list) SHORT.set(n, n.slice(p.length));
    }
  }
  const short = n => SHORT.get(n) || n;

  /* ---------- normalize one snapshot (local or aggregated remote) ---------- */
  function normalize(d) {
    d.hosts = Array.isArray(d.hosts) && d.hosts.length ? d.hosts : (d.host_id ? [{ host_id: d.host_id, hostname: d.hostname || d.host_id,
      activity_roots: d.activity_roots || [], activity_enabled: d.activity_enabled !== false, updated_at: d.collected_at }] : []);
    for (const h of d.hosts) {
      h.activity_roots = Array.isArray(h.activity_roots) ? h.activity_roots : [];
      if (h.activity_enabled === undefined) h.activity_enabled = h.activity_roots.length > 0;
    }
    d.sessions = (d.sessions || []).map(s => {
      s.steps = (s.steps || []).map(st => ({ ...st, category: cat(st.category) }));
      s.plan = s.plan || []; s.how = s.how || {};
      for (const k of ["files_edited", "files_read", "files_delivered"]) s[k] = s[k] || [];
      s.host_id = s.host_id || (d.hosts[0] || {}).host_id || "";
      const work = s.latest_work || [...s.steps].reverse().find(st => SUBSTANTIVE.has(st.category)) || s.latest_action || s.steps.at(-1);
      s.latest_work = work ? { ...work, category: cat(work.category) } : null;
      return s;
    });
    d.workspaces = d.workspaces || [];
    d.harnesses = d.harnesses || [];
    return d;
  }
  const machineLabel = h => h.hostname && h.hostname !== h.host_id ? `${h.hostname} (${h.host_id})` : h.host_id;
  const hostName = (d, id) => machineLabel(d.hosts.find(h => h.host_id === id) || {host_id: id}) || "this machine";
  const multiHost = d => d.hosts.length > 1;

  /* Paths are shown relative to the shared folder that contains them: "<folder>/<rest>". */
  function rootsOf(d) {
    const roots = [];
    for (const w of d.workspaces) if (w.path) roots.push([w.path, w.label || w.path.split(/[\\/]/).pop()]);
    for (const h of d.hosts) for (const r of h.activity_roots) roots.push([r, String(r).split(/[\\/]/).filter(Boolean).pop() || r]);
    return roots.sort((a, b) => b[0].length - a[0].length);
  }
  function rel(path, d) {
    const p = String(path || "");
    for (const [r, label] of rootsOf(d)) {
      if (p === r) return label;
      if (p.startsWith(r.replace(/[\\/]$/, "") + "/") || p.startsWith(r.replace(/[\\/]$/, "") + "\\")) return `${label}/${p.slice(r.replace(/[\\/]$/, "").length + 1)}`;
    }
    return p.split(/[\\/]/).slice(-2).join("/");
  }

  /* ---------- provider mark (recorded vs inferred) ---------- */
  const PROVIDER_PATH = {
    openai: "M12 3l8 4.5v9L12 21l-8-4.5v-9z M4 7.5l8 4.5 8-4.5 M12 12v9", anthropic: "M3 19l6-14 6 14 M5 15h8 M15 5l6 14",
    google: "M12 2c1 5 5 9 10 10-5 1-9 5-10 10-1-5-5-9-10-10 5-1 9-5 10-10z", zai: "M4 6h16L4 18h16 M7 12h9",
    deepseek: "M3 11q6 5 13-1l4-4v6q-1 7-9 7-5 0-8-8z", azure: "M4 19l7-15h4l6 15h-9l4-3-4-8-5 11z",
    ollama: "M6 11V4q5 0 5 7h3q0-7 5-7v11q0 5-7 5t-6-9z", openrouter: "M3 12h5q3 0 6-5l3-2h4 M8 12q3 0 6 5l3 2h4",
    opencode: "M4 4h16v16H4z M8 9l3 3-3 3 M13 15h3", xai: "M4 4l16 16 M20 4L4 20", mistral: "M4 4h4v4h8V4h4v16h-4v-8H8v8H4z",
    unknown: "M5 7h14v11H5z M8 4v3 M16 4v3 M8 12h2 M14 12h2" };
  function providerMark(s, inMap = false) {
    const id = s.provider || s.provider_id || "";
    const key = id === "zai-coding-plan" ? "zai" : (PROVIDER_PATH[id] ? id : "unknown");
    const basis = s.provider_basis || (id ? "recorded" : "unknown");
    const label = key === "unknown" ? "Provider unreported" : (s.provider_label || id) + (basis === "model" ? " model" : "");
    const title = basis === "recorded" ? `Provider recorded by the harness: ${s.provider_label || id}`
      : basis === "model" ? "Inferred from the model name; the harness did not record the provider" : "The harness did not record a provider";
    if (inMap) return `<svg x="5" y="7" width="20" height="20" viewBox="0 0 24 24" class="am-map-provider"><title>${H(title)}</title><path d="${PROVIDER_PATH[key]}"/></svg>`;
    return `<span class="am-provider am-vendor-${H(key)}" title="${H(title)}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${PROVIDER_PATH[key]}"/></svg>${H(label)}<span class="sr-only"> (${H(title)})</span></span>`;
  }

  /* ---------- flow: machine → harness → agent → shared folder ---------- */
  function flow(d, sessions) {
    const hosts = d.hosts.filter(h => state.host === "all" || h.host_id === state.host);
    const harn = [], agents = [], ws = [];
    const links = new Set();
    for (const s of sessions) {
      const hk = `${s.host_id}|${s.harness_name}`, ak = agentKey(s), wk = `${s.host_id}|${s.workspace}`;
      if (!harn.some(x => x.k === hk)) harn.push({ k: hk, name: s.harness_name, host: s.host_id });
      if (!agents.some(x => x.k === ak)) agents.push({ k: ak, name: s.agent_name, active: false, last: 0, s });
      const a = agents.find(x => x.k === ak); a.active ||= s.status === "active"; a.last = Math.max(a.last, s.updated_at || 0);
      if (s.workspace && !ws.some(x => x.k === wk)) ws.push({ k: wk, name: rel(s.workspace, d), host: s.host_id });
      links.add(`h:${s.host_id}>r:${hk}`); links.add(`r:${hk}>a:${ak}`); if (s.workspace) links.add(`a:${ak}>w:${wk}`);
    }
    const cols = [hosts.map(h => ({ id: `h:${h.host_id}`, title: machineLabel(h), sub: h.activity_enabled ? `${h.activity_roots.length} shared folder(s)` : "health only", cls: h.activity_enabled ? "running" : "idle" })),
      harn.map(r => ({ id: `r:${r.k}`, title: r.name, sub: multiHost(d) ? hostName(d, r.host) : "harness", cls: "running" })),
      agents.map(a => ({ id: `a:${a.k}`, title: short(a.name), sub: `${a.active ? "active" : "idle"} · ${ago(a.last)}`, cls: `${a.active ? "active" : "idle"} agent${state.agent === a.k ? " selected" : ""}${state.agent !== "all" && state.agent !== a.k ? " dim" : ""}`, agent: a.k, s: a.s })),
      ws.map(w => ({ id: `w:${w.k}`, title: short(w.name), sub: multiHost(d) ? hostName(d, w.host) : "shared folder", cls: "ws" }))];
    const rowH = 46, top = 34, W = 1000, boxW = 214, boxH = 34, colX = [8, 268, 528, 778];
    const rows = Math.max(1, ...cols.map(c => c.length));
    const pos = {};
    cols.forEach(c => c.forEach((n, i) => pos[n.id] = top + i * rowH + (rows - c.length) * rowH / 2));
    const colOf = id => ({ h: 0, r: 1, a: 2, w: 3 })[id[0]];
    let paths = "";
    for (const l of links) {
      const [from, to] = l.split(">");
      if (pos[from] === undefined || pos[to] === undefined) continue;
      const x1 = colX[colOf(from)] + boxW, x2 = colX[colOf(to)], y1 = pos[from] + boxH / 2, y2 = pos[to] + boxH / 2;
      const on = state.agent === "all" || l.includes(`a:${state.agent}`) ? "on" : "off";
      paths += `<path class="am-link ${on}" data-from="${H(from)}" data-to="${H(to)}" d="M${x1} ${y1} C${(x1 + x2) / 2} ${y1} ${(x1 + x2) / 2} ${y2} ${x2} ${y2}"/>`;
    }
    const nodes = cols.flatMap((c, ci) => c.map(n => `<g class="am-node ${n.cls}" data-node="${H(n.id)}" transform="translate(${colX[ci]} ${pos[n.id]})"${n.agent ? ` data-agent="${H(n.agent)}" tabindex="0" role="button" aria-pressed="${state.agent === n.agent}" aria-label="Show only ${H(n.title)}"` : ""}>
      <rect width="${boxW}" height="${boxH}" rx="5"/>${n.s ? providerMark(n.s, true) : `<circle cx="15" cy="${boxH / 2}" r="4.5"/>`}
      <text x="30" y="14">${H(n.title.length > 28 ? n.title.slice(0, 27) + "…" : n.title)}</text><text class="sub" x="30" y="27">${H(n.sub)}</text><title>${H(n.title)} · ${H(n.sub)}</title></g>`)).join("");
    const head = ["Machine", "Harness", "Agent", "Shared folder"].map((t, i) => `<text class="am-col" x="${colX[i]}" y="16">${t}</text>`).join("");
    return `<div class="am-flow${state.intro && !reduceMotion() ? " ap-intro" : ""}"><svg viewBox="0 0 ${W} ${top + rows * rowH + 6}" role="img" aria-label="Which harness each agent used on each machine, and which shared folder it worked in">${head}${paths}${nodes}</svg></div>`;
  }

  /* ---------- cards ---------- */
  function mix(how) {
    const counts = {};
    for (const [k, v] of Object.entries(how || {})) counts[cat(k)] = (counts[cat(k)] || 0) + Number(v || 0);
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (!total) return '<p class="muted small">No tool steps in the latest part of this session.</p>';
    const keys = CAT_ORDER.filter(k => counts[k]);
    return `<div class="am-bar" role="img" aria-label="${H(keys.map(k => `${CAT_LABEL[k]} ${counts[k]}`).join(", "))}">${keys.map(k => `<span class="am-seg c-${k}" style="flex:${counts[k]}"></span>`).join("")}</div>
      <div class="am-legend">${keys.map(k => `<span><i class="c-${k}" aria-hidden="true"></i>${CAT_LABEL[k]} ${counts[k]}</span>`).join("")}</div>`;
  }
  function fileList(title, list, d, cls, basis) {
    if (!list || !list.length) return "";
    return `<div class="am-files ${cls}"><h5>${H(title)} <span class="muted">${list.length}</span>${basis ? ` ${basis}` : ""}</h5><ul>${list.map(p => {
      const r = rel(p, d), i = r.lastIndexOf("/");
      return `<li title="${H(r)}"><strong>${H(r.slice(i + 1))}</strong> <span class="dir">${H(i > 0 ? r.slice(0, i) : "")}</span></li>`;
    }).join("")}</ul></div>`;
  }
  const evidence = b => b === "confirmed"
    ? '<span class="ap-evidence ok" title="A completed edit or read in the harness record names this file">Confirmed by the record</span>'
    : b === "mentioned" ? '<span class="ap-evidence" title="The file is named in the plan text; no edit record">Mentioned only</span>'
      : '<span class="ap-evidence" title="The file appears in the session record, not tied to a completed step">In session record</span>';
  const btn = (s, d, kind, i, text) => `<button type="button" class="am-inspect" data-session="${d.sessions.indexOf(s)}" data-kind="${kind}" data-index="${i}" aria-haspopup="dialog">${H(text)}</button>`;

  function card(s, d) {
    const icon = { completed: "✓", in_progress: "◐", pending: "○" };
    const plan = s.plan.length ? `<ul class="am-plan">${s.plan.map((p, i) => `<li class="${H(p.status)}"><span aria-hidden="true">${icon[p.status] || "○"}</span>${btn(s, d, "plan", i, p.text)}<span class="sr-only"> (${H(String(p.status).replace("_", " "))})</span></li>`).join("")}</ul>`
      : '<p class="muted small">No checklist recorded in this session.</p>';
    const steps = s.steps.length ? `<ol class="am-steps">${s.steps.map((st, i) => `<li><i class="c-${H(st.category)}" aria-hidden="true"></i><span class="sr-only">${H(CAT_LABEL[st.category])}: </span><time>${H(clock(st.time))}</time>${btn(s, d, "step", i, st.label)}${st.status === "error" ? ' <span class="ap-evidence bad">Failed</span>' : ""}</li>`).join("")}</ol>` : "";
    const latestKey = s.latest_work && stepKey(s, s.latest_work);
    const matches = latestKey ? s.steps.filter(st => stepKey(s, st) === latestKey) : [];
    const wi = matches.length === 1 ? s.steps.indexOf(matches[0]) : -1;
    const quick = s.latest_work ? (wi >= 0 ? btn(s, d, "step", wi, s.latest_work.label) : `<span>${H(s.latest_work.label)}</span>`) : "";
    const id = s.session_id;
    const isHl = Boolean(state.highlightSession && state.highlightSession === id);
    const linkBar = renderSessionLinksBar(s, d, (s.files_edited || [])[0] ? rel(s.files_edited[0], d) : "");
    return `<article class="am-agent-card"><details class="am-session ${H(s.status)}${isHl ? " is-linked-target" : ""}" data-open-key="${H(id)}"${state.open.has(id) || isHl ? " open" : ""}>
      <summary><span class="pill ${s.status === "active" ? "running" : "waiting"}">${s.status === "active" ? "Active" : "Idle"}</span>
        <strong>${H(s.agent_name)}</strong>${providerMark(s)}<span class="muted small">${H(s.harness_name)}${s.model ? " · " + H(s.model) : ""}${multiHost(d) ? " · " + H(hostName(d, s.host_id)) : ""} · ${H(ago(s.updated_at))}</span>
        <span class="am-what">${H(s.what_done)}</span></summary>
      ${linkBar}
      <div class="am-grid">
        <section><h4>What it did</h4><p>${H(s.what_done)}</p>
          <p class="muted small">Folder <code>${H(rel(s.workspace, d) || "unreported")}</code> · machine ${H(hostName(d, s.host_id))}${s.tokens_used ? ` · ${Number(s.tokens_used).toLocaleString()} tokens` : ""}</p></section>
        <section><h4>What it plans</h4>${plan}</section>
        <section><h4>How it worked</h4>${mix(s.how)}${steps}</section>
        <section><h4>Files</h4>${fileList("Edited", s.files_edited, d, "edited", evidence("confirmed")) + fileList("Delivered", s.files_delivered, d, "delivered") + fileList("Read", s.files_read, d, "read")
          || '<p class="muted small">No file inside the shared folders appears in the latest part of this session.</p>'}</section>
      </div></details>${quick ? `<div class="am-quick"><span>Latest work</span>${quick}</div>` : ""}</article>`;
  }

  /* ---------- detail dialog ---------- */
  const dialog = document.createElement("dialog");
  dialog.className = "am-detail";
  dialog.setAttribute("aria-labelledby", "am-detail-title");
  root.after(dialog);
  dialog.addEventListener("click", e => {
    const focusTask = e.target.closest("[data-focus-task]");
    if (focusTask) {
      const tid = focusTask.dataset.focusTask;
      dialog.close();
      document.dispatchEvent(new CustomEvent("swarm-focus-task", { detail: { taskId: tid } }));
      return;
    }
    if (e.target === dialog || e.target.closest("[data-close]")) dialog.close();
  });
  dialog.addEventListener("close", () => { state.opener?.focus?.(); state.opener = null; });

  // The map carries the exact journal event ID and organization for each recorded step.
  // Fetch its larger payload only when the operator opens the step.
  let evidenceSeq = 0;
  const SOURCE_LABEL = { tool_result: "What the tool returned to the agent", workspace_snapshot: "Copy of the file read on the agent's machine" };
  const SETTINGS_HELP = `Command text, output and file previews appear only when the observer on that machine enables them
    (<code>SWARMCONTROL_SHARE_COMMANDS</code>, <code>SWARMCONTROL_SHARE_COMMAND_OUTPUT</code>, <code>SWARMCONTROL_SHARE_FILE_PREVIEWS</code>). All are off by default.`;
  async function getJSON(url) {
    const r = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
    if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status });
    return r.json();
  }
  const kb = n => n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`;
  function evidenceHtml(ev, liveHref, hadStepFiles, d) {
    const out = [];
    const ran = ev.command_input != null || ev.command_output != null || ev.exit_code != null;
    if (ran) {
      const code = ev.exit_code == null ? '<span class="am-exit">exit code not recorded</span>'
        : `<span class="am-exit ${ev.exit_code === 0 ? "ok" : "bad"}">exit ${H(ev.exit_code)}</span>`;
      const input = ev.command_input != null ? `<span class="am-prompt" aria-hidden="true">$ </span>${H(ev.command_input)}`
        : `<span class="muted">${H(ev.program ? `${ev.program} …` : "Command")} (full text not shared)</span>`;
      const output = ev.command_output == null ? '<p class="muted small am-term-note">Output not shared by this machine.</p>'
        : `<pre class="am-term-out" tabindex="0" aria-label="Command output">${ev.command_output ? H(ev.command_output) : '<span class="muted">(no output)</span>'}</pre>
           ${ev.output_truncated ? '<p class="muted small am-term-note">Output shortened to its first 4,096 characters.</p>' : ""}`;
      out.push(`<section class="am-term" aria-label="Command and result"><div class="am-term-head"><h4>Command and result</h4>${code}</div>
        <pre class="am-term-in" tabindex="0" aria-label="Command">${input}</pre>${output}</section>`);
    }
    const images = (ev.images || []).filter(im => typeof im.url === "string" && im.url.startsWith("/api/v1/events/"));
    if (images.length) {
      const title = images.every(im => im.source === "tool_result") ? "Images the agent saw" : "Images recorded for this step";
      out.push(`<section class="am-shots"><h4>${title} <span class="muted">${images.length}</span></h4><div class="am-shot-grid">${images.map(im => {
        const when = im.captured_at ? new Date(im.captured_at * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "";
        return `<figure class="am-shot"><a href="${H(im.url)}" target="_blank" rel="noopener" title="Open full size">
          <img src="${H(im.url)}" alt="${H(im.path)}" loading="lazy" decoding="async"></a>
          <figcaption><strong>${H(String(im.path).split("/").pop())}</strong><span>${H(SOURCE_LABEL[im.source] || "Recorded image")}</span>
          <span class="muted">${H([when, im.size_bytes ? kb(im.size_bytes) : ""].filter(Boolean).join(" · "))}</span></figcaption></figure>`;
      }).join("")}</div></section>`);
    }
    const texts = (ev.text_previews || []).filter(t => typeof t.excerpt === "string" || typeof t.text === "string");
    if (texts.length) {
      out.push(`<section class="am-texts"><h4>File contents the agent read <span class="muted">${texts.length}</span></h4>${texts.map((t, i) => `
        <details class="am-text"${i === 0 ? " open" : ""}><summary><code>${H(t.path)}</code>${t.truncated ? ' <span class="muted small">(first 4,096 characters)</span>' : ""}</summary>
        <pre tabindex="0">${H(t.excerpt ?? t.text)}</pre></details>`).join("")}</section>`);
    }
    if (!hadStepFiles && Array.isArray(ev.files) && ev.files.length) out.push(fileList("Files recorded for this step", ev.files, d, "", evidence("recorded")));
    const open = `<a class="link-hop-btn" href="${H(liveHref)}">Open this event in Live events ↗</a>`;
    if (!out.length) return `<p class="muted small">This step is in the journal, but the machine did not share its command text, output or file contents.</p>
      <p class="muted small">${SETTINGS_HELP}</p>${open}`;
    return out.join("") + open;
  }
  async function loadEvidence(slot, s, st, d, firstFile, hadStepFiles) {
    const seq = ++evidenceSeq;
    // A newer request or a re-rendered dialog (the slot left the page) makes this answer stale.
    const settle = html => { if (seq === evidenceSeq && slot.isConnected) { slot.innerHTML = html; slot.removeAttribute("aria-busy"); } };
    try {
      const id = st.event_id, org = st.event_org;
      if (!Number.isSafeInteger(id) || id <= 0 || !Number.isSafeInteger(org) || org <= 0) {
        settle(`<p class="muted small">This step has no exact journal link yet. You can still browse the recorded events for this session.</p>
          <a class="link-hop-btn" href="${H(liveHrefForSession(s))}">View session history ↗</a>`);
        return;
      }
      const ev = await getJSON(`/api/v1/events/${id}/evidence?organization_id=${org}`);
      if (seq !== evidenceSeq || !slot.isConnected) return;
      if (ev.organization !== org || ev.event_id !== id || ev.session !== s.session_id) {
        settle('<p class="muted small">The event no longer matches this step. Reopen the step to refresh it.</p>');
        return;
      }
      const liveHref = `${liveHrefForSession(s, firstFile)}&event=${encodeURIComponent(`event:${id}`)}&organization=${org}`;
      settle(evidenceHtml(ev, liveHref, hadStepFiles, d));
    } catch (err) {
      settle(err.status === 409 ? '<p class="muted small">The organization changed. Close this window and open the step again.</p>'
        : err.status === 401 || err.status === 403 ? '<p class="muted small">Your session cannot read event details. Sign in again or ask an admin.</p>'
        : '<p class="muted small">The recorded detail could not be loaded. Try again in a moment.</p>');
    }
  }

  function showDetail(button) {
    const d = state.data, s = d?.sessions[Number(button.dataset.session)];
    if (!s) return;
    const isPlan = button.dataset.kind === "plan";
    const item = (isPlan ? s.plan : s.steps)[Number(button.dataset.index)];
    if (!item) return;
    state.opener = button;
    const planText = { completed: "The agent marked this checklist item complete.", in_progress: "The agent marked this checklist item in progress.", pending: "The agent listed this as a next step." };
    const stepStatus = { completed: "Completed", error: "Failed", running: "In progress", pending: "Pending" };
    const context = isPlan ? planText[item.status] || "Recorded in the agent's checklist."
      : [CAT_LABEL[item.category], stepStatus[item.status], String(item.time || "").replace("T", " ").slice(0, 19)].filter(Boolean).join(" · ");
    const stepFiles = isPlan ? fileList("Files named in this item", item.named_files, d, "", evidence("mentioned"))
      : fileList(item.category === "file_read" ? "Files read by this step" : item.category === "file_edit" ? "Files changed by this step" : "Files in this step",
        item.files, d, item.category === "file_edit" ? "edited" : "", evidence(item.file_basis || "recorded"));
    const sessionFiles = fileList("Edited", s.files_edited, d, "edited") + fileList("Delivered", s.files_delivered, d, "delivered") + fileList("Read", s.files_read, d, "read");
    const firstStepFile = !isPlan && Array.isArray(item.files) && item.files.length ? rel(item.files[0], d) : "";
    const detailLinkBar = renderSessionLinksBar(s, d, firstStepFile);
    dialog.innerHTML = `<div class="am-dialog-head">${providerMark(s)}<button type="button" class="btn small secondary" data-close>Close</button></div>
      <p class="am-detail-kind">${H(s.agent_name)} · ${H(s.harness_name)} · ${H(hostName(d, s.host_id))} · ${isPlan ? "Checklist item" : "Recorded step"}</p>
      <h3 id="am-detail-title">${H(isPlan ? item.text : item.label)}</h3><p>${H(context)}</p>
      ${detailLinkBar}
      <div class="am-detail-summary"><h4>What the agent did in this session</h4><p>${H(s.what_done)}</p></div>
      ${stepFiles || '<p class="muted small">No file inside the shared folders is tied to this single step.</p>'}
      ${isPlan ? "" : `<div class="am-evidence" data-evidence aria-live="polite" aria-busy="true"><p class="muted small am-loading">Loading the recorded command, output and files…</p></div>`}
      ${!isPlan && item.category === "file_edit" ? `<section class="am-survival" data-survival aria-live="polite" aria-busy="true"><h4>Lines still in the code</h4><p class="muted small am-loading">Checking Git…</p></section>` : ""}
      <dl class="ap-facts"><dt>Folder</dt><dd><code>${H(rel(s.workspace, d) || "unreported")}</code></dd>
        <dt>Agent identity</dt><dd>From the shared folder name${s.owner_basis && s.owner_basis !== "workspace" ? ` (${H(s.owner_basis)})` : ""}</dd>
        <dt>Provider</dt><dd>${H(s.provider_basis === "recorded" ? "Recorded by the harness" : s.provider_basis === "model" ? "Inferred from the model name" : "Not recorded")}</dd></dl>
      <details class="am-context"${stepFiles ? "" : " open"}><summary>All files in this session</summary>${sessionFiles || "<p class='muted small'>None recorded.</p>"}</details>`;
    dialog.showModal();
    dialog.querySelector("[data-close]").focus();
    const slot = dialog.querySelector("[data-evidence]");
    if (slot) loadEvidence(slot, s, item, d, firstStepFile, Boolean(stepFiles));
    const survival = dialog.querySelector("[data-survival]");
    if (survival) loadSurvival(survival, s, item);
  }

  /* ---------- line survival: lines this edit added that are still in the code (Git evidence only) ----------
     The server links the edit to the commit the same session's own `git commit` printed, and counts with `git blame`
     on the agent's machine how many of the lines that commit added are still assigned to it. Nothing is inferred
     from file text; when the evidence is not explicit the reason is shown instead of a number. */
  const SURVIVAL_HELP = `Line tracking appears when the observer on that machine sets <code>SWARMCONTROL_SHARE_LINE_SURVIVAL=1</code>.
    It sends commit IDs and line counts only, never file contents.`;
  function survivalHtml(r) {
    const files = Array.isArray(r.files) ? r.files : [];
    if (!files.length) return '<p class="muted small">This edit names no file in a shared folder, so there are no lines to follow.</p>';
    const when = t => t ? new Date(t * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "";
    return `<ul class="am-survival-list">${files.map(f => {
      if (f.status !== "attributed") {
        return `<li class="is-unknown"><code>${H(f.file)}</code><span class="am-survival-why">${H(f.reason || "Not enough Git evidence")}</span>
          ${f.status === "not_shared" ? `<span class="muted small">${SURVIVAL_HELP}</span>` : ""}</li>`;
      }
      const added = Number(f.added) || 0, kept = Math.min(Number(f.surviving) || 0, added), gone = added - kept;
      const pct = added ? Math.round((kept / added) * 100) : 0;
      return `<li><div class="am-survival-head"><code>${H(f.file)}</code><strong>${kept} of ${added} lines remain</strong></div>
        <div class="am-survival-bar" role="img" aria-label="${kept} lines remain, ${gone} changed or removed"><span style="width:${pct}%"></span></div>
        <p class="muted small">${gone ? `${gone} changed or removed since commit <code>${H(String(f.commit).slice(0, 7))}</code>` : `Unchanged since commit <code>${H(String(f.commit).slice(0, 7))}</code>`}${
          f.file_exists === false ? " · the file is no longer on the checked-out branch" : ""}${
          f.edits_in_commit > 1 ? ` · counts all ${H(f.edits_in_commit)} edits this session made to the file before that commit` : ""}.
          Measured at <code>${H(String(f.head).slice(0, 7))}</code>, ${H(when(f.measured_at))}. Uncommitted changes are not counted.</p></li>`;
    }).join("")}</ul>`;
  }
  let survivalSeq = 0;
  async function loadSurvival(slot, s, st) {
    const seq = ++survivalSeq;
    const settle = html => { if (seq === survivalSeq && slot.isConnected) { slot.innerHTML = `<h4>Lines still in the code</h4>${html}`; slot.removeAttribute("aria-busy"); } };
    const id = st.event_id, org = st.event_org;
    if (!Number.isSafeInteger(id) || id <= 0 || !Number.isSafeInteger(org) || org <= 0) {
      settle('<p class="muted small">This step has no exact journal link yet, so its lines cannot be followed.</p>');
      return;
    }
    try {
      const r = await getJSON(`/api/v1/events/${id}/line-survival?organization_id=${org}`);
      if (r.organization !== org || r.event_id !== id || r.session !== s.session_id) {
        settle('<p class="muted small">The event no longer matches this step. Reopen the step to refresh it.</p>');
        return;
      }
      settle(survivalHtml(r));
    } catch (err) {
      settle(err.status === 409 ? '<p class="muted small">The organization changed. Close this window and open the step again.</p>'
        : '<p class="muted small">Line tracking could not be loaded. Try again in a moment.</p>');
    }
  }

  /* ---------- empty and privacy states ---------- */
  const PRIVACY = `<p class="muted small ap-privacy">Each machine reads only the folders its operator lists. Summaries are cleaned on that machine before sending. Prompts never leave it; command text, output and file previews leave it only if its operator turns them on.</p>`;
  function emptyState(d) {
    const hosts = d.hosts;
    if (!hosts.length) {
      return `<div class="ap-empty" role="status"><h3>No machine has shared activity yet</h3>
        <ol><li>Install the observer on a machine that runs agents. <a href="#enrollment">Open the installer</a></li>
        <li>Choose the folders to share with <code>SWARMCONTROL_ACTIVITY_ROOTS</code>. Without folders, the machine sends health data only.</li>
        <li>Optionally check what would leave the machine: <code>swarmcontrol_agent.py --preview-activity</code></li></ol>${PRIVACY}</div>`;
    }
    const off = hosts.filter(h => !h.activity_enabled);
    if (off.length === hosts.length) {
      return `<div class="ap-empty" role="status"><h3>Activity sharing is off on ${hosts.length === 1 ? "this machine" : `all ${hosts.length} machines`}</h3>
        <p>${hosts.length === 1 ? "It sends" : "They send"} health data only, because no folder was chosen. To show tasks, plans and files, reinstall with <code>SWARMCONTROL_ACTIVITY_ROOTS</code> set to the project folders.</p>${PRIVACY}</div>`;
    }
    return `<div class="ap-empty" role="status"><h3>No agent session found in the shared folders yet</h3>
      <p>Shared folders are being read, but no Codex, Claude Code, Gemini/Antigravity or OpenCode session has worked inside them recently.</p></div>`;
  }
  function hostStrip(d) {
    return `<ul class="ap-hosts" aria-label="Machines">${d.hosts.map(h => `<li class="${h.activity_enabled ? "on" : "off"}">
      <strong>${H(machineLabel(h))}</strong><span class="muted small">${h.os_name ? H(h.os_name) + " · " : ""}seen <time data-ts="${h.updated_at || ""}">${H(ago(h.updated_at))}</time></span>
      <span class="ap-share ${h.activity_enabled ? "on" : ""}">${h.activity_enabled ? `Sharing ${h.activity_roots.length} folder${h.activity_roots.length === 1 ? "" : "s"}` : "Health only"}</span>
      ${h.activity_enabled ? rootList(d, h) : ""}</li>`).join("")}</ul>`;
  }
  function rootList(d, h) {
    const label = r => (d.workspaces.find(w => w.path === r && (!w.host_id || w.host_id === h.host_id)) || {}).label
      || String(r).split(/[\\/]/).filter(Boolean).pop() || r;
    const names = [...new Set(h.activity_roots.map(label))].sort((a, b) => a.localeCompare(b));
    const shown = names.slice(0, 3).map(n => `<span class="ap-root">${H(n)}</span>`).join("");
    const more = names.length > 3 ? `<span class="ap-root more" title="${H(names.slice(3).join(", "))}">+${names.length - 3} more</span>` : "";
    return `<span class="ap-roots" aria-label="Shared folders: ${H(names.join(", "))}">${shown}${more}</span>`;
  }

  function workspaces(d) {
    const list = d.workspaces.filter(w => state.host === "all" || w.host_id === state.host);
    if (!list.length) return "";
    return `<h3>Shared folders</h3><div class="am-ws-grid">${list.slice(0, 12).map(w => {
      const max = Math.max(1, ...(w.folders || []).map(f => f.files));
      return `<article class="am-ws"><header><strong>${H(w.label)}</strong><span class="muted small">${multiHost(d) ? H(hostName(d, w.host_id)) + " · " : ""}${w.file_count}${w.truncated ? "+" : ""} files · changed ${H(ago(w.last_modified))}</span></header>
        <ul class="am-folders">${(w.folders || []).map(f => `<li><span>${H(f.name === "." ? "(top level)" : f.name + "/")}</span><b style="width:${Math.round(f.files / max * 100)}%"></b><em>${f.files}</em></li>`).join("")}</ul>
        <h5>Recently modified</h5><ul class="am-recent">${(w.recent_files || []).slice(0, 6).map(f => `<li><span class="cat c-${H(f.category)}">${H(f.category)}</span><code>${H(f.rel_path)}</code><time>${H(ago(f.mtime))}</time>${(f.edited_by || []).length ? `<span class="by">Edit recorded by ${H(f.edited_by.join(", "))}</span>` : ""}</li>`).join("")}</ul></article>`;
    }).join("")}</div><p class="muted small">File times alone do not prove who edited a file. “Edit recorded by” appears only when a session's own record shows that edit.</p>`;
  }

  /* ---------- timeline: one lane per agent, one dot per recorded step ---------- */
  const stepMs = st => { const t = String(st.time || ""); return t ? Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(t) ? t : t + "Z") : NaN; };
  function timeline(d, sessions) {
    const end = Math.max(Date.now(), (d.collected_at || 0) * 1000), span = state.span * 1000, t0 = end - span;
    const lanes = new Map();
    for (const s of sessions) {
      const k = agentKey(s);
      if (!lanes.has(k)) lanes.set(k, { name: s.agent_name, s, dots: [] });
      s.steps.forEach((st, i) => { const t = stepMs(st); if (t >= t0 && t <= end + 60000) lanes.get(k).dots.push({ s, st, i, t }); });
    }
    const rows = [...lanes.values()].filter(l => l.dots.length).sort((a, b) => a.name.localeCompare(b.name));
    const spans = `<div class="ap-spans" role="group" aria-label="Time window">${WINDOWS.map(([v, n]) =>
      `<button type="button" class="am-chip${state.span === v ? " on" : ""}" data-span="${v}" aria-pressed="${state.span === v}">${n}</button>`).join("")}</div>`;
    if (!rows.length) return spans + `<div class="ap-empty ap-empty--soft" role="status"><h3>No recorded step in the last ${H(WINDOWS.find(w => w[0] === state.span)[1])}</h3><p>Choose a longer window, or clear the search.</p></div>`;
    const W = 1000, L = 200, R = 16, rowH = 34, top = 28, H2 = top + rows.length * rowH + 8;
    const x = t => L + (t - t0) / span * (W - L - R);
    const ticks = Array.from({ length: 6 }, (_, i) => t0 + span * i / 5).map((t, i) =>
      `<line class="ap-tick" x1="${x(t)}" x2="${x(t)}" y1="${top - 6}" y2="${H2 - 4}"/><text class="am-col" x="${x(t)}" y="16" text-anchor="${i === 5 ? "end" : "middle"}">${H(new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }))}</text>`).join("");
    const lanesSvg = rows.map((l, r) => {
      const y = top + r * rowH + rowH / 2;
      // Steps closer than 9 px merge into a burst (a pill with its count) so nothing hides behind another dot.
      const bursts = [];
      for (const o of l.dots.sort((a, b) => a.t - b.t)) {
        const last = bursts.at(-1);
        if (last && x(o.t) - x(last.at(-1).t) < 9) last.push(o); else bursts.push([o]);
      }
      const describe = o => `${clock(o.st.time)} · ${CAT_LABEL[o.st.category]} · ${o.st.label}${o.st.program ? " · " + o.st.program : ""}`;
      const dots = bursts.map(b => {
        const o = b.at(-1), fresh = b.some(q => state.fresh.has(stepKey(q.s, q.st))), err = b.some(q => q.st.status === "error");
        const attrs = `data-session="${d.sessions.indexOf(o.s)}" data-kind="step" data-index="${o.i}" tabindex="0" role="button"`;
        if (b.length === 1) return `<circle class="ap-dot c-${H(o.st.category)}${fresh ? " is-new" : ""}${err ? " is-error" : ""}" cx="${x(o.t).toFixed(1)}" cy="${y}" r="5.5" ${attrs}
          aria-label="${H(`${l.name}: ${o.st.label} at ${clock(o.st.time)}`)}"><title>${H(describe(o))}</title></circle>`;
        const cats = b.reduce((m, q) => (m[q.st.category] = (m[q.st.category] || 0) + 1, m), {});
        const main = Object.entries(cats).sort((p, q) => q[1] - p[1])[0][0];
        const x1 = x(b[0].t) - 6, w = Math.max(x(o.t) - x(b[0].t) + 12, 22);
        return `<g class="ap-burst c-${H(main)}${fresh ? " is-new" : ""}${err ? " is-error" : ""}" ${attrs}
          aria-label="${H(`${l.name}: ${b.length} steps from ${clock(b[0].st.time)} to ${clock(o.st.time)}; opens the latest`)}">
          <rect x="${x1.toFixed(1)}" y="${y - 7}" width="${w.toFixed(1)}" height="14" rx="7"/><text x="${(x1 + w / 2).toFixed(1)}" y="${y + 3.5}" text-anchor="middle">${b.length}</text>
          <title>${H(b.slice(-8).map(describe).join("\n") + (b.length > 8 ? `\n… ${b.length - 8} earlier` : ""))}</title></g>`;
      }).join("");
      return `<g class="ap-lane"><line class="ap-lane-line" x1="${L}" x2="${W - R}" y1="${y}" y2="${y}"/>
        <g transform="translate(4 ${y - 12})">${providerMark(l.s, true)}</g><text class="ap-lane-name" x="34" y="${y + 4}">${H(short(l.name).length > 22 ? short(l.name).slice(0, 21) + "…" : short(l.name))}<title>${H(l.name)}</title></text>
        <text class="ap-lane-count" x="${L - 8}" y="${y + 4}" text-anchor="end">${l.dots.length}</text>${dots}</g>`;
    }).join("");
    const legend = CAT_ORDER.filter(c => rows.some(l => l.dots.some(o => o.st.category === c)))
      .map(c => `<span><i class="c-${c}" aria-hidden="true"></i>${CAT_LABEL[c]}</span>`).join("");
    return `${spans}<div class="ap-timeline"><svg viewBox="0 0 ${W} ${H2}" role="group" aria-label="Recorded steps per agent over time">${ticks}${lanesSvg}</svg></div>
      <div class="am-legend ap-legend">${legend}<span class="muted">Select a dot for the step, its files and evidence.</span></div>`;
  }

  /* ---------- search ---------- */
  function matches(s, d, q) {
    if (!q) return true;
    const hay = [s.agent_name, s.harness_name, s.model, s.what_done, rel(s.workspace, d), hostName(d, s.host_id),
      ...s.steps.flatMap(st => [st.label, st.program, st.command, ...(st.files || []).map(f => rel(f, d))]),
      ...s.plan.map(p => p.text), ...s.files_edited.map(f => rel(f, d)), ...s.files_read.map(f => rel(f, d))].join(" ").toLowerCase();
    return q.toLowerCase().split(/\s+/).filter(Boolean).every(w => hay.includes(w));
  }

  /* ---------- render ---------- */
  function toolbar(d, shown, total) {
    const tabs = VIEWS.map(([v, n]) => `<button type="button" role="tab" class="ap-tab${state.view === v ? " on" : ""}" data-view="${v}"
      aria-selected="${state.view === v}" tabindex="${state.view === v ? 0 : -1}">${n}</button>`).join("");
    return `<div class="ap-toolbar"><div class="ap-tabs" role="tablist" aria-label="Activity views">${tabs}</div>
      <label class="ap-search"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>
        <span class="sr-only">Search sessions</span><input type="search" data-role="search" value="${H(state.query)}" placeholder="Search agents, files, commands…" autocomplete="off" spellcheck="false">
        <kbd aria-hidden="true">/</kbd></label>
      <span class="ap-live" title="Refreshes every 20 seconds"><i aria-hidden="true"></i>Live · <time data-ts="${d.collected_at || ""}">${H(ago(d.collected_at))}</time></span></div>
      ${state.query ? `<p class="ap-matchline" role="status">${shown} of ${total} sessions match “${H(state.query)}” <button type="button" class="ap-link" data-clear>Clear</button></p>` : ""}`;
  }

  function render(d = state.data, force = false) {
    if (!d) return;
    const print = JSON.stringify([d.sessions.map(s => [s.session_id, s.updated_at, s.status, s.steps.length]), d.hosts.map(h => [h.host_id, h.activity_enabled, h.activity_roots.length]),
      d.workspaces.map(w => [w.id, w.last_modified]), state.host, state.agent, state.view, state.query, state.span, [...state.open], state.highlightSession, state.fromTaskId, Object.keys(state.linksBySession).sort()]);
    if (!force && print === state.print) { tick(); return; }  // nothing changed: keep hover, focus and scroll
    state.print = print;
    const searchHadFocus = document.activeElement?.dataset?.role === "search";
    const caret = searchHadFocus ? document.activeElement.selectionStart : 0;
    const scoped = d.sessions.filter(s => state.host === "all" || s.host_id === state.host);
    const all = scoped.filter(s => matches(s, d, state.query));
    const sessions = all.filter(s => state.agent === "all" || agentKey(s) === state.agent);
    const recent = [], older = [], seen = new Set();
    for (const s of sessions) {
      const k = `${agentKey(s)}|${s.harness}`;
      if ((s.status === "active" || Date.now() / 1000 - s.updated_at < 86400) && !seen.has(k)) { seen.add(k); recent.push(s); } else older.push(s);
    }
    const hostChips = multiHost(d) ? `<div class="am-filter" role="group" aria-label="Filter by machine">${[["all", "All machines"], ...d.hosts.map(h => [h.host_id, machineLabel(h)])]
      .map(([id, n]) => `<button type="button" class="am-chip${state.host === id ? " on" : ""}" data-host="${H(id)}" aria-pressed="${state.host === id}">${H(n)}</button>`).join("")}</div>` : "";
    buildShortNames([...d.sessions.map(s => s.agent_name), ...d.sessions.map(s => rel(s.workspace, d))]);
    const agentChips = new Map(all.map(s => [agentKey(s), short(s.agent_name) + (multiHost(d) ? ` · ${hostName(d, s.host_id)}` : "")]));
    const fullName = new Map(all.map(s => [agentKey(s), s.agent_name + (multiHost(d) ? ` · ${hostName(d, s.host_id)}` : "")]));
    const chips = agentChips.size > 1 ? `<div class="am-filter ap-agents" role="group" aria-label="Filter by agent">${[["all", "All agents"], ...agentChips]
      .map(([id, n]) => `<button type="button" class="am-chip${state.agent === id ? " on" : ""}" data-agent="${H(id)}" aria-pressed="${state.agent === id}" title="${H(fullName.get(id) || n)}">${H(n)}</button>`).join("")}</div>` : "";
    const active = new Set(scoped.filter(s => s.status === "active").map(agentKey)).size;
    const edited = new Set(scoped.flatMap(s => s.files_edited)).size;
    const stat = (key, value, label) => `<div><b data-count="${key}" data-value="${value}">${value}</b><span>${label}</span></div>`;
    const cards = list => list.map((s, i) => card(s, d).replace('<article class="am-agent-card"',
      `<article class="am-agent-card${state.fresh.size && s.steps.some(st => state.fresh.has(stepKey(s, st))) ? " is-new" : ""}" style="--i:${Math.min(i, 12)}"`)).join("");
    let body;
    if (!scoped.length && state.view !== "folders") body = emptyState(d);
    else if (state.view === "timeline") body = hostChips + chips + timeline(d, sessions);
    else if (state.view === "folders") body = hostChips + (workspaces(d) || '<p class="muted">No shared folder reported yet.</p>');
    else if (state.view === "sessions") body = `${hostChips}${chips}<div class="am-sessions">${cards(recent) || '<p class="muted">No session in the last 24 hours for this filter.</p>'}
        ${older.length ? `<details class="am-older" data-open-key="__older"${state.open.has("__older") ? " open" : ""}><summary>Show ${older.length} earlier session${older.length === 1 ? "" : "s"}</summary>${cards(older)}</details>` : ""}</div>`;
    else body = `${hostChips}${chips}${flow(d, sessions)}
        <div class="ap-section-head"><h3>Latest work</h3>${recent.length > 6 || older.length ? `<button type="button" class="ap-link" data-view="sessions">All ${sessions.length} sessions →</button>` : ""}</div>
        <div class="am-sessions">${cards(recent.slice(0, 6)) || '<p class="muted">No session in the last 24 hours for this filter.</p>'}</div>`;
    const nav = [state.view, state.host, state.agent, state.query, state.span].join("|");
    const animate = state.intro || nav !== state.nav;  // entrance motion on first load or navigation, never on a data refresh
    state.nav = nav;
    const before = Object.fromEntries([...root.querySelectorAll("[data-count]")].map(b => [b.dataset.count, Number(b.dataset.value)]));
    const backAssign = state.fromTaskId && state.highlightSession
      ? `<div class="return-nav-banner" style="margin-bottom:10px;"><button type="button" class="btn small primary" data-focus-task="${H(state.fromTaskId)}">← Back to assignment</button><span class="muted small">Viewing linked session <code>${H(state.highlightSession)}</code></span></div>`
      : "";
    root.innerHTML = `
      ${backAssign}
      ${toolbar(d, all.length, scoped.length)}
      ${hostStrip(d)}
      <div class="am-stats">${stat("machines", `${d.hosts.filter(h => h.activity_enabled).length}/${d.hosts.length}`, "machines sharing activity")}
        ${stat("active", `${active}/${new Set(scoped.map(agentKey)).size}`, "agents active (15 min)")}${stat("sessions", scoped.length, "recent sessions")}
        ${stat("edited", edited, "files with a recorded edit")}${stat("folders", d.workspaces.length, "shared folders")}</div>
      <div class="ap-view${animate ? " ap-enter" : ""}" data-current="${state.view}">${body}</div>
      ${scoped.length ? PRIVACY : ""}
      <p class="muted small am-foot">Updated <time data-ts="${d.collected_at || ""}">${H(ago(d.collected_at))}</time>${d.hosts.length ? ` from ${d.hosts.length} machine${d.hosts.length === 1 ? "" : "s"}` : ""} · read-only · press <kbd>/</kbd> to search.</p>`;
    countUp(before);
    state.intro = false;
    if (searchHadFocus) { const input = root.querySelector('[data-role="search"]'); input.focus(); input.setSelectionRange(caret, caret); }
  }
  function countUp(before) {
    if (reduceMotion()) return;
    for (const b of root.querySelectorAll("[data-count]")) {
      const to = Number(b.dataset.value), from = before[b.dataset.count];
      if (!Number.isFinite(to) || !Number.isFinite(from) || from === to) continue;
      const t0 = performance.now();
      const step = now => { const k = Math.min(1, (now - t0) / 450); b.textContent = Math.round(from + (to - from) * (1 - (1 - k) ** 3)); if (k < 1) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    }
  }
  function tick() { for (const t of root.querySelectorAll("time[data-ts]")) t.textContent = ago(Number(t.dataset.ts)); }
  setInterval(tick, 15000);

  /* hover a node: highlight its paths; hover elsewhere: restore */
  root.addEventListener("pointerover", e => {
    const node = e.target.closest?.("[data-node]");
    const svg = root.querySelector(".am-flow svg");
    if (!svg) return;
    svg.classList.toggle("ap-hovering", Boolean(node));
    for (const p of svg.querySelectorAll(".am-link")) p.classList.toggle("ap-hl", Boolean(node) && (p.dataset.from === node.dataset.node || p.dataset.to === node.dataset.node));
  });
  root.addEventListener("input", e => {
    if (e.target.dataset.role !== "search") return;
    clearTimeout(state.typing);
    state.typing = setTimeout(() => { state.query = e.target.value.trim(); syncActivityUrl(); render(); }, 120);
  });
  document.addEventListener("keydown", e => {
    const typing = /^(input|textarea|select)$/i.test(e.target.tagName) || e.target.isContentEditable;
    const r = root.getBoundingClientRect();
    if (e.key === "/" && !typing && !dialog.open && r.bottom > 0 && r.top < innerHeight) {
      const input = root.querySelector('[data-role="search"]');
      if (input) { e.preventDefault(); input.focus(); input.select(); }
    } else if (e.key === "Escape" && e.target.dataset?.role === "search" && state.query) {
      state.query = ""; syncActivityUrl(); render(); e.preventDefault();
    }
  });

  root.addEventListener("click", e => {
    const focusTask = e.target.closest("[data-focus-task]");
    if (focusTask) {
      document.dispatchEvent(new CustomEvent("swarm-focus-task", { detail: { taskId: focusTask.dataset.focusTask } }));
      return;
    }
    const detail = e.target.closest("[data-kind]");
    if (detail) { showDetail(detail); return; }
    const v = e.target.closest("[data-view]");
    if (v && v.dataset.view !== state.view) { state.view = v.dataset.view; syncActivityUrl(); render(); root.querySelector(`.ap-tab[data-view="${state.view}"]`)?.focus(); return; }
    const sp = e.target.closest("[data-span]");
    if (sp) { state.span = Number(sp.dataset.span); syncActivityUrl(); render(); return; }
    if (e.target.closest("[data-clear]")) { state.query = ""; syncActivityUrl(); render(); return; }
    const h = e.target.closest("[data-host]");
    if (h) { state.host = h.dataset.host; state.agent = "all"; syncActivityUrl(); render(); return; }
    const a = e.target.closest("[data-agent]");
    if (a) { state.agent = state.agent === a.dataset.agent && a.dataset.agent !== "all" ? "all" : a.dataset.agent; syncActivityUrl(); render(); }
  });
  root.addEventListener("keydown", e => {
    if ((e.key === "Enter" || e.key === " ") && e.target.matches("g[data-agent], circle[data-kind], g[data-kind]")) {
      e.preventDefault(); e.target.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    } else if ((e.key === "ArrowRight" || e.key === "ArrowLeft") && e.target.matches(".ap-tab")) {
      const i = VIEWS.findIndex(([v]) => v === state.view), n = VIEWS.length;
      state.view = VIEWS[(i + (e.key === "ArrowRight" ? 1 : n - 1)) % n][0]; render();
      root.querySelector(`.ap-tab[data-view="${state.view}"]`)?.focus(); e.preventDefault();
    }
  });
  root.addEventListener("toggle", e => {
    const k = e.target.dataset && e.target.dataset.openKey;
    if (k) e.target.open ? state.open.add(k) : state.open.delete(k);
  }, true);

  /* ---------- loading: retry, alternate route, notices ---------- */
  const notice = document.createElement("div");
  notice.className = "am-load-notice";
  notice.setAttribute("role", "status");
  notice.hidden = true;
  const message = document.createElement("span");
  const retry = document.createElement("button");
  retry.className = "btn small secondary"; retry.type = "button"; retry.textContent = "Retry";
  notice.append(message, retry);
  root.before(notice);
  let pending = null;
  const signedOut = () => !app || app.classList.contains("hidden");

  function display(snapshot) {
    if (!snapshot || !Array.isArray(snapshot.sessions)) throw new Error("incomplete");
    state.data = normalize(snapshot);
    if (state.host !== "all" && !state.data.hosts.some(h => h.host_id === state.host)) state.host = "all";
    const keys = new Set(state.data.sessions.flatMap(s => s.steps.map(st => stepKey(s, st))));
    state.fresh = state.known ? new Set([...keys].filter(k => !state.known.has(k))) : new Set();  // flash only what arrived since the last read
    state.known = keys;
    render(undefined, state.fresh.size > 0);
    notice.hidden = true;
    if (app) delete app.dataset.includeActivity;
  }
  let reports = [];
  function showAvailableReports() {
    const expanded = new Set(Array.from(root.querySelectorAll("[data-report][open]"), el => el.dataset.report));
    root.innerHTML = reports.length
      ? "<h3>Reports declared by agents</h3>" + renderWorkReports(reports, expanded)
      : '<p class="muted">Activity is unavailable right now.</p>';
  }
  function reset() {
    reports = [];
    pending?.abort(); pending = null;
    if (dialog.open) dialog.close();
    dialog.replaceChildren();
    Object.assign(state, { host: "all", agent: "all", data: null, view: "overview", query: "", print: "", known: null, fresh: new Set(), intro: true, highlightSession: "", fromTaskId: "", linksBySession: {} });
    state.open.clear();
    if (app) delete app.dataset.includeActivity;
    notice.hidden = true;
    root.innerHTML = `<div class="ap-skeleton" role="status" aria-label="Loading agent activity"><span></span><span></span><span></span><span></span></div>`;
  }
  async function load() {
    if (pending || dialog.open || signedOut()) return;
    const req = new AbortController();
    pending = req; retry.disabled = true;
    const timer = setTimeout(() => req.abort(), 12000);
    let reason = "The connection to the activity service was interrupted.", transport = true;
    try {
      let res;
      for (let attempt = 0; attempt < 2; attempt++) {
        try { res = await fetch("/api/v1/activity", { credentials: "same-origin", cache: "no-store", signal: req.signal }); break; }
        catch (err) { if (attempt === 1 || req.signal.aborted || signedOut()) throw err; await new Promise(r => setTimeout(r, 600)); }
      }
      if (pending !== req || signedOut()) return;
      if (res.status === 401) { reset(); if (typeof showLogin === "function") showLogin(); return; }
      transport = false;
      if (res.status === 403) { reason = "Your role cannot view the activity map for this organization."; throw new Error(); }
      if (!res.ok) { reason = `The activity service returned HTTP ${res.status}.`; throw new Error(); }
      display(await res.json());
    } catch (err) {
      if (pending !== req || signedOut()) return;
      if (req.signal.aborted) reason = "The activity service did not respond within 12 seconds.";
      if (transport && app) app.dataset.includeActivity = "true";  // next work-board read carries the map
      message.textContent = state.data ? `${reason} Showing the reading from ${new Date(state.data.collected_at * 1000).toLocaleTimeString()}.` : reason;
      notice.hidden = false;
      if (!state.data) showAvailableReports();
    } finally {
      clearTimeout(timer);
      if (pending === req) { pending = null; retry.disabled = false; }
    }
  }
  retry.addEventListener("click", load);
  document.addEventListener("agent-reports", e => {
    if (signedOut()) return;
    reports = e.detail?.reports || [];
    if (e.detail?.links?.by_session && typeof e.detail.links.by_session === "object") {
      state.linksBySession = e.detail.links.by_session;
      if (state.data) render(undefined, false);
    }
    if (!state.data && !notice.hidden) showAvailableReports();
    const snap = e.detail && e.detail.activity;
    if (app?.dataset.includeActivity && snap && !dialog.open) { try { display(snap); } catch { /* keep the last good map */ } }
  });
  document.addEventListener("swarm-open-session", e => {
    const sid = String(e.detail?.sessionId || "").trim();
    if (!sid) return;
    state.view = "sessions";
    state.highlightSession = sid;
    state.fromTaskId = String(e.detail?.fromTaskId || "").trim();
    state.open.add(sid);
    syncActivityUrl();
    if (state.data) {
      state.print = "";
      render(undefined, false);
      const target = root.querySelector(`details[data-open-key="${CSS.escape(sid)}"]`);
      target?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  });
  document.addEventListener("swarm-org-changed", () => { reset(); load(); });
  document.getElementById("refresh-btn")?.addEventListener("click", load);
  window.addEventListener("online", load);
  if (app) new MutationObserver(() => { if (signedOut()) reset(); else load(); }).observe(app, { attributes: true, attributeFilter: ["class"] });
  load();
  setInterval(load, 20000);
})();
