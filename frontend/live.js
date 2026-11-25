/* NeuroSwarm Live NOC Console (OMi / SCOM / Nagios style)
   - Dual-mode real-time transport: cursor-based /api/v1/event-feed (EVENT-FEED-CONTRACT.md)
     with automatic fallback to /api/v1/live-records + /alerts + /events
   - Real agent work visibility from /api/v1/activity (file edits, commands, workspaces, plans)
     plus multi-agent collaboration tasks from /api/v1/work-board and admin audit trail
   - Multi-signal correlations (same file, same workspace, same session/change, same host, same agent)
   - Zero external CDNs, zero inline handlers (100% CSP-safe). */
(() => {
  "use strict";

  const el = (id) => document.getElementById(id);
  const authGate = el("auth-gate");
  const appEl = el("app");
  const tbody = el("rows");
  const emptyEl = el("empty");
  const detailEl = el("detail");
  const detailQuick = el("detail-quick");
  const orgSwitcher = el("org-switcher");
  const orgBadge = el("org-badge");
  const liveBadge = el("live-badge");
  const feedModeBadge = el("feed-mode-badge");
  const syncEl = el("sync");
  const toastEl = el("toast");
  const caseDialog = el("incident-dialog");
  const eventDialog = el("event-dialog");
  let caseView = null;

  const MAX_RECORDS = 5000;
  const DEFAULT_RENDER_LIMIT = 120;
  const RICH_POLL_MS = 30000;
  const OVERVIEW_POLL_MS = 60000;
  const ALLOWED_IMAGE_MIMES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
  const TIME_FMT = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const SEV_RANK = { CRITICAL: 5, ERROR: 4, WARNING: 3, INFO: 2, NORMAL: 1 };
  const CAT_LABELS = {
    file_edit: "Edit files",
    shell: "Run commands",
    file_read: "Read files",
    plan: "Plan",
    coordination: "Coordinate",
    web: "Web & browser",
    think: "Reason",
    visual: "Images",
    guardrail: "Guardrail",
    audit: "Audit",
    other: "Action",
  };

  const state = {
    user: null,
    org: null,
    memberships: [],
    hosts: [],
    // Separated maps by stream so cursor upserts never get wiped by activity refreshes
    feedMap: new Map(),       // alert:* and event:* (from /event-feed or /live-records)
    historyMap: new Map(),    // older paginated pages from /live-records?before=...
    workMap: new Map(),       // work:* (from /activity steps & plans)
    collabMap: new Map(),     // collab:* (from /work-board collaboration)
    auditMap: new Map(),      // audit:* (admin only from /overview)
    mergedCache: [],
    mergedDirty: true,
    feedCursor: null,
    historyCursor: null,
    useEventFeed: true,
    seenKeys: new Set(),
    newKeys: new Set(),
    bufferedWhilePaused: 0,
    displaySnapshot: null,    // frozen array while paused
    selectedKey: "",
    detailTab: "general",
    perspective: "all",
    scopeHost: "",
    scopeAgent: "",
    scopeWorkspace: "",
    scopeProgram: "",
    scopeTask: "",
    scopeSession: "",
    scopeFile: "",
    scopeRuntime: "",
    pendingEventKey: "",
    returnUrl: "",
    linksByTask: {},
    linksBySession: {},
    windowSec: "all",
    timeFrom: 0,
    timeTo: 0,
    filterSev: "",
    filterKind: "",
    filterCat: "",
    filterStatus: "",
    filterSource: "",
    filterHttp: "",
    search: "",
    groupMode: "none",
    rowTint: true,
    comfortable: false,
    sortKey: "ts",
    sortDir: "desc",
    paused: false,
    intervalMs: 2500,
    timer: null,
    pollSeq: 0,
    lastRichAt: 0,
    lastOverviewAt: 0,
    lastExplorerSig: "",
    lastExplorerAt: 0,
    lastSyncedUrl: "",
    renderLimit: DEFAULT_RENDER_LIMIT,
    renderedFilteredTotal: 0,
    evidenceCache: new Map(),
    eventModalKey: "",
    eventModalOrg: "",
    eventModalOpener: null,
    zoomOverlay: null,
    generation: 0,
    busy: false,
    searchDebounce: null,
    cmdkOpen: false,
    cmdkIdx: 0,
    cmdkItems: [],
  };

  function esc(v) {
    return String(v ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function safeCls(v, fb = "info") {
    const c = String(v ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
    return c || fb;
  }

  function toast(msg) {
    if (!toastEl || !msg) return;
    toastEl.textContent = msg;
    toastEl.classList.remove("hidden");
    clearTimeout(toastEl._t);
    toastEl._t = setTimeout(() => toastEl.classList.add("hidden"), 3000);
  }

  function announceA11y(msg) {
    const region = el("a11y-announce");
    if (!region || !msg) return;
    region.textContent = "";
    requestAnimationFrame(() => { region.textContent = String(msg); });
  }

  function roleOf() { return String(state.user?.role || "viewer").toLowerCase(); }
  function isAdmin() { return roleOf() === "admin"; }
  function canAck() { const r = roleOf(); return r === "admin" || r === "operator"; }

  function normSev(raw, status = "") {
    const s = String(raw || "").toUpperCase();
    const st = String(status || "").toUpperCase();
    if (st === "RESOLVED" || st === "COMPLETED" || st === "DONE" || s === "NORMAL" || s === "OK" || s === "HEALTHY") return "NORMAL";
    if (s.includes("CRIT") || s === "HIGH" || st === "FAILED" || st === "BLOCKED") return "CRITICAL";
    if (s.includes("ERR") || s.includes("FAIL")) return "ERROR";
    if (s.includes("WARN") || s.includes("DEGRAD") || s === "MEDIUM") return "WARNING";
    return "INFO";
  }

  function normStatus(raw) {
    const s = String(raw || "").toUpperCase();
    if (["OPEN", "ACTIVE", "RUNNING", "IN_PROGRESS", "QUEUED", "PENDING"].includes(s)) return "OPEN";
    if (["ACKED", "ACKNOWLEDGED"].includes(s)) return "ACKED";
    if (["RESOLVED", "COMPLETED", "DONE", "FINISHED"].includes(s)) return "RESOLVED";
    return s || "RECORDED";
  }

  function parseTs(v, fallback = 0) {
    if (typeof v === "number" && Number.isFinite(v) && v > 0) return v;
    if (typeof v === "string" && v.trim()) {
      const n = Number(v);
      if (Number.isFinite(n) && n > 0) return n;
      const ms = Date.parse(v.endsWith("Z") || /[+-]\d{2}:\d{2}$/.test(v) ? v : v + "Z");
      if (Number.isFinite(ms) && ms > 0) return ms / 1000;
    }
    return fallback;
  }

  function fmtTime(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return "—";
    const d = new Date(n * 1000);
    return Number.isNaN(d.getTime()) ? "—" : TIME_FMT.format(d);
  }

  function fmtAge(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return "—";
    const d = Math.max(0, Math.floor(Date.now() / 1000 - n));
    if (d < 60) return `${d}s`;
    if (d < 3600) return `${Math.floor(d / 60)}m`;
    if (d < 86400) return `${Math.floor(d / 3600)}h`;
    return `${Math.floor(d / 86400)}d`;
  }

  function shortPath(p) {
    const s = String(p || "").trim();
    if (!s) return "";
    const parts = s.replace(/\\/g, "/").split("/").filter(Boolean);
    return parts.length > 2 ? parts.slice(-2).join("/") : s;
  }

  function safeRelativeUrl(raw) {
    const s = String(raw || "").trim();
    if (!s || !s.startsWith("/") || s.startsWith("//") || /[\r\n\0]/.test(s)) return "";
    return s;
  }

  const VALID_PERSPS = new Set(["all", "agent_work", "file_edits", "files_touched", "shell_cmds", "open_alerts", "crit_warn", "collab", "events", "audit"]);
  const VALID_WINS = new Set(["all", "900", "3600", "86400"]);
  const VALID_SEVS = new Set(["CRITICAL", "ERROR", "WARNING", "INFO", "NORMAL"]);
  const VALID_KINDS = new Set(["Alert", "Agent Work", "Event", "Collaboration", "Audit"]);
  const VALID_CATS = new Set(["file_edit", "shell", "file_read", "plan", "coordination", "web", "guardrail"]);
  const VALID_STATUSES = new Set(["OPEN", "ACKED", "RESOLVED", "RECORDED"]);
  const VALID_GROUPS = new Set(["none", "severity", "agent", "workspace"]);
  const URL_SECRET_RE = /(?:^|\b)(?:bearer\s+[a-z0-9._~+/-]{8,}|(?:sk|pk|ghp|gho|glpat|xox[baprs])-[a-z0-9_-]{8,}|eyJ[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}|(?:token|api_?key|secret|password|passwd|auth)\s*[:=]\s*\S+)/i;

  function normalizeHttpFilter(raw) {
    const s = String(raw || "").trim().toLowerCase();
    if (!s) return "";
    if (s === "errors" || s === "4xx" || s === "5xx") return s;
    if (/^[1-5]\d{2}$/.test(s)) return s;
    return "";
  }

  function formatHttpFilterLabel(val) {
    if (!val) return "";
    if (val === "errors") return "HTTP errors (4xx/5xx)";
    if (val === "4xx") return "HTTP 4xx";
    if (val === "5xx") return "HTTP 5xx";
    return `HTTP ${val}`;
  }

  function ensureHttpFilterOption(val) {
    const sel = el("http-filter");
    if (!sel) return;
    sel.querySelectorAll('option[data-custom-http="1"]').forEach((opt) => {
      if (opt.value !== val) opt.remove();
    });
    if (val && ![...sel.options].some((o) => o.value === val)) {
      const opt = document.createElement("option");
      opt.value = val;
      opt.textContent = formatHttpFilterLabel(val);
      opt.dataset.customHttp = "1";
      sel.appendChild(opt);
    }
    sel.value = val || "";
  }

  function sanitizeFilterToken(raw, maxLen = 128) {
    const s = String(raw || "").trim();
    if (!s || s.length > maxLen || /[\r\n\0<>]/.test(s)) return "";
    if (URL_SECRET_RE.test(s)) return "";
    return s;
  }

  function sanitizeSearchForUrl(raw) {
    const s = String(raw || "").trim();
    if (!s || s.length > 120 || /[\r\n\0]/.test(s)) return "";
    if (URL_SECRET_RE.test(s)) return "";
    return s;
  }

  function parseBoundTs(raw) {
    const s = String(raw || "").trim();
    if (!s || s.length > 40) return 0;
    if (/^\d{9,13}(?:\.\d+)?$/.test(s)) {
      let n = Number(s);
      if (n > 1e12) n = Math.floor(n / 1000);
      n = Math.floor(n);
      return Number.isFinite(n) && n >= 946684800 && n <= 4102444800 ? n : 0;
    }
    const ms = Date.parse(s);
    if (!Number.isFinite(ms)) return 0;
    const sec = Math.floor(ms / 1000);
    return sec >= 946684800 && sec <= 4102444800 ? sec : 0;
  }

  function sanitizeEventKey(raw) {
    const s = String(raw || "").trim();
    if (/^(?:event|alert):[1-9]\d{0,18}$/.test(s)) return s;
    if (/^(?:work|collab|audit):[A-Za-z0-9._:@/-]{1,120}$/.test(s)) return s;
    return "";
  }

  function currentLiveUrl() {
    const qs = new URLSearchParams();
    if (state.perspective && state.perspective !== "all" && VALID_PERSPS.has(state.perspective)) qs.set("persp", state.perspective);
    if (state.scopeTask) qs.set("task", state.scopeTask);
    if (state.scopeSession) qs.set("session", state.scopeSession);
    if (state.scopeHost) qs.set("host", state.scopeHost);
    if (state.scopeAgent) qs.set("agent", state.scopeAgent);
    if (state.scopeRuntime) qs.set("runtime", state.scopeRuntime);
    if (state.scopeWorkspace) qs.set("ws", state.scopeWorkspace);
    if (state.scopeProgram) qs.set("prog", state.scopeProgram);
    if (state.scopeFile) qs.set("file", state.scopeFile);
    if (state.windowSec && state.windowSec !== "all" && VALID_WINS.has(state.windowSec)) qs.set("win", state.windowSec);
    if (state.timeFrom > 0) qs.set("from_ts", String(Math.floor(state.timeFrom)));
    if (state.timeTo > 0) qs.set("to_ts", String(Math.floor(state.timeTo)));
    if (state.filterSev && VALID_SEVS.has(state.filterSev)) qs.set("sev", state.filterSev);
    if (state.filterKind && VALID_KINDS.has(state.filterKind)) qs.set("kind", state.filterKind);
    if (state.filterCat && VALID_CATS.has(state.filterCat)) qs.set("cat", state.filterCat);
    if (state.filterStatus && VALID_STATUSES.has(state.filterStatus)) qs.set("status", state.filterStatus);
    if (state.filterSource) qs.set("source", state.filterSource);
    if (state.filterHttp) qs.set("http", state.filterHttp);
    if (state.groupMode && state.groupMode !== "none" && VALID_GROUPS.has(state.groupMode)) qs.set("group", state.groupMode);
    const safeQ = ""; // Free text may contain output or credentials; keep it local.
    if (safeQ) qs.set("q", safeQ);
    const safeEv = sanitizeEventKey(state.selectedKey || state.pendingEventKey);
    if (safeEv) qs.set("event", safeEv);
    // The return destination can contain arbitrary query text; keep it local.
    const str = qs.toString();
    return "/live" + (str ? `?${str}` : "");
  }

  function syncLiveUrl() {
    if (!window.history?.replaceState) return;
    const nextUrl = currentLiveUrl();
    if (nextUrl === state.lastSyncedUrl && (window.location.pathname + window.location.search) === nextUrl) return;
    state.lastSyncedUrl = nextUrl;
    window.history.replaceState(null, "", nextUrl);
  }

  function applyUrlParams() {
    const p = new URLSearchParams(window.location.search);
    state.scopeTask = sanitizeFilterToken(p.get("task"), 96);
    state.scopeSession = sanitizeFilterToken(p.get("session"), 128);
    state.scopeHost = sanitizeFilterToken(p.get("host"), 128);
    state.scopeAgent = sanitizeFilterToken(p.get("agent"), 96);
    state.scopeRuntime = sanitizeFilterToken(p.get("runtime"), 64);
    state.scopeWorkspace = sanitizeFilterToken(p.get("ws"), 128);
    state.scopeProgram = sanitizeFilterToken(p.get("prog") || p.get("program"), 48);
    state.scopeFile = sanitizeFilterToken(p.get("file"), 220);
    state.filterSource = sanitizeFilterToken(p.get("source") || p.get("event_type"), 64);
    state.pendingEventKey = sanitizeEventKey(p.get("event"));
    state.returnUrl = safeRelativeUrl(p.get("from"));

    const rawPersp = String(p.get("persp") || "").trim();
    state.perspective = VALID_PERSPS.has(rawPersp) ? rawPersp : "all";

    const rawWin = String(p.get("win") || "").trim();
    state.windowSec = VALID_WINS.has(rawWin) ? rawWin : "all";
    if (el("window")) el("window").value = state.windowSec;

    const fromTs = parseBoundTs(p.get("from_ts"));
    const toTs = parseBoundTs(p.get("to_ts"));
    if (fromTs && toTs && fromTs > toTs) {
      state.timeFrom = 0;
      state.timeTo = 0;
    } else {
      state.timeFrom = fromTs;
      state.timeTo = toTs;
    }

    const rawSev = String(p.get("sev") || "").trim().toUpperCase();
    state.filterSev = VALID_SEVS.has(rawSev) ? rawSev : "";
    if (el("severity")) el("severity").value = state.filterSev;

    const rawKind = String(p.get("kind") || "").trim();
    state.filterKind = VALID_KINDS.has(rawKind) ? rawKind : "";
    if (el("kind")) el("kind").value = state.filterKind;

    const rawCat = String(p.get("cat") || "").trim();
    state.filterCat = VALID_CATS.has(rawCat) ? rawCat : "";
    if (el("category")) el("category").value = state.filterCat;

    const rawStatus = String(p.get("status") || "").trim().toUpperCase();
    state.filterStatus = VALID_STATUSES.has(rawStatus) ? rawStatus : "";
    if (el("status")) el("status").value = state.filterStatus;

    state.filterHttp = normalizeHttpFilter(p.get("http"));
    ensureHttpFilterOption(state.filterHttp);

    const rawGroup = String(p.get("group") || "").trim();
    state.groupMode = VALID_GROUPS.has(rawGroup) ? rawGroup : "none";
    if (el("group-mode")) el("group-mode").value = state.groupMode;

    state.search = ""; // Untrusted free-text URL parameters are intentionally ignored.
    if (el("search")) el("search").value = state.search;

    const retEl = el("return-link");
    if (retEl) {
      if (state.returnUrl) {
        retEl.href = state.returnUrl;
        retEl.textContent = state.returnUrl.includes("#activity")
          ? "← Return to Activity Map (filters preserved)"
          : "← Return to Assignment (filters preserved)";
        retEl.classList.remove("hidden");
      } else {
        retEl.classList.add("hidden");
      }
    }
  }

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.message || data.error || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  /* ---------- Record Normalizers ---------- */
  function extractHttpStatus(rawObj, details, cmdOut = "") {
    const candidates = [
      details?.web_resource?.status_code,
      details?.http?.status_code,
      details?.http_status,
      rawObj?.web_resource?.status_code,
      rawObj?.http?.status_code,
      rawObj?.http_status,
    ];
    for (const cand of candidates) {
      if (cand === null || cand === undefined || cand === "") continue;
      const n = Number(cand);
      if (Number.isInteger(n) && n >= 100 && n <= 599) return n;
    }
    if (typeof cmdOut === "string" && cmdOut) {
      const normalized = cmdOut.replace(/\r\n/g, "\n");
      const statusRe = /^(?:<\s*)?HTTP\/(?:\d+(?:\.\d+)?)\s+(\d{3})(?:[ \t]+[^\n]*)?$/gm;
      let m;
      let found = null;
      while ((m = statusRe.exec(normalized)) !== null) {
        const code = Number(m[1]);
        if (code !== 100 && code >= 100 && code <= 599) found = code;
      }
      if (found !== null) return found;
    }
    return null;
  }

  function normalizeFeedRecord(r) {
    const isAlert = String(r.kind || "").toLowerCase() === "alert";
    const src = String(r.source || r.rule_code || r.event_type || "");
    const work = r.work && typeof r.work === "object" ? r.work : null;
    const rawDetails = r.details || r.evidence || r.metadata || {};
    const details = work ? { ...rawDetails, ...work, persisted_journal: true } : rawDetails;
    const isObservedWork = !isAlert && (src === "observed_step" || Boolean(work));
    const httpStatus = extractHttpStatus(r, details);

    if (isObservedWork) {
      const cat = String(details.action || "other");
      const files = Array.isArray(details.files) ? details.files.map(String) : [];
      const ws = String(details.workspace || "");
      const program = String(details.program || "");
      const command = String(details.command || "");
      const currentFolder = String(details.current_folder || "");
      const outcome = String(details.outcome || "recorded");
      const rawSev = normSev(r.severity, outcome);
      const sev =
        ["CRITICAL", "ERROR", "WARNING"].includes(rawSev)
          ? rawSev
          : outcome.toLowerCase().includes("err") || outcome.toLowerCase().includes("fail")
            ? "ERROR"
            : cat === "file_edit"
              ? "NORMAL"
              : "INFO";
      const where = files.length
        ? shortPath(files[0])
        : program
          ? `${shortPath(ws) || "shell"} · ${program}`
          : shortPath(ws) || String(details.tool || "observed_step");
      return {
        key: String(r.key || `event:${r.id}`),
        rawId: r.id,
        kind: "Agent Work",
        severity: sev,
        status: normStatus(outcome),
        rawStatus: outcome,
        ts: parseTs(r.ts || r.created_at),
        createdAt: parseTs(r.created_at || r.ts),
        host_id: String(r.host_id || "console"),
        agent: String(r.agent || details.agent || r.agent_name || r.detail || "agent"),
        harness: String(r.runtime || details.runtime || r.harness || "runtime"),
        source: String(details.tool || "observed_step"),
        eventType: src,
        category: cat,
        categoryLabel: CAT_LABELS[cat] || cat,
        workspace: ws,
        files,
        where,
        program,
        command,
        currentFolder,
        httpStatus,
        message: String(r.message || r.title || CAT_LABELS[cat] || "Agent work"),
        summary: command || (program ? `Program: ${program}${files.length ? " · Files: " + files.join(", ") : ""}` : files.length ? files.join(", ") : String(r.message || "")),
        ackedBy: "",
        ackedAt: 0,
        sessionId: String(details.session || ""),
        taskId: String(details.task_id || r.task_id || ""),
        changeId: "",
        fileBasis: String(details.basis || "journal"),
        sessionFiles: { edited: cat === "file_edit" ? files : [], delivered: [], read: cat === "file_read" ? files : [] },
        details,
        canAck: false,
      };
    }

    const rawState = String(r.state || r.status || (isAlert ? "OPEN" : "RECORDED")).toUpperCase();
    const files = Array.isArray(details.files) ? details.files.map(String) : [];
    const ws = String(details.workspace || "");
    const rawOriginId =
      r.source_event_id ??
      r.evidence_event_id ??
      details.source_event_id ??
      details.trigger_event_id ??
      details.event_id ??
      null;
    const originEventId = /^[1-9]\d{0,18}$/.test(String(rawOriginId ?? "")) ? String(rawOriginId) : null;
    const alertSession = String(r.session || details.session || (details.last_step && details.last_step.session) || "");
    const alertProgram = String(details.program || "");
    const alertCommand = String(details.command || "");
    const cat = isAlert
      ? "guardrail"
      : src.includes("work_") || src === "plan"
        ? "plan"
        : src.includes("error")
          ? "shell"
          : "other";
    return {
      key: String(r.key || `${isAlert ? "alert" : "event"}:${r.id}`),
      rawId: r.id,
      evidenceEventId: originEventId,
      evidenceEventOrg: r.organization ?? state.org?.id ?? null,
      kind: isAlert ? "Alert" : "Event",
      severity: normSev(r.severity, rawState),
      status: normStatus(rawState),
      rawStatus: rawState,
      ts: parseTs(r.ts || r.updated_at || r.created_at),
      createdAt: parseTs(r.created_at || r.ts),
      host_id: String(r.host_id || "console"),
      agent: String(r.agent || r.agent_name || details.agent_name || details.comm || (isAlert ? "host guardrail" : r.detail || "observer")),
      harness: String(r.runtime || r.harness || details.harness || (isAlert ? "guardrail" : "observer")),
      source: src,
      category: cat,
      categoryLabel: CAT_LABELS[cat] || "Event",
      workspace: ws,
      files,
      where: files.length ? shortPath(files[0]) : shortPath(ws) || src,
      program: alertProgram,
      command: alertCommand,
      httpStatus,
      message: String(r.title || r.message || src || "Record"),
      summary: String(r.summary || r.detail || r.message || ""),
      ackedBy: String(r.acked_by || ""),
      ackedAt: parseTs(r.acked_at),
      owner: r.owner || "",
      signalCount: r.occurrence_count,
      countIsMinimum: r.count_is_minimum,
      previousCase: r.previous_id,
      sessionId: alertSession,
      taskId: String(details.task_id || ""),
      changeId: String(details.task_id || ""),
      sessionFiles: { edited: [], delivered: [], read: [] },
      details,
      canAck: isAlert && rawState === "OPEN" && canAck(),
    };
  }

  function normalizeActivitySessions(activity) {
    const next = new Map();
    const sessions = Array.isArray(activity?.sessions) ? activity.sessions : [];
    const labels = activity?.category_labels || CAT_LABELS;

    for (const s of sessions) {
      const hostId = String(s.host_id || activity?.host || "host");
      const agent = String(s.agent_name || s.workspace_label || "agent");
      const harness = String(s.harness_name || s.harness || "runtime");
      const model = String(s.model || "");
      const ws = String(s.workspace_label || shortPath(s.workspace) || "");
      const sid = String(s.session_id || `${hostId}:${agent}`);
      const sessionFiles = {
        edited: Array.isArray(s.files_edited) ? s.files_edited : [],
        delivered: Array.isArray(s.files_delivered) ? s.files_delivered : [],
        read: Array.isArray(s.files_read) ? s.files_read : [],
      };

      const steps = Array.isArray(s.steps) ? s.steps : [];
      steps.forEach((st, idx) => {
        const cat = String(st.category || "other");
        const stepFiles = Array.isArray(st.files) ? st.files.map(String) : [];
        const stepTs = parseTs(st.time, parseTs(s.updated_at) - Math.max(0, steps.length - 1 - idx));
        const stStatus = normStatus(st.status || (s.status === "active" && idx === steps.length - 1 ? "OPEN" : "RESOLVED"));
        const sev = String(st.status || "").toLowerCase().includes("fail") || String(st.status || "").toLowerCase().includes("err")
          ? "ERROR"
          : cat === "file_edit"
            ? "NORMAL"
            : "INFO";
        const where = stepFiles.length ? shortPath(stepFiles[0]) : ws;
        const k = `work:${sid}:step:${idx}:${String(st.time || "")}`;
        next.set(k, {
          key: k,
          rawId: k,
          evidenceEventId: st.event_id || null,
          evidenceEventOrg: st.event_org ?? null,
          kind: "Agent Work",
          severity: sev,
          status: stStatus,
          rawStatus: String(st.status || "recorded"),
          ts: stepTs,
          createdAt: stepTs,
          host_id: hostId,
          agent,
          harness: model ? `${harness} · ${model}` : harness,
          source: String(st.tool || cat),
          category: cat,
          categoryLabel: labels[cat] || CAT_LABELS[cat] || cat,
          workspace: ws,
          files: stepFiles,
          where: where || harness,
          program: String(st.program || ""),
          command: String(st.command || ""),
          currentFolder: String(s.current_folder || st.current_folder || ""),
          httpStatus: extractHttpStatus(st, st),
          message: String(st.label || "Agent action"),
          summary: stepFiles.length ? stepFiles.slice(0, 3).map(shortPath).join(", ") : String(st.program ? `Program: ${st.program}` : ""),
          sessionSummary: String(s.what_done || ""),
          ackedBy: "",
          ackedAt: 0,
          sessionId: sid,
          taskId: String(st.task_id || s.task_id || ""),
          changeId: "",
          fileBasis: String(st.file_basis || ""),
          sessionFiles,
          details: {
            tool: st.tool,
            category: cat,
            file_basis: st.file_basis || "session",
            files: stepFiles,
            workspace: s.workspace || ws,
            model,
            provider: s.provider_label || s.provider || "",
            provider_basis: s.provider_basis || "",
            tokens_used: s.tokens_used || 0,
          },
          canAck: false,
        });
      });

      // Also include active / completed plan milestones if no steps or in_progress plan exists
      const plans = Array.isArray(s.plan) ? s.plan : [];
      plans.forEach((p, idx) => {
        if (!p || !p.text) return;
        const pStatus = normStatus(p.status);
        const pFiles = Array.isArray(p.named_files) ? p.named_files.map(String) : [];
        const pTs = parseTs(s.updated_at);
        const k = `work:${sid}:plan:${idx}`;
        next.set(k, {
          key: k,
          rawId: k,
          evidenceEventId: p.event_id || null,
          evidenceEventOrg: p.event_org ?? null,
          kind: "Agent Work",
          severity: pStatus === "RESOLVED" ? "NORMAL" : "INFO",
          status: pStatus,
          rawStatus: String(p.status || "pending"),
          ts: pTs,
          createdAt: pTs,
          host_id: hostId,
          agent,
          harness: model ? `${harness} · ${model}` : harness,
          source: "plan",
          category: "plan",
          categoryLabel: "Plan",
          workspace: ws,
          files: pFiles,
          where: pFiles.length ? shortPath(pFiles[0]) : ws,
          program: "",
          message: `[Plan] ${String(p.text)}`,
          summary: pFiles.length ? pFiles.slice(0, 3).map(shortPath).join(", ") : "",
          sessionSummary: String(s.what_done || ""),
          ackedBy: "",
          ackedAt: 0,
          sessionId: sid,
          taskId: String(p.task_id || s.task_id || ""),
          changeId: "",
          fileBasis: pFiles.length ? "mentioned" : "",
          sessionFiles,
          details: { plan_status: p.status, named_files: pFiles, workspace: s.workspace || ws, model },
          canAck: false,
        });
      });
    }
    return next;
  }

  function normalizeCollaboration(workBoard) {
    const next = new Map();
    const changes = Array.isArray(workBoard?.collaboration?.changes) ? workBoard.collaboration.changes : [];
    for (const ch of changes) {
      const tasks = Array.isArray(ch.tasks) ? ch.tasks : [];
      for (const t of tasks) {
        const st = normStatus(t.status);
        const k = `collab:${ch.id}:${t.id}`;
        next.set(k, {
          key: k,
          rawId: t.id,
          kind: "Collaboration",
          severity: normSev(t.status, t.status),
          status: st,
          rawStatus: String(t.status || "recorded"),
          ts: parseTs(t.updated_at || ch.updated_at),
          createdAt: parseTs(t.updated_at || ch.updated_at),
          host_id: "channel",
          agent: String(t.agent || "unassigned"),
          harness: "collaboration",
          source: String(ch.id || "change"),
          category: "coordination",
          categoryLabel: "Coordinate",
          workspace: "",
          files: [],
          where: String(ch.title || "change").slice(0, 36),
          message: String(t.title || "Assigned task"),
          summary: String(t.result || "No formal result recorded yet."),
          ackedBy: "",
          ackedAt: 0,
          sessionId: "",
          taskId: String(t.id || ""),
          changeId: String(ch.id || ""),
          sessionFiles: { edited: [], delivered: [], read: [] },
          details: { change_id: ch.id, change_title: ch.title, task_id: t.id, parent_id: t.parent_id || null, status: t.status },
          canAck: false,
        });
      }
    }
    return next;
  }

  function normalizeAudit(overview) {
    const next = new Map();
    if (!isAdmin() || !Array.isArray(overview?.audit)) return next;
    overview.audit.forEach((au, idx) => {
      const aid = au.id !== undefined && au.id !== null ? au.id : `${au.created_at || 0}:${idx}`;
      const action = String(au.action || "audit");
      const detail = String(au.detail || "").trim();
      const k = `audit:${aid}`;
      next.set(k, {
        key: k,
        rawId: aid,
        kind: "Audit",
        severity: "INFO",
        status: "RECORDED",
        rawStatus: "recorded",
        ts: parseTs(au.created_at),
        createdAt: parseTs(au.created_at),
        host_id: "console",
        agent: String(au.actor || "system"),
        harness: "audit",
        source: action,
        category: "audit",
        categoryLabel: "Audit",
        workspace: "",
        files: [],
        where: "console",
        message: detail ? `${action} — ${detail}` : action,
        summary: detail || action,
        ackedBy: "",
        ackedAt: 0,
        sessionId: "",
        changeId: "",
        sessionFiles: { edited: [], delivered: [], read: [] },
        details: { actor: au.actor, action, detail },
        canAck: false,
      });
    });
    return next;
  }

  function markPoolDirty() {
    state.mergedDirty = true;
  }

  function getSearchHay(r) {
    if (r._hay === undefined) {
      r._hay = `${r.message} ${r.summary} ${r.host_id} ${r.agent} ${r.harness} ${r.workspace} ${r.where} ${(r.files || []).join(" ")} ${r.source} ${r.severity} ${r.status} ${r.program || ""} ${r.command || ""}`.toLowerCase();
    }
    return r._hay;
  }

  function getShortFiles(r) {
    if (r._shortFiles === undefined) {
      r._shortFiles = (r.files || []).map((f) => shortPath(f).toLowerCase()).filter(Boolean);
    }
    return r._shortFiles;
  }

  function getRecordByKey(key) {
    if (!key) return null;
    if (state.paused && Array.isArray(state.displaySnapshot)) {
      return state.displaySnapshot.find((r) => r.key === key) || null;
    }
    return (
      state.feedMap.get(key) ||
      state.historyMap.get(key) ||
      state.workMap.get(key) ||
      state.collabMap.get(key) ||
      state.auditMap.get(key) ||
      null
    );
  }

  function getEvidenceEventId(item) {
    if (!item) return "";
    if (typeof item.key === "string" && item.key.startsWith("event:") && /^[1-9]\d{0,18}$/.test(String(item.rawId))) {
      return String(item.rawId);
    }
    if (item.evidenceEventId && /^[1-9]\d{0,18}$/.test(String(item.evidenceEventId))) {
      if (item.evidenceEventOrg === null || item.evidenceEventOrg === undefined || sameActiveOrg(item.evidenceEventOrg)) {
        return String(item.evidenceEventId);
      }
    }
    return "";
  }

  function isNumericEventId(item) {
    return Boolean(getEvidenceEventId(item));
  }

  function allMergedRecords() {
    if (state.paused && Array.isArray(state.displaySnapshot)) return state.displaySnapshot;
    if (!state.mergedDirty && Array.isArray(state.mergedCache)) return state.mergedCache;
    const byKey = new Map();
    for (const r of state.historyMap.values()) byKey.set(r.key, r);
    for (const r of state.feedMap.values()) byKey.set(r.key, r);

    // Deduplicate live activity tail steps already persisted as observed_step journal events
    if (state.workMap.size > 0) {
      const journalSigs = new Set();
      for (const r of byKey.values()) {
        if (r.kind === "Agent Work" && r.sessionId) {
          const f0 = shortPath((r.files && r.files[0]) || "");
          journalSigs.add(`${r.sessionId}|${r.category}|${Math.round(r.ts / 2)}|${f0}`);
        }
      }
      for (const r of state.workMap.values()) {
        const f0 = shortPath((r.files && r.files[0]) || "");
        const sig = `${r.sessionId}|${r.category}|${Math.round(r.ts / 2)}|${f0}`;
        if (!journalSigs.has(sig)) byKey.set(r.key, r);
      }
    }
    for (const r of state.collabMap.values()) byKey.set(r.key, r);
    for (const r of state.auditMap.values()) byKey.set(r.key, r);

    const merged = [...byKey.values()];
    if (merged.length > MAX_RECORDS) {
      merged.sort((a, b) => b.ts - a.ts);
      merged.length = MAX_RECORDS;
    }
    state.mergedCache = merged;
    state.mergedDirty = false;
    return merged;
  }

  /* ---------- Multi-Signal Correlation Engine ---------- */
  function findCorrelations(item, pool) {
    if (!item) return [];
    const sf = getShortFiles(item);
    const itemFiles = sf.length ? new Set(sf) : null;
    const hits = [];
    for (let i = 0; i < pool.length; i++) {
      const other = pool[i];
      if (other.key === item.key) continue;
      const reasons = [];
      let score = 0;

      if (item.sessionId && other.sessionId && item.sessionId === other.sessionId) {
        reasons.push("Same session");
        score += 5;
      }
      if (item.changeId && other.changeId && item.changeId === other.changeId) {
        reasons.push("Same change");
        score += 5;
      }
      let matchedFile = false;
      if (itemFiles && other.files && other.files.length) {
        const osf = getShortFiles(other);
        for (let j = 0; j < osf.length; j++) {
          if (itemFiles.has(osf[j])) {
            reasons.push(`Same file: ${shortPath(other.files[j])}`);
            score += 6;
            matchedFile = true;
            break;
          }
        }
      }
      if (item.workspace && other.workspace && item.workspace === other.workspace && !matchedFile) {
        reasons.push("Same workspace");
        score += 3;
      }
      if (item.agent && other.agent && item.agent === other.agent && item.kind !== "Audit") {
        reasons.push("Same agent");
        score += 2;
      }
      if (item.host_id && other.host_id && item.host_id === other.host_id && item.host_id !== "console" && item.host_id !== "channel") {
        const nearTime = Math.abs((item.ts || 0) - (other.ts || 0)) <= 600;
        if (nearTime || other.kind === "Alert" || item.kind === "Alert") {
          reasons.push(nearTime ? "Same host (±10m)" : "Same host");
          score += nearTime ? 3 : 1;
        }
      }
      if (score > 0) hits.push({ item: other, reasons, score });
    }
    hits.sort((a, b) => b.score - a.score || Math.abs(a.item.ts - item.ts) - Math.abs(b.item.ts - item.ts));
    return hits.slice(0, 18);
  }

  /* ---------- Filtering & Sorting ---------- */
  function matchesHttpFilter(httpStatus, filterHttp) {
    if (!filterHttp) return true;
    if (typeof httpStatus !== "number" || !Number.isFinite(httpStatus)) return false;
    if (filterHttp === "errors") return httpStatus >= 400 && httpStatus <= 599;
    if (filterHttp === "4xx") return httpStatus >= 400 && httpStatus <= 499;
    if (filterHttp === "5xx") return httpStatus >= 500 && httpStatus <= 599;
    if (/^[1-5]\d{2}$/.test(filterHttp)) return httpStatus === Number(filterHttp);
    return true;
  }

  function buildFilterContext() {
    return {
      q: state.search.trim().toLowerCase(),
      nowSec: Date.now() / 1000,
      winSec: state.windowSec === "all" ? 0 : Number(state.windowSec) || 0,
      timeFrom: state.timeFrom || 0,
      timeTo: state.timeTo || 0,
      wantFile: state.scopeFile ? state.scopeFile.toLowerCase() : "",
      wantProg: state.scopeProgram ? state.scopeProgram.toLowerCase() : "",
      wantSource: state.filterSource ? state.filterSource.toLowerCase() : "",
      filterHttp: state.filterHttp || "",
      linkedForTask: state.scopeTask ? state.linksByTask[state.scopeTask] : null,
    };
  }

  function recordMatchesFilter(r, ctx) {
    if (ctx.winSec > 0 && r.ts > 0 && ctx.nowSec - r.ts > ctx.winSec) return false;
    if (ctx.timeFrom > 0 && (!r.ts || r.ts < ctx.timeFrom)) return false;
    if (ctx.timeTo > 0 && (!r.ts || r.ts > ctx.timeTo)) return false;
    const persp = state.perspective;
    if (persp === "open_alerts" && !(r.kind === "Alert" && r.status === "OPEN")) return false;
    if (persp === "crit_warn" && r.severity !== "CRITICAL" && r.severity !== "ERROR" && r.severity !== "WARNING") return false;
    if (persp === "agent_work" && r.kind !== "Agent Work") return false;
    if (persp === "file_edits" && r.category !== "file_edit") return false;
    if (persp === "files_touched" && !((r.files && r.files.length > 0) || r.category === "file_edit" || r.category === "file_read" || r.category === "visual")) return false;
    if (persp === "shell_cmds" && r.category !== "shell") return false;
    if (persp === "collab" && r.kind !== "Collaboration") return false;
    if (persp === "events" && r.kind !== "Event") return false;
    if (persp === "audit" && r.kind !== "Audit") return false;

    if (state.scopeHost && r.host_id !== state.scopeHost) return false;
    if (state.scopeAgent && r.agent !== state.scopeAgent) return false;
    if (state.scopeWorkspace && r.workspace !== state.scopeWorkspace) return false;
    if (ctx.wantProg && String(r.program || "").toLowerCase() !== ctx.wantProg) return false;
    if (state.scopeTask) {
      const linkedForTask = ctx.linkedForTask;
      const explicitMatch = r.taskId === state.scopeTask || (r.kind === "Collaboration" && r.rawId === state.scopeTask);
      const turnMatch =
        linkedForTask &&
        linkedForTask.status === "linked" &&
        linkedForTask.basis === "explicit_turn_session" &&
        linkedForTask.session_id &&
        r.sessionId === linkedForTask.session_id &&
        (!r.taskId || r.taskId === state.scopeTask);
      if (!explicitMatch && !turnMatch) return false;
    }
    if (state.scopeSession && r.sessionId !== state.scopeSession) return false;
    if (ctx.wantFile) {
      const files = r.files || [];
      let matchesFile = false;
      for (let i = 0; i < files.length; i++) {
        const f = String(files[i]).toLowerCase();
        if (f === ctx.wantFile || f.endsWith("/" + ctx.wantFile) || ctx.wantFile.endsWith("/" + f)) {
          matchesFile = true;
          break;
        }
      }
      if (!matchesFile) return false;
    }

    if (state.filterSev && r.severity !== state.filterSev) return false;
    if (state.filterKind && r.kind !== state.filterKind) return false;
    if (state.filterCat && r.category !== state.filterCat) return false;
    if (state.filterStatus && r.status !== state.filterStatus) return false;
    if (ctx.wantSource && String(r.source || "").toLowerCase() !== ctx.wantSource && String(r.eventType || "").toLowerCase() !== ctx.wantSource) return false;
    if (ctx.filterHttp && !matchesHttpFilter(r.httpStatus, ctx.filterHttp)) return false;

    if (ctx.q && !getSearchHay(r).includes(ctx.q)) return false;
    return true;
  }

  function getFiltered(pool) {
    const ctx = buildFilterContext();
    const list = [];
    for (let i = 0; i < pool.length; i++) {
      if (recordMatchesFilter(pool[i], ctx)) list.push(pool[i]);
    }

    const dir = state.sortDir === "asc" ? 1 : -1;
    list.sort((a, b) => {
      let cmp = 0;
      if (state.sortKey === "severity") cmp = (SEV_RANK[a.severity] || 0) - (SEV_RANK[b.severity] || 0);
      else if (state.sortKey === "ts") cmp = a.ts - b.ts;
      else cmp = String(a[state.sortKey] || "").localeCompare(String(b[state.sortKey] || ""));
      return cmp !== 0 ? cmp * dir : b.ts - a.ts;
    });
    return list;
  }

  /* ---------- Render View Explorer ---------- */
  function renderExplorer(pool, force = false) {
    let agentWorkCnt = 0;
    let fileEditsCnt = 0;
    let filesTouchedCnt = 0;
    let shellCmdsCnt = 0;
    let openAlertsCnt = 0;
    let critWarnCnt = 0;
    let collabCnt = 0;
    let eventsCnt = 0;
    let auditCnt = 0;

    const hCounts = new Map();
    const hCrit = new Set();
    const hWarn = new Set();
    const aCounts = new Map();
    const wCounts = new Map();
    const fCounts = new Map();

    for (let i = 0; i < pool.length; i++) {
      const r = pool[i];
      if (r.kind === "Agent Work") agentWorkCnt++;
      else if (r.kind === "Collaboration") collabCnt++;
      else if (r.kind === "Event") eventsCnt++;
      else if (r.kind === "Audit") auditCnt++;
      else if (r.kind === "Alert" && r.status === "OPEN") openAlertsCnt++;

      if (r.category === "file_edit") fileEditsCnt++;
      if (r.category === "shell") shellCmdsCnt++;
      if ((r.files && r.files.length > 0) || r.category === "file_edit" || r.category === "file_read" || r.category === "visual") {
        filesTouchedCnt++;
      }
      if (r.severity === "CRITICAL" || r.severity === "ERROR" || r.severity === "WARNING") critWarnCnt++;

      if (r.host_id) {
        hCounts.set(r.host_id, (hCounts.get(r.host_id) || 0) + 1);
        if (r.status === "OPEN") {
          if (r.severity === "CRITICAL" || r.severity === "ERROR") hCrit.add(r.host_id);
          else if (r.severity === "WARNING") hWarn.add(r.host_id);
        }
      }
      if (r.agent && (r.kind === "Agent Work" || r.kind === "Collaboration")) {
        aCounts.set(r.agent, (aCounts.get(r.agent) || 0) + 1);
      }
      if (r.workspace) wCounts.set(r.workspace, (wCounts.get(r.workspace) || 0) + 1);
      if (r.files && r.files.length) {
        for (let j = 0; j < r.files.length; j++) {
          const fp = String(r.files[j] || "").trim();
          if (fp) fCounts.set(fp, (fCounts.get(fp) || 0) + 1);
        }
      }
    }

    const hosts = [...new Set([...state.hosts.map((h) => h.host_id), ...hCounts.keys()])].filter(Boolean);
    const agents = [...aCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14);
    const wsList = [...wCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const fileList = [...fCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);

    const sig = [
      pool.length, agentWorkCnt, fileEditsCnt, filesTouchedCnt, shellCmdsCnt, openAlertsCnt, critWarnCnt, collabCnt, eventsCnt, auditCnt,
      state.perspective, state.scopeHost, state.scopeAgent, state.scopeWorkspace, state.scopeFile,
      hosts.map((h) => `${h}:${hCounts.get(h) || 0}:${hCrit.has(h) ? 2 : hWarn.has(h) ? 1 : 0}`).join(","),
      agents.map(([a, c]) => `${a}:${c}`).join(","),
      wsList.map(([w, c]) => `${w}:${c}`).join(","),
      fileList.map(([f, c]) => `${f}:${c}`).join(","),
    ].join("|");

    if (!force && sig === state.lastExplorerSig) return;
    state.lastExplorerSig = sig;
    state.lastExplorerAt = Date.now();

    const persp = [
      { id: "all", label: "All Live Stream", count: pool.length, dot: "online" },
      { id: "agent_work", label: "Agent Work (All)", count: agentWorkCnt, dot: "work" },
      { id: "file_edits", label: "File Edits Only", count: fileEditsCnt, dot: "online" },
      { id: "files_touched", label: "Files & Media", count: filesTouchedCnt, dot: "online" },
      { id: "shell_cmds", label: "Commands & Tests", count: shellCmdsCnt, dot: "work" },
      { id: "open_alerts", label: "Open Alerts", count: openAlertsCnt, dot: "warn" },
      { id: "crit_warn", label: "Critical & Warning", count: critWarnCnt, dot: "crit" },
      { id: "collab", label: "Collaboration", count: collabCnt, dot: "online" },
      { id: "events", label: "System Events", count: eventsCnt, dot: "online" },
    ];
    if (isAdmin()) persp.push({ id: "audit", label: "Audit Trail", count: auditCnt, dot: "" });

    el("perspectives").innerHTML = persp
      .map(
        (p) => {
          const isActive = state.perspective === p.id && !state.scopeHost && !state.scopeAgent && !state.scopeWorkspace && !state.scopeFile;
          return `<li><button type="button" class="tree-btn${isActive ? " active" : ""}" aria-pressed="${isActive ? "true" : "false"}" data-persp="${esc(p.id)}">
          <span class="tree-name"><i class="dot ${p.dot}" aria-hidden="true"></i>${esc(p.label)}</span>
          <span class="tree-cnt">${p.count}</span>
        </button></li>`;
        }
      )
      .join("");

    el("host-tree").innerHTML = hosts.length
      ? hosts
          .map((hid) => {
            const dot = hCrit.has(hid) ? "crit" : hWarn.has(hid) ? "warn" : "online";
            const isActive = state.scopeHost === hid;
            return `<li><button type="button" class="tree-btn${isActive ? " active" : ""}" aria-pressed="${isActive ? "true" : "false"}" data-scope-host="${esc(hid)}">
              <span class="tree-name"><i class="dot ${dot}" aria-hidden="true"></i>${esc(hid)}</span>
              <span class="tree-cnt">${hCounts.get(hid) || 0}</span>
            </button></li>`;
          })
          .join("")
      : '<li class="muted" style="padding:4px 8px;font-size:.76rem;">No hosts reporting</li>';

    el("agent-tree").innerHTML = agents.length
      ? agents
          .map(
            ([ag, cnt]) => {
              const isActive = state.scopeAgent === ag;
              return `<li><button type="button" class="tree-btn${isActive ? " active" : ""}" aria-pressed="${isActive ? "true" : "false"}" data-scope-agent="${esc(ag)}">
              <span class="tree-name"><i class="dot work" aria-hidden="true"></i>${esc(ag)}</span>
              <span class="tree-cnt">${cnt}</span>
            </button></li>`;
            }
          )
          .join("")
      : '<li class="muted" style="padding:4px 8px;font-size:.76rem;">No agent activity yet</li>';

    el("workspace-tree").innerHTML = wsList.length
      ? wsList
          .map(
            ([ws, cnt]) => {
              const isActive = state.scopeWorkspace === ws;
              return `<li><button type="button" class="tree-btn${isActive ? " active" : ""}" aria-pressed="${isActive ? "true" : "false"}" data-scope-ws="${esc(ws)}">
              <span class="tree-name"><i class="dot online" aria-hidden="true"></i>${esc(ws)}</span>
              <span class="tree-cnt">${cnt}</span>
            </button></li>`;
            }
          )
          .join("")
      : '<li class="muted" style="padding:4px 8px;font-size:.76rem;">No shared workspaces</li>';

    const fileTree = el("file-tree");
    if (fileTree) {
      fileTree.innerHTML = fileList.length
        ? fileList
            .map(
              ([fp, cnt]) => {
                const isActive = state.scopeFile === fp;
                return `<li><button type="button" class="tree-btn${isActive ? " active" : ""}" aria-pressed="${isActive ? "true" : "false"}" data-scope-file="${esc(fp)}" title="${esc(fp)}">
                <span class="tree-name"><i class="dot online" aria-hidden="true"></i>${esc(shortPath(fp))}</span>
                <span class="tree-cnt">${cnt}</span>
              </button></li>`;
              }
            )
            .join("")
        : '<li class="muted" style="padding:4px 8px;font-size:.76rem;">No files recorded yet</li>';
    }
  }

  /* ---------- Render Main Table & Status Bar ---------- */
  const SENSITIVE_QUERY_RE = /^(?:token|access_token|refresh_token|id_token|api_?key|key|secret|client_secret|password|passwd|pwd|auth|authorization|bearer|jwt|sig|signature|session|sid|code|x-amz-signature|x-amz-credential|x-amz-security-token)$/i;

  function redactDisplayUrl(raw) {
    const s = String(raw || "").trim().replace(/^['"<]+|['">),.;]+$/g, "");
    if (!s || !/^https?:/i.test(s)) return null;
    try {
      const u = new URL(s);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      const hadCreds = Boolean(u.username || u.password);
      u.username = "";
      u.password = "";
      let redactedParams = false;
      const parts = [];
      for (const [k, v] of u.searchParams.entries()) {
        if (SENSITIVE_QUERY_RE.test(k)) {
          parts.push(`${encodeURIComponent(k)}=[REDACTED]`);
          redactedParams = true;
        } else {
          parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
        }
      }
      const qs = parts.join("&");
      const display = `${u.protocol}//${u.host}${u.pathname}${qs ? "?" + qs : ""}`;
      const short = `${u.host}${u.pathname === "/" ? "" : u.pathname}`;
      const clickable = !hadCreds && !redactedParams && !display.includes("[REDACTED]") && !display.includes("***");
      return { display, short, href: clickable ? u.toString() : "", host: u.host, redacted: hadCreds || redactedParams };
    } catch {
      return null;
    }
  }

  function redactCommandForDisplay(cmd) {
    const raw = String(cmd || "");
    if (!raw) return "";
    return raw.replace(/https?:\/\/[^\s'"]+/gi, (match) => {
      const parsed = redactDisplayUrl(match);
      return parsed ? parsed.display : match;
    });
  }

  function redactLocationValue(rawVal) {
    const val = String(rawVal || "").trim();
    if (!val) return null;
    if (/^https?:/i.test(val)) return redactDisplayUrl(val);
    if (val.startsWith("/")) {
      try {
        const u = new URL(val, window.location.origin);
        let redactedParams = false;
        const parts = [];
        for (const [k, v] of u.searchParams.entries()) {
          if (SENSITIVE_QUERY_RE.test(k)) {
            parts.push(`${encodeURIComponent(k)}=[REDACTED]`);
            redactedParams = true;
          } else {
            parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
          }
        }
        const qs = parts.join("&");
        const display = `${u.pathname}${qs ? "?" + qs : ""}`;
        return { display, short: u.pathname, href: "", host: "", redacted: redactedParams };
      } catch {
        // fall through to generic query masking
      }
    }
    let redacted = false;
    const masked = val.replace(/([?&])([^=&\s]+)=([^&\s]+)/g, (full, sep, k) => {
      if (SENSITIVE_QUERY_RE.test(k)) {
        redacted = true;
        return `${sep}${k}=[REDACTED]`;
      }
      return full;
    });
    return { display: masked, short: masked, href: "", host: "", redacted };
  }

  const SENSITIVE_HEADER_RE = /^([<>]\s*)?(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*(.+)$/i;
  const LOCATION_HEADER_RE = /^([<>]\s*)?(location|content-location)\s*:\s*(.+)$/i;

  function redactHeaderLine(line) {
    const raw = String(line ?? "");
    const locMatch = LOCATION_HEADER_RE.exec(raw);
    if (locMatch) {
      const prefix = locMatch[1] || "";
      const hdrName = locMatch[2];
      const locInfo = redactLocationValue(locMatch[3]);
      return `${prefix}${hdrName}: ${locInfo ? locInfo.display : "[REDACTED]"}`;
    }
    const secMatch = SENSITIVE_HEADER_RE.exec(raw);
    if (secMatch) {
      return `${secMatch[1] || ""}${secMatch[2]}: [REDACTED]`;
    }
    return redactCommandForDisplay(raw);
  }

  function redactHeaderBlock(block) {
    return String(block || "")
      .replace(/\r\n/g, "\n")
      .split("\n")
      .map(redactHeaderLine)
      .join("\n")
      .trim();
  }

  function redactOutputForDisplay(rawOut) {
    const text = String(rawOut || "");
    if (!text) return "";
    return text
      .replace(/\r\n/g, "\n")
      .split("\n")
      .map((line) => (LOCATION_HEADER_RE.test(line) || SENSITIVE_HEADER_RE.test(line) ? redactHeaderLine(line) : redactCommandForDisplay(line)))
      .join("\n");
  }

  function classifyBrowserStep(item, ev) {
    if (!item) return null;
    const wr = (ev && (ev.web_resource || ev.browser_action || ev.web)) || (item.details && (item.details.web_resource || item.details.browser_action || item.details.web)) || null;
    const toolRaw = String(wr?.tool || wr?.action_kind || item.source || item.details?.tool || "").toLowerCase();
    const msgRaw = String(item.message || "").toLowerCase();
    const isBrowserLike =
      item.category === "web" ||
      Boolean(wr && !wr.http_client) ||
      /(?:browser|web_search|search_web|web_fetch|fetch_url|snapshot|screenshot|submit_secret|list_logins|vault|takeover|navigate)/.test(toolRaw);
    if (!isBrowserLike) return null;
    if (String(item.program || "").toLowerCase() === "curl" || String(item.program || "").toLowerCase() === "wget") return null;

    let kind = "web";
    let label = "Web action";
    if (/(?:submit_secret|list_logins|vault|request_takeover|fill_card)/.test(toolRaw)) {
      kind = "credential";
      label = "Credential step";
    } else if (/(?:snapshot|screenshot|capture_screen|get_window_state|get_desktop_state)/.test(toolRaw) || /\bsnapshot\b|\bscreenshot\b/.test(msgRaw) || wr?.kind === "snapshot") {
      kind = "snapshot";
      label = "Page snapshot";
    } else if (/(?:search_web|web_search|brave_search|\bsearch\b)/.test(toolRaw) || /^search:/i.test(item.message || "") || wr?.kind === "search") {
      kind = "search";
      label = "Web search";
    } else if (/(?:open|navigate|goto|web_fetch|fetch_url|browse|\bpage\b)/.test(toolRaw) || wr?.kind === "visit") {
      kind = "visit";
      label = "Page visit";
    } else if (/(?:click|type|fill_fields|press|hover|scroll|select_option|set_checked|drag|run_script|\bact\b|handle_dialog|close_tab|list_tabs)/.test(toolRaw) || wr?.kind === "interact") {
      kind = "interact";
      label = "Browser action";
    }
    const rawUrl = wr?.url || item.details?.url || "";
    const urlInfo = redactDisplayUrl(rawUrl);
    const query = String(wr?.query || item.details?.query || (/^search:\s*(.+)$/i.exec(item.message || "")?.[1] || "")).trim();
    const title = String(wr?.title || item.details?.page_title || item.details?.title || "").trim();
    const excerpt = String(wr?.response_excerpt || wr?.excerpt || wr?.body || "").trim();
    const statusCode = Number.isFinite(Number(wr?.status_code)) && Number(wr?.status_code) >= 100 ? Number(wr.status_code) : null;
    return { kind, label, tool: String(item.source || ""), urlInfo, query, title, excerpt, statusCode };
  }

  function parseHttpTrace(item, ev) {
    const wr = (ev && (ev.http || ev.web_resource)) || (item?.details && (item.details.http || item.details.web_resource)) || null;
    const prog = String((ev && ev.program) || item?.program || "").toLowerCase();
    const cmdIn = String((ev && ev.command_input) || item?.command || "").trim();
    const cmdOut = typeof ev?.command_output === "string" ? ev.command_output : "";
    const looksLikeHttpCmd = prog === "curl" || prog === "wget" || /(?:^|&&|\|\||;|\s)(?:curl|wget)\s/i.test(cmdIn);
    if (!looksLikeHttpCmd && !(wr && (wr.status_code || wr.method || (wr.url && prog)))) return null;

    let method = String(wr?.method || "").toUpperCase();
    if (!method && cmdIn) {
      const mExplicit = cmdIn.match(/(?:^|\s)(?:-X|--request)\s+['"]?([A-Za-z]+)['"]?/);
      if (mExplicit) method = mExplicit[1].toUpperCase();
      else if (/(?:^|\s)(?:-I|--head)(?:\s|$)/.test(cmdIn)) method = "HEAD";
      else if (/(?:^|\s)(?:-d|--data(?:-[a-z]+)?|-F|--form|--json)(?:\s|=)/.test(cmdIn)) method = "POST";
      else method = "GET";
    }

    let urlInfo = redactDisplayUrl(wr?.url || "");
    if (!urlInfo && cmdIn) {
      const urlMatches = cmdIn.match(/https?:\/\/[^\s'"]+/gi) || [];
      for (const cand of urlMatches) {
        const parsed = redactDisplayUrl(cand);
        if (parsed) { urlInfo = parsed; break; }
      }
    }

    let statusCode = Number.isFinite(Number(wr?.status_code ?? ev?.http_status)) && Number(wr?.status_code ?? ev?.http_status) >= 100
      ? Number(wr?.status_code ?? ev?.http_status)
      : null;
    let statusText = String(wr?.status_text || ev?.http_status_text || "").trim();
    let responseHeaders = "";
    let responseBody = String(wr?.response_excerpt || wr?.body || "").trim();

    if (cmdOut) {
      const normalized = cmdOut.replace(/\r\n/g, "\n");
      const statusRe = /^HTTP\/(?:\d+(?:\.\d+)?)\s+(\d{3})(?:[ \t]+([^\n]*))?$/gm;
      let m;
      let lastStatusEnd = -1;
      let lastHeaderStart = -1;
      while ((m = statusRe.exec(normalized)) !== null) {
        const code = Number(m[1]);
        if (code === 100) continue; // skip 100 Continue
        if (statusCode === null) {
          statusCode = code;
          statusText = (m[2] || "").trim();
        } else if (m.index > lastStatusEnd) {
          statusCode = code;
          statusText = (m[2] || "").trim();
        }
        lastHeaderStart = m.index;
        lastStatusEnd = m.index + m[0].length;
      }
      if (lastHeaderStart >= 0) {
        const tail = normalized.slice(lastHeaderStart);
        const sep = tail.indexOf("\n\n");
        if (sep >= 0) {
          responseHeaders = tail.slice(0, sep).trim();
          if (!responseBody) responseBody = tail.slice(sep + 2).trim();
        } else {
          responseHeaders = tail.trim();
        }
      } else if (!responseBody) {
        responseBody = normalized.trim();
      }
    }

    let formattedBody = responseBody;
    let isJson = false;
    if (responseBody && (responseBody.startsWith("{") || responseBody.startsWith("["))) {
      try {
        formattedBody = JSON.stringify(JSON.parse(responseBody), null, 2);
        isJson = true;
      } catch {
        formattedBody = responseBody;
      }
    }
    if (formattedBody.length > 2400) {
      formattedBody = formattedBody.slice(0, 2400) + "\n… (excerpt truncated)";
    }

    // Every recorded response in order (302 -> 401). The recorded hops win; otherwise read the status lines.
    let hops = Array.isArray(wr?.hops)
      ? wr.hops.filter(h => h && Number.isInteger(h.status_code)).slice(0, 10)
          .map(h => ({ code: h.status_code, text: String(h.status_text || ""), location: redactDisplayUrl(String(h.location || ""))?.display || (String(h.location || "").startsWith("/") ? String(h.location) : "") }))
      : [];
    if (!hops.length && cmdOut) {
      const lines = [...cmdOut.replace(/\r\n/g, "\n").matchAll(/^HTTP\/(?:\d+(?:\.\d+)?)\s+(\d{3})(?:[ \t]+([^\n]*))?$/gm)]
        .filter(m => m[1] !== "100");
      if (lines.length > 1) hops = lines.slice(0, 10).map(m => ({ code: Number(m[1]), text: (m[2] || "").trim(), location: "" }));
    }
    if (hops.length < 2) hops = [];
    const exitCode = ev && ev.exit_code !== null && ev.exit_code !== undefined ? Number(ev.exit_code) : null;
    const isHttpError = statusCode !== null && statusCode >= 400;
    const exitZeroHttpError = isHttpError && exitCode === 0;
    return {
      method: method || "GET",
      urlInfo,
      statusCode,
      statusText,
      isHttpError,
      exitZeroHttpError,
      responseHeaders,
      formattedBody,
      isJson,
      exitCode,
      hops,
    };
  }

  function normalizeReasonCode(raw) {
    const s = String(raw || "").trim().toLowerCase().replace(/[\s-]+/g, "_");
    if (!s) return "";
    if (["empty_output", "output_empty", "empty", "no_output"].includes(s)) return "empty_output";
    if (["capture_disabled", "output_disabled", "commands_disabled", "share_disabled", "disabled", "opt_out"].includes(s)) return "capture_disabled";
    if (["outside_scope", "out_of_scope", "unscoped", "outside_project", "outside_authorized_roots", "cd_failed", "outside_root"].includes(s)) return "outside_scope";
    if (["protected", "protected_command", "protected_file", "redacted", "sensitive_path", "privacy_redacted", "secret_redacted"].includes(s)) return "protected";
    if (["no_file_target", "inline_command", "not_applicable"].includes(s)) return "no_file_target";
    if (["not_recorded", "unknown", "legacy", "unavailable"].includes(s)) return "not_recorded";
    return s;
  }

  function classifyEvidenceReason(item, ev) {
    const rawCode =
      ev?.output_reason ||
      ev?.evidence_reason ||
      ev?.missing_reason ||
      ev?.redaction_reason ||
      ev?.evidence_status ||
      item?.details?.output_reason ||
      item?.details?.evidence_reason ||
      item?.details?.missing_reason ||
      item?.details?.redaction_reason ||
      "";
    let code = normalizeReasonCode(rawCode);
    const flags = ev?.capture_flags || item?.details?.capture_flags || null;
    if (!code && typeof ev?.command_output === "string" && ev.command_output === "") {
      code = "empty_output";
    } else if (!code && flags && (flags.share_command_output === false || flags.share_commands === false)) {
      code = "capture_disabled";
    } else if (!code && (ev?.outside_scope === true || item?.details?.outside_scope === true)) {
      code = "outside_scope";
    } else if (!code && (ev?.protected === true || item?.details?.protected === true)) {
      code = "protected";
    } else if (!code) {
      code = "not_recorded";
    }
    const copy = {
      empty_output: {
        badge: "Empty output",
        tone: "info",
        text: "Command completed and its captured output is empty (0 bytes).",
      },
      capture_disabled: {
        badge: "Capture disabled",
        tone: "warn",
        text: "Command or output capture is disabled on this host (enable SWARMCONTROL_SHARE_COMMANDS / SWARMCONTROL_SHARE_COMMAND_OUTPUT to record it).",
      },
      outside_scope: {
        badge: "Outside authorized folders",
        tone: "warn",
        text: "Command ran outside authorized project folders (or its directory change failed), so output was withheld.",
      },
      protected: {
        badge: "Withheld by privacy policy",
        tone: "warn",
        text: "Command output was withheld because it touched protected credentials, secrets, or sensitive paths.",
      },
      not_recorded: {
        badge: "Not recorded",
        tone: "muted",
        text: "Not recorded — historical event or no capture metadata was saved for this step.",
      },
    };
    return { code, ...(copy[code] || copy.not_recorded) };
  }

  function classifyFilesReason(item, ev) {
    const rawCode =
      ev?.files_reason ||
      ev?.missing_files_reason ||
      item?.details?.files_reason ||
      item?.details?.missing_files_reason ||
      ev?.redaction_reason ||
      item?.details?.redaction_reason ||
      "";
    let code = normalizeReasonCode(rawCode);
    const flags = ev?.capture_flags || item?.details?.capture_flags || null;
    const cmdIn = String((ev && ev.command_input) || item?.command || "");
    if (!code && (ev?.outside_scope === true || item?.details?.outside_scope === true)) {
      code = "outside_scope";
    } else if (!code && (ev?.protected === true || item?.details?.protected === true)) {
      code = "protected";
    } else if (!code && flags && flags.share_files === false) {
      code = "capture_disabled";
    } else if (
      !code &&
      (item?.category === "web" ||
        String(item?.program || "").toLowerCase() === "curl" ||
        String(item?.program || "").toLowerCase() === "wget" ||
        /\bpython3?\s+-(?:c|m)\b/.test(cmdIn))
    ) {
      code = "no_file_target";
    } else if (!code) {
      code = "not_recorded";
    }
    const copy = {
      outside_scope: {
        badge: "Outside authorized folders",
        tone: "warn",
        text: "No file path shown because the target path was outside this host's authorized project folders.",
      },
      capture_disabled: {
        badge: "Capture disabled",
        tone: "warn",
        text: "File path capture is disabled for this host.",
      },
      protected: {
        badge: "Protected file",
        tone: "warn",
        text: "File path was withheld by privacy policy (such as .env, keys, or credential files).",
      },
      no_file_target: {
        badge: "No workspace file target",
        tone: "info",
        text: "This action ran inline code or a web/network request with no local workspace file target.",
      },
      not_recorded: {
        badge: "Not recorded",
        tone: "muted",
        text: "No file path was recorded for this event. Historical event or no file path capture metadata available.",
      },
    };
    return { code, ...(copy[code] || copy.not_recorded) };
  }

  function renderEvidenceGapSummary(pool) {
    const counts = new Map();
    let totalMissingFiles = 0;
    for (let i = 0; i < pool.length; i++) {
      const r = pool[i];
      if (r.kind !== "Agent Work") continue;
      if ((r.category === "shell" || r.category === "file_read" || r.category === "file_edit") && !(r.files && r.files.length)) {
        const key = r.program || r.source || r.category;
        counts.set(key, (counts.get(key) || 0) + 1);
        totalMissingFiles++;
      }
    }
    if (!totalMissingFiles) return "";
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
    return `
      <section class="ev-section ev-gap-section" aria-label="Commands missing file evidence">
        <h3><span>Commands without recorded files (${totalMissingFiles})</span><span class="muted">Loaded stream breakdown</span></h3>
        <div class="chips">
          ${top.map(([prog, cnt]) => `<button type="button" class="chip-btn" data-gap-search="${esc(prog)}" title="Search ${esc(prog)} in stream"><code>${esc(prog)}</code> · ${cnt}</button>`).join("")}
        </div>
      </section>`;
  }

  function renderRow(r) {
    const sel = r.key === state.selectedKey ? " selected" : "";
    const fresh = state.newKeys.has(r.key) ? " is-new" : "";
    const sevCls = safeCls(r.severity, "info");
    const kindCls = safeCls(r.kind.replace(/\s+/g, "-"), "event");
    const catCls = safeCls(r.category, "other");
    const stCls = safeCls(r.status, "recorded");
    const progHtml = r.program ? `<span class="prog-badge" title="Program executed">${esc(r.program)}</span>` : "";
    const httpBadgeHtml = typeof r.httpStatus === "number"
      ? `<span class="http-pill row-http-pill ${r.httpStatus >= 400 ? "fail" : r.httpStatus >= 300 ? "warn" : "ok"}" data-row-http="${esc(r.httpStatus)}">HTTP ${esc(r.httpStatus)}</span>`
      : "";
    const browserStep = classifyBrowserStep(r, null);
    const browserBadge = browserStep
      ? `<span class="browser-kind-pill bk-${safeCls(browserStep.kind, "web")}" title="${esc(browserStep.tool || browserStep.label)}">${esc(browserStep.label)}</span>`
      : "";
    const rowMsg = browserStep && /^web request$/i.test(String(r.message || "").trim())
      ? (browserStep.query
          ? browserStep.query
          : browserStep.urlInfo
            ? (browserStep.title ? `${browserStep.title} · ${browserStep.urlInfo.short}` : browserStep.urlInfo.short)
            : (browserStep.tool || browserStep.label))
      : r.message;
    const rowWhere = browserStep?.urlInfo ? browserStep.urlInfo.host : (r.where || "—");
    const rowAria = [
      r.severity,
      r.kind,
      r.status,
      typeof r.httpStatus === "number" ? `HTTP ${r.httpStatus}` : "",
      r.host_id,
      r.agent,
      rowMsg,
    ].filter(Boolean).join(", ");
    return `<tr class="row sev-${sevCls}${sel}${fresh}" data-key="${esc(r.key)}" tabindex="0" aria-selected="${r.key === state.selectedKey ? "true" : "false"}" aria-label="${esc(rowAria)}">
      <td class="col-sev"><span class="sev-pill ${sevCls}">${esc(r.severity)}</span></td>
      <td class="col-kind"><span class="kind-pill ${kindCls}">${esc(r.kind)}</span></td>
      <td class="col-cat"><span class="cat-pill cat-${catCls}">${esc(r.categoryLabel)}</span></td>
      <td class="col-state"><span class="state-pill ${stCls}">${esc(r.status)}</span></td>
      <td class="col-time num">${esc(fmtTime(r.ts))}</td>
      <td class="col-age num">${esc(fmtAge(r.ts))}</td>
      <td class="col-host" title="${esc(r.host_id)}">${esc(r.host_id)}</td>
      <td class="col-agent" title="${esc(r.agent)} · ${esc(r.harness)}">${esc(r.agent)}</td>
      <td class="col-where" title="${esc((r.files || []).join(", ") || browserStep?.urlInfo?.display || r.workspace)}"><code>${esc(rowWhere)}</code></td>
      <td class="col-msg" title="${esc(rowMsg)}${r.command ? " · " + esc(r.command) : ""}">${progHtml}${httpBadgeHtml}${browserBadge}<strong>${esc(rowMsg)}</strong>${r.summary && !String(rowMsg || "").includes(r.summary.slice(0, 24)) && !(browserStep && /^web request$/i.test(r.summary.trim())) ? ` <span class="muted">— ${esc(r.summary)}</span>` : ""}</td>
    </tr>`;
  }

  function renderActiveChips() {
    const chips = [];
    if (state.perspective !== "all") chips.push({ id: "perspective", label: `Perspective: ${state.perspective.replace(/_/g, " ")}` });
    if (state.scopeTask) chips.push({ id: "scopeTask", label: `Assignment: ${state.scopeTask}` });
    if (state.scopeSession) chips.push({ id: "scopeSession", label: `Session: ${state.scopeSession}` });
    if (state.scopeFile) chips.push({ id: "scopeFile", label: `File: ${shortPath(state.scopeFile)}` });
    if (state.scopeHost) chips.push({ id: "scopeHost", label: `Host: ${state.scopeHost}` });
    if (state.scopeAgent) chips.push({ id: "scopeAgent", label: `Agent: ${state.scopeAgent}` });
    if (state.scopeWorkspace) chips.push({ id: "scopeWorkspace", label: `Folder: ${state.scopeWorkspace}` });
    if (state.scopeProgram) chips.push({ id: "scopeProgram", label: `Program: ${state.scopeProgram}` });
    if (state.windowSec !== "all") chips.push({ id: "windowSec", label: `Window: ${el("window")?.selectedOptions?.[0]?.textContent || state.windowSec}` });
    if (state.timeFrom || state.timeTo) {
      const bounds = `${state.timeFrom ? fmtTime(state.timeFrom) : "start"} → ${state.timeTo ? fmtTime(state.timeTo) : "now"}`;
      chips.push({ id: "timeBounds", label: `Range: ${bounds}` });
    }
    if (state.filterSev) chips.push({ id: "filterSev", label: `Severity: ${state.filterSev}` });
    if (state.filterKind) chips.push({ id: "filterKind", label: `Source: ${state.filterKind}` });
    if (state.filterCat) chips.push({ id: "filterCat", label: `Action: ${CAT_LABELS[state.filterCat] || state.filterCat}` });
    if (state.filterStatus) chips.push({ id: "filterStatus", label: `State: ${state.filterStatus}` });
    if (state.filterSource) chips.push({ id: "filterSource", label: `Event type: ${state.filterSource}` });
    if (state.filterHttp) chips.push({ id: "filterHttp", label: `HTTP: ${formatHttpFilterLabel(state.filterHttp)}` });
    if (state.search.trim()) chips.push({ id: "search", label: `Search: “${state.search.trim()}”` });
    const banner = el("scope-banner");
    const box = el("active-chips");
    if (!chips.length) {
      banner.classList.add("hidden");
      if (box) box.innerHTML = "";
      return;
    }
    if (box) {
      box.innerHTML =
        '<span class="muted" style="font-weight:700;font-size:.73rem;">Active filters:</span>' +
        chips.map((c) => `<button type="button" class="filter-chip" data-clear-chip="${esc(c.id)}" aria-label="Remove filter: ${esc(c.label)}" title="Remove filter">${esc(c.label)} <span class="x" aria-hidden="true">×</span></button>`).join("");
    }
    banner.classList.remove("hidden");
  }

  function updateStatusBar(pool, filteredTotal, shownCount) {
    let crit = 0, warn = 0, info = 0, norm = 0, openAlerts = 0, workCnt = 0, recent5m = 0;
    const cutoff5m = Date.now() / 1000 - 300;
    for (let i = 0; i < pool.length; i++) {
      const r = pool[i];
      if (r.severity === "CRITICAL" || r.severity === "ERROR") crit++;
      else if (r.severity === "WARNING") warn++;
      else if (r.severity === "INFO") info++;
      else if (r.severity === "NORMAL") norm++;
      if (r.kind === "Alert" && r.status === "OPEN") openAlerts++;
      if (r.kind === "Agent Work") workCnt++;
      if (r.ts > cutoff5m) recent5m++;
    }
    el("count").textContent =
      shownCount < filteredTotal
        ? `${shownCount} shown · ${filteredTotal} of ${pool.length} records`
        : `${filteredTotal} of ${pool.length} records`;
    el("cnt-critical").textContent = String(crit);
    el("cnt-warning").textContent = String(warn);
    el("cnt-info").textContent = String(info);
    el("cnt-normal").textContent = String(norm);
    document.querySelectorAll(".statusbar [data-quick-sev]").forEach((btn) => {
      btn.setAttribute("aria-pressed", String(state.filterSev === btn.dataset.quickSev));
    });
    el("open-alerts-cnt").textContent = `${openAlerts} open alert${openAlerts === 1 ? "" : "s"}`;
    el("work-steps-cnt").textContent = `${workCnt} agent action${workCnt === 1 ? "" : "s"}`;
    const rateEl = el("rate-badge");
    if (rateEl) rateEl.textContent = `${recent5m} / 5m`;

    const moreBtn = el("show-more-rows");
    if (moreBtn) {
      const hasMore = filteredTotal > shownCount;
      moreBtn.classList.toggle("hidden", !hasMore);
      if (hasMore) {
        moreBtn.textContent = `Show more (${shownCount}/${filteredTotal})`;
      }
    }
  }

  function selectRowKey(key, opts = {}) {
    if (!key) return;
    const prevKey = state.selectedKey;
    state.selectedKey = key;
    if (prevKey && prevKey !== key) {
      const prevRow = tbody.querySelector(`tr[data-key="${CSS.escape(prevKey)}"]`);
      if (prevRow) {
        prevRow.classList.remove("selected");
        prevRow.setAttribute("aria-selected", "false");
      }
    }
    const nextRow = tbody.querySelector(`tr[data-key="${CSS.escape(key)}"]`);
    if (nextRow) {
      nextRow.classList.add("selected");
      nextRow.setAttribute("aria-selected", "true");
      if (opts.scrollIntoView) nextRow.scrollIntoView({ block: "nearest" });
    }
    const sel = getRecordByKey(key);
    el("ack-selected").classList.toggle("hidden", !(sel && sel.canAck));
    renderDetails(sel, allMergedRecords());
    syncLiveUrl();
  }

  function applyIncrementalUpdate(addedRecords, updatedRecords) {
    const pool = allMergedRecords();
    const ctx = buildFilterContext();
    const matchingAdded = [];
    for (let i = 0; i < addedRecords.length; i++) {
      if (recordMatchesFilter(addedRecords[i], ctx)) matchingAdded.push(addedRecords[i]);
    }
    matchingAdded.sort((a, b) => b.ts - a.ts);

    let domMutated = false;
    if (matchingAdded.length) {
      const toInsert = [];
      for (let i = 0; i < matchingAdded.length; i++) {
        const rec = matchingAdded[i];
        const existing = tbody.querySelector(`tr[data-key="${CSS.escape(rec.key)}"]`);
        if (existing) {
          existing.outerHTML = renderRow(rec);
          domMutated = true;
        } else {
          toInsert.push(rec);
        }
      }
      if (toInsert.length) {
        emptyEl.hidden = true;
        tbody.insertAdjacentHTML("afterbegin", toInsert.map(renderRow).join(""));
        state.renderedFilteredTotal += toInsert.length;
        domMutated = true;
      }
      while (tbody.children.length > state.renderLimit) {
        tbody.lastElementChild.remove();
      }
      if (!state.selectedKey && toInsert.length) {
        selectRowKey(toInsert[0].key);
      }
    }

    let selectedTouched = false;
    for (let i = 0; i < updatedRecords.length; i++) {
      const rec = updatedRecords[i];
      if (rec.key === state.selectedKey) selectedTouched = true;
      const existing = tbody.querySelector(`tr[data-key="${CSS.escape(rec.key)}"]`);
      if (existing) {
        existing.outerHTML = renderRow(rec);
        domMutated = true;
      }
    }

    if (domMutated || addedRecords.length || updatedRecords.length) {
      const shownCount = tbody.querySelectorAll("tr[data-key]").length;
      if (state.renderedFilteredTotal < shownCount) state.renderedFilteredTotal = shownCount;
      updateStatusBar(pool, state.renderedFilteredTotal, shownCount);
      if (Date.now() - state.lastExplorerAt >= 10000) {
        renderExplorer(pool);
      }
      if (selectedTouched) {
        const sel = getRecordByKey(state.selectedKey);
        el("ack-selected").classList.toggle("hidden", !(sel && sel.canAck));
        renderDetails(sel, pool);
      }
    }
    if (caseView?.updated && state.feedMap.get(`alert:${caseView.id}`)?.ts > caseView.updated) {
      el("incident-refresh").textContent = "Refresh · case updated";
    }
  }

  function render(opts = {}) {
    appEl.classList.toggle("row-tint", state.rowTint);
    appEl.classList.toggle("comfortable", state.comfortable);
    const wrap = el("table-wrap");
    const prevScroll = wrap ? wrap.scrollTop : 0;
    const pool = allMergedRecords();
    if (!opts.skipExplorer) renderExplorer(pool);
    const filtered = getFiltered(pool);
    state.renderedFilteredTotal = filtered.length;
    renderActiveChips();

    if (state.pendingEventKey && filtered.some((r) => r.key === state.pendingEventKey)) {
      state.selectedKey = state.pendingEventKey;
      state.pendingEventKey = "";
    }

    let visible = filtered;
    if (filtered.length > state.renderLimit) {
      visible = filtered.slice(0, state.renderLimit);
    }

    const prevSelKey = state.selectedKey;
    if (state.selectedKey && !filtered.some((r) => r.key === state.selectedKey)) {
      state.selectedKey = visible[0]?.key || "";
    } else if (!state.selectedKey && visible.length) {
      state.selectedKey = visible[0].key;
    }

    if (!visible.length) {
      tbody.innerHTML = "";
      emptyEl.textContent = state.scopeTask
        ? `No confirmed steps or files explicitly linked to assignment "${state.scopeTask}" in this organization (link unknown).`
        : pool.length
          ? "No records match the active filters."
          : "No events, alerts, or agent work recorded for this organization yet.";
      emptyEl.hidden = false;
    } else {
      emptyEl.hidden = true;
      if (state.groupMode === "severity") {
        const order = ["CRITICAL", "ERROR", "WARNING", "INFO", "NORMAL"];
        let html = "";
        for (const sev of order) {
          const grp = visible.filter((r) => r.severity === sev);
          if (!grp.length) continue;
          html += `<tr class="group-row"><td colspan="10">Severity: ${esc(sev)} (${grp.length})</td></tr>`;
          html += grp.map(renderRow).join("");
        }
        tbody.innerHTML = html;
      } else if (state.groupMode === "agent" || state.groupMode === "workspace") {
        const field = state.groupMode === "agent" ? "agent" : "workspace";
        const groups = new Map();
        for (const r of visible) {
          const k = String(r[field] || "(unspecified)");
          if (!groups.has(k)) groups.set(k, []);
          groups.get(k).push(r);
        }
        let html = "";
        for (const [gName, items] of groups.entries()) {
          html += `<tr class="group-row"><td colspan="10">${esc(field === "agent" ? "Agent" : "Workspace")}: ${esc(gName)} (${items.length})</td></tr>`;
          html += items.map(renderRow).join("");
        }
        tbody.innerHTML = html;
      } else {
        tbody.innerHTML = visible.map(renderRow).join("");
      }
      if (wrap && prevScroll > 0) wrap.scrollTop = prevScroll;
    }

    const sel = (state.selectedKey && getRecordByKey(state.selectedKey)) || visible[0] || null;
    el("ack-selected").classList.toggle("hidden", !(sel && sel.canAck));
    document.querySelectorAll(".tbl thead th").forEach((th) => {
      const btn = th.querySelector("[data-sort]");
      if (!btn) return;
      if (btn.dataset.sort === state.sortKey) {
        th.setAttribute("aria-sort", state.sortDir === "asc" ? "ascending" : "descending");
      } else {
        th.setAttribute("aria-sort", "none");
      }
    });
    updateStatusBar(pool, filtered.length, visible.length);

    if (!opts.skipDetails && !(opts.skipDetailsIfSame && prevSelKey && prevSelKey === state.selectedKey)) {
      renderDetails(sel, pool);
    }
    if (caseView?.updated && state.feedMap.get(`alert:${caseView.id}`)?.ts > caseView.updated) {
      el("incident-refresh").textContent = "Refresh · case updated";
    }
    syncLiveUrl();
  }

  /* ---------- On-Demand Event Evidence & Popup Investigation Modal ---------- */
  const evidenceInFlight = new Map();
  const evidenceSlots = new WeakMap();
  const evidenceReadAt = new WeakMap();
  const EXECUTION_RECHECK_MS = 5000;

  function isSafeRasterImage(img) {
    if (!img || typeof img !== "object") return false;
    const url = String(img.url || "").trim();
    const mime = String(img.mime_type || "").toLowerCase().trim();
    return url.startsWith("/api/v1/events/") && !url.startsWith("//") && !/[\r\n\0]/.test(url) && ALLOWED_IMAGE_MIMES.has(mime);
  }

  function formatBytes(n) {
    const v = Number(n);
    if (!Number.isFinite(v) || v <= 0) return "";
    if (v < 1024) return `${v} B`;
    if (v < 1048576) return `${(v / 1024).toFixed(1)} KB`;
    return `${(v / 1048576).toFixed(1)} MB`;
  }

  function fetchEventEvidence(item, orgId, fresh = false) {
    const evId = getEvidenceEventId(item);
    if (!evId || !orgId) return Promise.resolve(null);
    const cacheKey = `${orgId}:${evId}`;
    if (evidenceInFlight.has(cacheKey)) {
      return evidenceInFlight.get(cacheKey);
    }
    if (!fresh && state.evidenceCache.has(cacheKey) && item.category !== "file_edit") {
      return Promise.resolve(state.evidenceCache.get(cacheKey));
    }
    const qs = new URLSearchParams({ organization_id: String(orgId) });
    const req = api(`/api/v1/events/${encodeURIComponent(evId)}/evidence?${qs.toString()}`)
      .then((data) => {
        if (data && String(data.organization) === String(orgId) && String(data.event_id) === evId) {
          evidenceReadAt.set(data, performance.now());
          state.evidenceCache.set(cacheKey, data);
          const inferredHttp = extractHttpStatus(data, data, data.command_output || "");
          if (inferredHttp !== null) {
            if (item && item.httpStatus == null) item.httpStatus = inferredHttp;
            const liveRec = item?.key ? (state.feedMap.get(item.key) || state.historyMap.get(item.key)) : null;
            if (liveRec && liveRec.httpStatus == null) liveRec.httpStatus = inferredHttp;
          }
          return data;
        }
        return null;
      })
      .finally(() => {
        evidenceInFlight.delete(cacheKey);
      });
    evidenceInFlight.set(cacheKey, req);
    return req;
  }

  function eventFilePaths(item, ev) {
    return [...new Set([...(item.files || []), ...(ev?.files || []),
      ...(ev?.text_previews || []).map(p => p.path), ...(ev?.images || []).map(p => p.path)]
      .filter(path => typeof path === "string" && path.trim()))];
  }

  function renderEvidenceHtml(ev, item, opts = {}) {
    const sections = [];
    const evId = getEvidenceEventId(item);
    if (item && item.kind === "Alert" && evId && !opts.filesTab) {
      const evRecordMsg = ev?.record?.message ? ` · ${ev.record.message}` : "";
      sections.push(`
        <section class="ev-section ev-origin-banner" aria-label="Original triggering event">
          <h3>
            <span>Original triggering result (Event #${esc(evId)}${esc(evRecordMsg)})</span>
            <button type="button" class="btn small" data-open-origin-event="${esc(evId)}" data-org="${esc(state.org?.id || "")}">Open original event #${esc(evId)} ↗</button>
          </h3>
        </section>`);
    }
    if (ev?.verification) {
      const proof = ev.verification;
      const tests = (proof.tests || []).filter(t => Number.isSafeInteger(t.event_id) && t.event_id > 0);
      const links = tests.map(t =>
        `<li><button type="button" class="btn" data-verification-test="${t.event_id}" data-org="${esc(ev.organization)}">${t.result === "passed" ? "Passed" : "Failed"} · ${esc(t.program || "Test")} · Open command and output</button></li>`
      ).join("");
      sections.push(`<section class="ev-section" aria-label="Verification after edit"><h3>Verification after edit</h3>
        ${tests.length ? `<p>Task <code>${esc(proof.task_id)}</code> · ${esc(proof.actor)} · Revision <code title="${esc(proof.revision)}">${esc(proof.revision.slice(0, 12))}</code></p><ul>${links}</ul>`
                       : '<p class="muted">No verification recorded</p>'}</section>`);
    }

    const httpTrace = !opts.filesTab ? parseHttpTrace(item, ev) : null;
    if (httpTrace) {
      const statusCls = httpTrace.statusCode === null ? "neutral" : httpTrace.statusCode >= 400 ? "fail" : httpTrace.statusCode >= 300 ? "warn" : "ok";
      const statusLabel = httpTrace.statusCode !== null
        ? `HTTP ${httpTrace.statusCode}${httpTrace.statusText ? " " + httpTrace.statusText : ""}`
        : "HTTP status not recorded";
      const mismatchCallout = httpTrace.exitZeroHttpError
        ? `<div class="ev-http-callout" data-http-mismatch="1" role="status"><strong>HTTP ${esc(httpTrace.statusCode)}</strong> returned even though <code>${esc((ev && ev.program) || item.program || "curl")}</code> exited 0.</div>`
        : "";
      const urlHtml = httpTrace.urlInfo
        ? `<div class="ev-http-url"><span class="http-method-pill">${esc(httpTrace.method)}</span>${
            httpTrace.urlInfo.href
              ? `<a href="${esc(httpTrace.urlInfo.href)}" target="_blank" rel="noopener noreferrer" class="ev-url-link">${esc(httpTrace.urlInfo.display)} ↗</a>`
              : `<code class="ev-url-code">${esc(httpTrace.urlInfo.display)}</code>`
          }${httpTrace.urlInfo.redacted ? '<span class="ev-source-badge snap">Credentials redacted</span>' : ""}</div>`
        : `<div class="ev-http-url"><span class="http-method-pill">${esc(httpTrace.method)}</span><span class="muted">URL not recorded</span></div>`;
      const headersHtml = httpTrace.responseHeaders
        ? `<details class="ev-http-headers"><summary>Response headers</summary><pre class="ev-text-pre">${esc(httpTrace.responseHeaders)}</pre></details>`
        : "";
      const hopClass = code => code >= 400 ? "fail" : code >= 300 ? "warn" : "ok";
      const hopsHtml = httpTrace.hops.length
        ? `<ol class="ev-http-hops" aria-label="Redirect chain">${httpTrace.hops.map((h, i) => `<li data-hop="${i + 1}">
            <span class="http-pill ${hopClass(h.code)}">HTTP ${esc(h.code)}${h.text ? " " + esc(h.text) : ""}</span>
            ${h.location ? `<span class="ev-http-hop-to">→ <code>${esc(h.location)}</code></span>` : i < httpTrace.hops.length - 1 ? '<span class="muted">→ next response</span>' : '<span class="muted">final response</span>'}
          </li>`).join("")}</ol>`
        : "";
      const bodyHtml = httpTrace.formattedBody
        ? `<div class="ev-http-body-wrap"><div class="ev-text-head"><span>Response excerpt${httpTrace.isJson ? " (JSON)" : ""}</span>${ev?.output_truncated ? '<span class="trunc-pill">Truncated</span>' : ""}</div><pre class="ev-text-pre">${esc(httpTrace.formattedBody)}</pre></div>`
        : "";
      sections.push(`
        <section class="ev-section ev-http-card${httpTrace.isHttpError ? " is-http-error" : ""}" aria-label="HTTP request and response" data-http-status="${esc(httpTrace.statusCode ?? "")}">
          <h3>
            <span>HTTP Request &amp; Response</span>
            <span class="ev-cmd-badges">
              <span class="http-pill ${statusCls}">${esc(statusLabel)}</span>
              ${httpTrace.exitCode !== null ? `<span class="exit-pill ${httpTrace.exitCode === 0 ? "ok" : "fail"}">Exit ${esc(httpTrace.exitCode)}</span>` : ""}
            </span>
          </h3>
          ${mismatchCallout}
          ${urlHtml}
          ${hopsHtml}
          ${bodyHtml}
          ${headersHtml}
        </section>`);
    }

    const browserStep = !opts.filesTab ? classifyBrowserStep(item, ev) : null;
    if (browserStep) {
      const bUrl = browserStep.urlInfo
        ? (browserStep.urlInfo.href
            ? `<a href="${esc(browserStep.urlInfo.href)}" target="_blank" rel="noopener noreferrer" class="ev-url-link">${esc(browserStep.urlInfo.display)} ↗</a>`
            : `<code class="ev-url-code">${esc(browserStep.urlInfo.display)}</code>`)
        : "";
      const bRows = [
        browserStep.query ? `<div><strong>Search query:</strong> <code>${esc(browserStep.query)}</code></div>` : "",
        bUrl ? `<div><strong>URL:</strong> ${bUrl}${browserStep.urlInfo?.redacted ? ' <span class="ev-source-badge snap">Credentials redacted</span>' : ""}</div>` : "",
        browserStep.title ? `<div><strong>Page title:</strong> ${esc(browserStep.title)}</div>` : "",
        browserStep.kind === "credential" ? '<div class="muted">Credential and vault contents are never captured.</div>' : "",
      ].filter(Boolean).join("");
      const bExcerpt = browserStep.excerpt
        ? `<pre class="ev-text-pre" style="margin-top:6px;">${esc(browserStep.excerpt)}</pre>`
        : "";
      sections.push(`
        <section class="ev-section ev-browser-card" aria-label="Web and browser action" data-browser-kind="${esc(browserStep.kind)}">
          <h3>
            <span>Web &amp; Browser Action</span>
            <span class="ev-cmd-badges">
              <span class="browser-kind-pill bk-${safeCls(browserStep.kind, "web")}">${esc(browserStep.label)}</span>
              ${browserStep.statusCode ? `<span class="http-pill ${browserStep.statusCode >= 400 ? "fail" : "ok"}">HTTP ${esc(browserStep.statusCode)}</span>` : ""}
            </span>
          </h3>
          ${bRows || `<p class="muted" style="margin:0;">Tool: <code>${esc(browserStep.tool || "browser")}</code> · No URL or response excerpt was recorded for this step.</p>`}
          ${bExcerpt}
        </section>`);
    }

    const cmdIn = (ev && ev.command_input) || item.command || "";
    const cmdOut = ev?.command_output;
    const hasExit = ev && ev.exit_code !== null && ev.exit_code !== undefined;
    const truncated = Boolean(ev && ev.output_truncated);
    const evReason = classifyEvidenceReason(item, ev);

    if (!opts.filesTab && (cmdIn || typeof cmdOut === "string" || hasExit)) {
      const exitBadge = hasExit
        ? `<span class="exit-pill ${Number(ev.exit_code) === 0 ? "ok" : "fail"}">Exit ${esc(ev.exit_code)}</span>`
        : "";
      const httpInlineBadge = httpTrace && httpTrace.statusCode !== null
        ? `<span class="http-pill ${httpTrace.statusCode >= 400 ? "fail" : httpTrace.statusCode >= 300 ? "warn" : "ok"}">HTTP ${esc(httpTrace.statusCode)}</span>`
        : "";
      const truncBadge = truncated ? '<span class="trunc-pill">Output truncated</span>' : "";
      const progBadge = (ev && ev.program) || item.program ? `<span class="prog-badge">${esc((ev && ev.program) || item.program)}</span>` : "";
      const emptyOutHtml = cmdOut === ""
        ? `<pre class="ev-cmd-out muted" data-evidence-reason="empty_output">(captured output is empty · 0 bytes)</pre>`
        : `<pre class="ev-cmd-out muted" data-evidence-reason="${esc(evReason.code)}">(${esc(evReason.badge)}: ${esc(evReason.text)})</pre>`;
      sections.push(`
        <section class="ev-section" aria-label="Command input and output" data-evidence-reason="${esc(cmdOut ? "captured" : evReason.code)}">
          <h3>
            <span>Command &amp; Output</span>
            <span class="ev-cmd-badges">${progBadge}${httpInlineBadge}${exitBadge}${truncBadge}</span>
          </h3>
          <div class="ev-terminal">
            <div class="ev-cmd-head">
              <span>Redacted execution capture</span>
              ${cmdIn ? `<button type="button" class="btn" data-act="copy-ev-cmd" data-ev-key="${esc(item.key)}">Copy command</button>` : ""}
            </div>
            ${cmdIn ? `<pre class="ev-cmd-in" tabindex="0">$ ${esc(redactCommandForDisplay(cmdIn))}</pre>` : ""}
            ${cmdOut ? `<pre class="ev-cmd-out" tabindex="0">${esc(redactOutputForDisplay(cmdOut))}</pre>` : emptyOutHtml}
          </div>
        </section>`);
    }

    const safeImages = Array.isArray(ev?.images) ? ev.images.filter(isSafeRasterImage) : [];
    if (safeImages.length) {
      sections.push(`
        <section class="ev-section" aria-label="Captured images">
          <h3><span>Captured Images (${safeImages.length})</span><span class="muted">Click any thumbnail to zoom</span></h3>
          <div class="ev-images-grid">
            ${safeImages
              .map((img) => {
                const isSnap = String(img.source || "").toLowerCase() === "workspace_snapshot";
                const srcLabel = isSnap ? "Workspace snapshot at capture time" : "Captured from tool result";
                const sizeTxt = formatBytes(img.size_bytes);
                return `<div class="ev-image-card">
                  <button type="button" class="ev-image-btn" data-zoom-src="${esc(img.url)}" data-zoom-label="${esc(img.path || "Captured image")}" data-zoom-source="${esc(srcLabel)}">
                    <img class="ev-image-thumb" src="${esc(img.url)}" alt="${esc(img.path || "Captured event image")}" loading="lazy" />
                  </button>
                  <div class="ev-image-meta">
                    <span class="ev-image-path" title="${esc(img.path || "")}">${esc(shortPath(img.path || "image"))}</span>
                    <span class="ev-source-badge ${isSnap ? "snap" : "tool"}">${esc(srcLabel)}</span>
                    ${sizeTxt ? `<span class="muted">${esc(img.mime_type)} · ${esc(sizeTxt)}</span>` : `<span class="muted">${esc(img.mime_type)}</span>`}
                  </div>
                </div>`;
              })
              .join("")}
          </div>
        </section>`);
    }

    const previews = Array.isArray(ev?.text_previews) ? ev.text_previews : [];
    if (previews.length) {
      sections.push(`
        <section class="ev-section" aria-label="File text previews">
          <h3><span>File &amp; Output Previews (${previews.length})</span></h3>
          <div class="ev-text-list">
            ${previews
              .map((tp) => {
                const isSnap = String(tp.source || "").toLowerCase() === "workspace_snapshot";
                const srcLabel = isSnap ? "Workspace snapshot" : "Tool result";
                return `<div class="ev-text-card">
                  <div class="ev-text-head">
                    <code title="${esc(tp.path || "")}">${esc(tp.path || "preview")}</code>
                    <span class="ev-cmd-badges">
                      <span class="ev-source-badge ${isSnap ? "snap" : "tool"}">${esc(srcLabel)}</span>
                      ${tp.truncated ? '<span class="trunc-pill">Truncated</span>' : ""}
                    </span>
                  </div>
                  <pre class="ev-text-pre">${esc(tp.text || "")}</pre>
                </div>`;
              })
              .join("")}
          </div>
        </section>`);
    }

    const mergedFiles = eventFilePaths(item, ev);
    if (opts.includeFiles && mergedFiles.length) {
      sections.unshift(`
        <section class="ev-section" aria-label="Files touched or viewed">
          <h3><span>Files Touched &amp; Viewed (${mergedFiles.length})</span><span class="muted">Click to filter stream</span></h3>
          <div class="chips">
            ${mergedFiles.map((f) => `<button type="button" class="chip-btn edited" data-scope-file="${esc(f)}" title="Filter by ${esc(f)}">${esc(f)}</button>`).join("")}
          </div>
        </section>`);
    }

    if (opts.filesTab) {
      el("files-count").textContent = String(mergedFiles.length);
      if (!mergedFiles.length) {
        const fReason = classifyFilesReason(item, ev);
        sections.unshift(`
          <div class="ev-reason-box tone-${safeCls(fReason.tone, "muted")}" data-files-reason="${esc(fReason.code)}">
            <span class="ev-reason-pill">${esc(fReason.badge)}</span>
            <span>${esc(fReason.text)}</span>
          </div>`);
      }
    }
    if (!sections.length && ev && ["shell", "web", "file_read"].includes(item.category)) {
      sections.push(`
        <div class="ev-reason-box tone-${safeCls(evReason.tone, "muted")}" data-evidence-reason="${esc(evReason.code)}">
          <span class="ev-reason-pill">${esc(evReason.badge)}</span>
          <span>${esc(evReason.text)}</span>
        </div>`);
    }
    if (!sections.length && !opts.compact) {
      return `<div class="ev-reason-box tone-${safeCls(evReason.tone, "muted")}" data-evidence-reason="${esc(evReason.code)}"><span class="ev-reason-pill">${esc(evReason.badge)}</span><span>${esc(evReason.text)}</span></div>`;
    }
    return sections.join("");
  }

  function refreshOpenCommandEvidence(force) {
    for (const id of ["detail-evidence-slot", "event-dialog-evidence"]) {
      const slot = el(id);
      const binding = evidenceSlots.get(slot);
      if (!binding || binding.opts.filesTab || (binding.opts.dialog && !eventDialog?.open)) continue;
      const { item, opts } = binding;
      if (!item.program || !["shell", "file_read"].includes(item.category)) continue;
      const key = `${state.org?.id}:${getEvidenceEventId(item)}`;
      const cached = state.evidenceCache.get(key);
      if (!cached || (cached.command_output != null && cached.exit_code != null)) continue;
      const now = performance.now();
      if (!force && !evidenceInFlight.has(key) && now - evidenceReadAt.get(cached) < EXECUTION_RECHECK_MS) continue;
      // A reply can enrich the existing event without advancing the feed cursor.
      evidenceReadAt.set(cached, now);
      hydrateEvidenceSlot(item, slot, opts, true);
    }
  }

  async function hydrateEvidenceSlot(item, slotEl, opts = {}, refresh = false) {
    const evId = getEvidenceEventId(item);
    if (!slotEl || !evId || !state.org) return;
    const orgId = String(state.org.id);
    const cacheKey = `${orgId}:${evId}`;
    const expectedKey = item.key;
    const gen = state.generation;
    evidenceSlots.set(slotEl, { item, opts });
    const cached = state.evidenceCache.get(cacheKey);
    if (!refresh && cached && item.category !== "file_edit") {
      slotEl.innerHTML = renderEvidenceHtml(cached, item, opts);
      if (!evidenceInFlight.has(cacheKey)) return;
    } else if (!refresh && !opts.compact) {
      slotEl.innerHTML = '<p class="ev-loading">Loading captured command output, images &amp; previews…</p>';
    }
    try {
      const ev = await fetchEventEvidence(item, orgId, refresh);
      if (gen !== state.generation || !slotEl.isConnected || slotEl.dataset.evKey !== expectedKey) return;
      if (opts.dialog && (state.eventModalKey !== expectedKey || state.eventModalOrg !== orgId)) return;
      if (ev && JSON.stringify(ev) === JSON.stringify(cached) && item.category !== "file_edit") return;
      slotEl.innerHTML = renderEvidenceHtml(ev, item, opts);
    } catch (err) {
      if (cached && item.category !== "file_edit") return;
      if (gen !== state.generation || !slotEl.isConnected || slotEl.dataset.evKey !== expectedKey) return;
      {
        slotEl.innerHTML = (opts.filesTab ? renderEvidenceHtml(null, item, opts) : "") + `<p class="ev-error">Could not load detailed evidence (${esc(err.message || "request failed")}).</p>`;
      }
    }
  }

  function closeImageZoom() {
    if (state.zoomOverlay) {
      state.zoomOverlay.remove();
      state.zoomOverlay = null;
    }
  }

  function openImageZoom(src, label, sourceText) {
    if (!src || !src.startsWith("/api/v1/events/") || src.startsWith("//")) return;
    closeImageZoom();
    const ov = document.createElement("div");
    ov.className = "ev-zoom-overlay";
    ov.setAttribute("role", "dialog");
    ov.setAttribute("aria-modal", "true");
    ov.setAttribute("aria-label", label || "Image preview");
    ov.innerHTML = `
      <div class="ev-zoom-card">
        <div class="ev-zoom-bar">
          <span><strong>${esc(label || "Image")}</strong>${sourceText ? ` · <span class="muted">${esc(sourceText)}</span>` : ""}</span>
          <button type="button" class="btn" data-close-zoom="1">Close</button>
        </div>
        <img class="ev-zoom-img" src="${esc(src)}" alt="${esc(label || "Zoomed event image")}" />
      </div>`;
    ov.addEventListener("click", (e) => {
      if (e.target === ov || e.target.closest("[data-close-zoom]")) closeImageZoom();
    });
    // Mount inside eventDialog when open so it renders above the native top-layer dialog
    (eventDialog && eventDialog.open ? eventDialog : document.body).appendChild(ov);
    state.zoomOverlay = ov;
    ov.querySelector("[data-close-zoom]")?.focus();
  }

  function closeEventPopup(opts = {}) {
    closeImageZoom();
    const opener = state.eventModalOpener;
    const prevKey = state.eventModalKey;
    state.eventModalKey = "";
    state.eventModalOrg = "";
    state.eventModalOpener = null;
    if (eventDialog && eventDialog.open && !opts.fromNativeClose) {
      eventDialog.close();
    }
    if (!opts.skipFocus) {
      if (opener && opener.isConnected && typeof opener.focus === "function") {
        opener.focus();
      } else {
        const targetKey = state.selectedKey || prevKey;
        const row = targetKey ? tbody.querySelector(`tr[data-key="${CSS.escape(targetKey)}"]`) : null;
        if (row) row.focus();
        else el("table-wrap")?.focus();
      }
    }
  }

  async function openVerificationTest(button, explicitId = null, explicitOrg = null) {
    const org = state.org?.id, gen = state.generation;
    const id = String(explicitId || button?.dataset?.verificationTest || button?.dataset?.openOriginEvent || "");
    const btnOrg = explicitOrg ?? button?.dataset?.org;
    if (!org || !sameActiveOrg(btnOrg) || !/^[1-9]\d{0,18}$/.test(id)) return;
    const key = `event:${id}`;
    try {
      // A linked test or triggering event can be older than every loaded feed/history page.
      const ev = await fetchEventEvidence({key, rawId: id}, org, true);
      if (gen !== state.generation || !sameActiveOrg(org) || (button && button.isConnected === false)) return;
      if (!ev?.record) { toast("This event is no longer available."); return; }
      const record = normalizeFeedRecord(ev.record);
      const inferredHttp = extractHttpStatus(ev, ev, ev.command_output || "");
      if (inferredHttp !== null && record.httpStatus == null) record.httpStatus = inferredHttp;
      state.historyMap.set(key, record);
      markPoolDirty();
      const opener = button && eventDialog?.contains(button) ? state.eventModalOpener : button;
      openEventPopup(key, opener, record);
      announceA11y(`Opened original event #${id}: ${record.message}`);
    } catch (err) {
      if (gen === state.generation) toast(err.message || "Could not open the event.");
    }
  }

  function openEventPopup(key, openerEl = null, exactRecord = null) {
    if (!eventDialog) return;
    const item = exactRecord || getRecordByKey(key) || allMergedRecords().find((r) => r.key === key);
    if (!item) return;
    closeImageZoom();
    state.eventModalKey = item.key;
    state.eventModalOrg = String(state.org?.id || "");
    state.eventModalOpener = openerEl || document.activeElement;

    const titleEl = el("event-dialog-title");
    const subEl = el("event-dialog-sub");
    const bodyEl = el("event-dialog-body");
    if (titleEl) titleEl.textContent = item.message || item.source || "Event details";
    if (subEl) {
      subEl.innerHTML = `
        <span class="sev-pill ${safeCls(item.severity)}">${esc(item.severity)}</span>
        <span class="kind-pill ${safeCls(item.kind.replace(/\s+/g, "-"))}">${esc(item.kind)}</span>
        <span class="state-pill ${safeCls(item.status)}">${esc(item.status)}</span>
        ${item.program ? `<span class="prog-badge">${esc(item.program)}</span>` : ""}
        <span>${esc(item.agent)} · ${esc(item.host_id)} · ${esc(fmtTime(item.ts))}</span>`;
    }

    const evId = getEvidenceEventId(item);
    const canFetchEv = Boolean(evId);
    const cachedEv = canFetchEv && state.org && item.category !== "file_edit" ? state.evidenceCache.get(`${state.org.id}:${evId}`) : null;
    const initialEvidence = cachedEv
      ? renderEvidenceHtml(cachedEv, item, { includeFiles: true })
      : canFetchEv
        ? '<p class="ev-loading">Loading captured command output, images &amp; previews…</p>'
        : renderEvidenceHtml(null, item, { includeFiles: true });

    if (bodyEl) {
      bodyEl.innerHTML = `
        <section class="ev-section" aria-label="Event summary and metadata">
          <h3><span>Summary &amp; Context</span><span><code>${esc(item.key)}</code></span></h3>
          <p style="margin:0 0 10px;font-size:.86rem;">${esc(item.summary || item.sessionSummary || item.message)}</p>
          <dl class="ev-meta-grid">
            <div><dt>Agent</dt><dd><strong>${esc(item.agent)}</strong></dd></div>
            <div><dt>Harness / Tool</dt><dd>${esc(item.harness)} <code>${esc(item.source)}</code></dd></div>
            <div><dt>Host / Node</dt><dd><code>${esc(item.host_id)}</code></dd></div>
            <div><dt>Workspace</dt><dd><code>${esc(item.workspace || "—")}</code></dd></div>
            <div><dt>Session</dt><dd>${item.sessionId ? `<code>${esc(item.sessionId)}</code>` : '<span class="muted">None recorded</span>'}</dd></div>
            <div><dt>Timestamp</dt><dd class="num">${esc(fmtTime(item.ts))} (${esc(fmtAge(item.ts))} ago)</dd></div>
            <div><dt>Organization</dt><dd>${esc(state.org?.name || "Active organization")}</dd></div>
          </dl>
        </section>
        <div id="event-dialog-evidence" data-ev-key="${esc(item.key)}">${initialEvidence}</div>
        <details class="ev-section">
          <summary style="cursor:pointer;font-size:.8rem;font-weight:700;color:var(--sc-muted);">Raw structured event metadata</summary>
          <pre class="pre" style="margin-top:8px;">${esc(JSON.stringify(item.details || {}, null, 2))}</pre>
        </details>`;
    }

    if (!eventDialog.open) eventDialog.showModal();
    el("event-dialog-close")?.focus();

    if (canFetchEv) {
      hydrateEvidenceSlot(item, el("event-dialog-evidence"), { includeFiles: true, dialog: true });
    }
  }

  /* ---------- Bottom Split Inspector ---------- */
  function renderDetails(item, pool) {
    document.querySelectorAll("[data-dtab]").forEach((btn) => {
      const active = btn.dataset.dtab === state.detailTab;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", String(active));
      btn.setAttribute("tabindex", active ? "0" : "-1");
    });
    if (detailEl) detailEl.setAttribute("aria-labelledby", `dtab-${state.detailTab}`);

    if (!item) {
      detailQuick.innerHTML = "";
      el("corr-count").textContent = "0";
      el("files-count").textContent = "0";
      detailEl.innerHTML = '<p class="muted">Select any alert, event, file edit, or command row above to inspect its full details, correlations, and files touched.</p>';
      return;
    }

    const corrs = findCorrelations(item, pool);
    const allFilesCount = eventFilePaths(item, state.evidenceCache.get(`${state.org?.id}:${getEvidenceEventId(item)}`)).length;
    el("corr-count").textContent = String(corrs.length);
    el("files-count").textContent = String(allFilesCount);

    const liveReturn = encodeURIComponent(currentLiveUrl());
    const turnOnlyLinks =
      item.sessionId && Array.isArray(state.linksBySession[item.sessionId])
        ? state.linksBySession[item.sessionId].filter((l) => l && l.basis === "explicit_turn_session")
        : [];
    const explicitTaskId = item.taskId || (turnOnlyLinks.length === 1 ? turnOnlyLinks[0].task_id : "");
    const assignHref = explicitTaskId ? `/?task=${encodeURIComponent(explicitTaskId)}&return_to=${liveReturn}#agent-work` : "";
    const sessionMapHref = item.sessionId ? `/?am_view=sessions&am_session=${encodeURIComponent(item.sessionId)}&return_to=${liveReturn}#activity` : "";

    detailQuick.innerHTML = `
      <button type="button" class="btn primary" data-act="open-popup">Open popup</button>
      ${item.kind === "Alert" ? `<button type="button" class="btn primary" data-act="incident" data-id="${esc(item.rawId)}">Incident #${esc(item.rawId)} · History</button>` : ""}
      ${item.canAck ? `<button type="button" class="btn primary" data-act="ack" data-id="${esc(item.rawId)}">Acknowledge</button>` : ""}
      ${assignHref ? `<a href="${esc(assignHref)}" class="btn" id="detail-open-assignment">Open assignment ↗</a>` : ""}
      ${sessionMapHref ? `<a href="${esc(sessionMapHref)}" class="btn" id="detail-open-session-map">Session in Map ↗</a>` : ""}
      ${item.agent ? `<button type="button" class="btn" data-act="scope-agent" data-val="${esc(item.agent)}">Filter agent</button>` : ""}
      ${item.workspace ? `<button type="button" class="btn" data-act="scope-ws" data-val="${esc(item.workspace)}">Filter folder</button>` : ""}
      <button type="button" class="btn" data-act="copy-json">Copy JSON</button>`;

    if (state.detailTab === "correlations") {
      detailEl.innerHTML = corrs.length
        ? `<ul class="corr-list">${corrs
            .map(
              (c) => `<li><button type="button" class="corr-btn" data-jump="${esc(c.item.key)}">
                <span>
                  <span class="sev-pill ${safeCls(c.item.severity)}">${esc(c.item.severity)}</span>
                  <span class="kind-pill ${safeCls(c.item.kind.replace(/\s+/g, "-"))}">${esc(c.item.kind)}</span>
                  ${c.reasons.map((rs) => `<span class="chip reason">${esc(rs)}</span>`).join(" ")}
                  <strong>${esc(c.item.message)}</strong>
                  <span class="muted">(${esc(c.item.agent)} · ${esc(c.item.host_id)})</span>
                </span>
                <time class="muted">${esc(fmtTime(c.item.ts))}</time>
              </button></li>`
            )
            .join("")}</ul>`
        : '<p class="muted">No correlated events found on the same file, workspace, session, agent, or host.</p>';
      return;
    }

    if (state.detailTab === "files") {
      const grp = (title, arr, cls) =>
        arr && arr.length
          ? `<div class="file-group"><h4>${esc(title)} (${arr.length})</h4><div class="chips">${arr.map((f) => `<button type="button" class="chip-btn ${cls}" data-scope-file="${esc(f)}" title="Filter by ${esc(f)}">${esc(shortPath(f))}</button>`).join("")}</div></div>`
          : "";
      const otherFiles = new Map();
      if (item.sessionId) {
        for (const record of pool) {
          if (record.key === item.key || record.sessionId !== item.sessionId ||
              record.host_id !== item.host_id || record.agent !== item.agent) continue;
          for (const path of record.files || []) {
            if (!otherFiles.has(path)) otherFiles.set(path, record);
          }
        }
      }
      const related = [...otherFiles].map(([path, record]) =>
        `<button type="button" class="chip-btn" data-file-event data-jump="${esc(record.key)}">${esc(path)} · ${esc(record.categoryLabel)}</button>`).join("");
      detailEl.innerHTML =
        (item.workspace ? `<p><strong>Workspace:</strong> <code>${esc(item.workspace)}</code></p>` : "") +
        `<div id="detail-evidence-slot" data-ev-key="${esc(item.key)}"></div>` +
        (related ? `<div class="file-group"><h4>Files from other events in this session</h4><p>Choose a file to inspect its event.</p><div class="chips">${related}</div></div>` : "") +
        (item.key.startsWith("event:") ? "" : grp("Session edited files", item.sessionFiles?.edited, "edited") +
          grp("Session delivered files", item.sessionFiles?.delivered, "") + grp("Session read files", item.sessionFiles?.read, ""));
      const slot = el("detail-evidence-slot");
      const opts = { filesTab: true, includeFiles: true };
      slot.innerHTML = renderEvidenceHtml(null, item, opts);
      if (isNumericEventId(item)) hydrateEvidenceSlot(item, slot, opts);
      return;
    }

    if (state.detailTab === "evidence") {
      detailEl.innerHTML = `
        ${isNumericEventId(item) ? `<div id="detail-evidence-slot" class="detail-evidence-slot" data-ev-key="${esc(item.key)}"></div>` : ""}
        ${renderEvidenceGapSummary(pool)}
        <p class="muted" style="margin:8px 0 6px;">Redacted structured details for <code>${esc(item.key)}</code>:</p>
        <pre class="pre">${esc(JSON.stringify(item.details || {}, null, 2))}</pre>`;
      if (isNumericEventId(item)) {
        hydrateEvidenceSlot(item, el("detail-evidence-slot"), { includeFiles: true });
      }
      return;
    }

    if (state.detailTab === "actions") {
      detailEl.innerHTML = `
        <div style="display:flex;gap:7px;flex-wrap:wrap;margin-bottom:8px;">
          <button type="button" class="btn primary" data-act="open-popup">Open event popup</button>
          ${item.canAck ? `<button type="button" class="btn primary" data-act="ack" data-id="${esc(item.rawId)}">Acknowledge alert</button>` : `<span class="muted">${item.kind === "Alert" ? (canAck() ? "Alert already acknowledged/resolved." : "Viewer role is read-only.") : "Observation record (read-only)."}</span>`}
          <button type="button" class="btn" data-act="scope-host" data-val="${esc(item.host_id)}">Scope host: ${esc(item.host_id)}</button>
          <button type="button" class="btn" data-act="scope-agent" data-val="${esc(item.agent)}">Scope agent: ${esc(item.agent)}</button>
          ${item.workspace ? `<button type="button" class="btn" data-act="scope-ws" data-val="${esc(item.workspace)}">Scope folder: ${esc(item.workspace)}</button>` : ""}
          <a href="/#activity" class="btn">Activity Map ↗</a>
          <a href="/#agent-work" class="btn">Agent Work ↗</a>
        </div>
        <div class="keys-grid">
          <div class="key-item"><kbd>Enter</kbd> / Double-click Open event popup</div>
          <div class="key-item"><kbd>⌘K</kbd> / <kbd>Ctrl+K</kbd> Quick jump palette</div>
          <div class="key-item"><kbd>↑</kbd> / <kbd>↓</kbd> Navigate rows</div>
          <div class="key-item"><kbd>/</kbd> Focus search</div>
          <div class="key-item"><kbd>A</kbd> Acknowledge open alert</div>
          <div class="key-item"><kbd>P</kbd> Pause / resume display</div>
          <div class="key-item"><kbd>D</kbd> Toggle density</div>
          <div class="key-item"><kbd>F</kbd> Toggle full screen</div>
        </div>`;
      return;
    }

    // General tab
    const fileChips = (item.files || []).length
      ? `<div class="chips">${item.files.map((f) => `<button type="button" class="chip-btn edited" data-scope-file="${esc(f)}" title="Filter by ${esc(f)}">${esc(shortPath(f))}</button>`).join("")}</div>`
      : "";
    const cmdBlock = item.command
      ? `<div class="cmd-wrap"><div class="cmd-bar"><span>Redacted command</span><button type="button" class="btn" data-act="copy-cmd">Copy</button></div><pre class="cmd-preview">$ ${esc(redactCommandForDisplay(item.command))}</pre></div>`
      : "";
    detailEl.innerHTML = `
      <div class="detail-grid">
        <div>
          <h3 class="detail-title">
            <span class="sev-pill ${safeCls(item.severity)}">${esc(item.severity)}</span>
            <span class="kind-pill ${safeCls(item.kind.replace(/\s+/g, "-"))}">${esc(item.kind)}</span>
            <span class="state-pill ${safeCls(item.status)}">${esc(item.status)}</span>
            ${item.program ? `<span class="prog-badge">${esc(item.program)}</span>` : ""}
            ${esc(item.message)}
          </h3>
          <div class="detail-msg">${esc(item.summary || item.sessionSummary || item.message)}</div>
          ${item.kind === "Alert" && item.signalCount ? `<p>${item.countIsMinimum ? "At least " : ""}${esc(item.signalCount)} signals · ${esc(item.owner || "Unassigned")}${item.previousCase ? ` · Recurrence after #${esc(item.previousCase)}` : ""}</p>` : ""}
          ${cmdBlock}
          ${item.sessionSummary && item.summary && item.sessionSummary !== item.summary ? `<div class="muted" style="font-size:.78rem;margin-top:4px;"><strong>Session context:</strong> ${esc(item.sessionSummary)}</div>` : ""}
          ${fileChips}
          ${isNumericEventId(item) ? `<div id="detail-evidence-slot" class="detail-evidence-slot" data-ev-key="${esc(item.key)}"></div>` : ""}
        </div>
        <dl class="kv">
          <dt>Agent</dt><dd><strong>${esc(item.agent)}</strong></dd>
          <dt>Harness / Tool</dt><dd>${esc(item.harness)} <code>${esc(item.source)}</code>${item.program ? ` · <code>${esc(item.program)}</code>` : ""}</dd>
          <dt>Session</dt><dd>${item.sessionId ? `<code>${esc(item.sessionId)}</code>${sessionMapHref ? ` <a href="${esc(sessionMapHref)}" class="detail-link-hop">Activity Map ↗</a>` : ""}` : '<span class="muted">None recorded</span>'}</dd>
          <dt>Assignment</dt><dd>${
            assignHref
              ? `<a href="${esc(assignHref)}" class="detail-link-hop" data-detail-link="linked">Open assignment <code>${esc(explicitTaskId)}</code> ↗</a>`
              : '<span class="detail-link-unknown" data-detail-link="unknown">Link unknown (no explicit task link)</span>'
          }</dd>
          <dt>Host / Node</dt><dd><code>${esc(item.host_id)}</code></dd>
          <dt>Workspace</dt><dd><code>${esc(item.workspace || "—")}</code></dd>
          ${item.currentFolder && item.currentFolder !== item.workspace ? `<dt>Working dir</dt><dd><code>${esc(item.currentFolder)}</code></dd>` : ""}
          <dt>Received</dt><dd class="num">${esc(fmtTime(item.ts))} (${esc(fmtAge(item.ts))} ago)</dd>
          ${item.ackedBy ? `<dt>Acknowledged</dt><dd>${esc(item.ackedBy)} · ${esc(fmtTime(item.ackedAt))}</dd>` : ""}
          <dt>Organization</dt><dd>${esc(state.org?.name || "Active organization")}</dd>
        </dl>
      </div>`;
    if (isNumericEventId(item)) {
      hydrateEvidenceSlot(item, el("detail-evidence-slot"), { compact: true });
    }
  }


  // Keep the incident history outside the polling table so reading or assigning a case
  // never loses focus on refresh. All actions are bound to the organization that opened it.
  function closeIncident() {
    caseView = null;
    if (caseDialog.open) caseDialog.close();
    el("incident-content").replaceChildren();
    el("incident-feedback").textContent = "";
    el("incident-heading").textContent = "Incident";
  }

  function incidentTime(ts) {
    return ts ? new Date(Number(ts) * 1000).toLocaleString() : "Time unknown";
  }

  function resolutionLabel(reason) {
    return ({
      measurement_recovered: "Reading returned below threshold",
      heartbeat_resumed: "Heartbeat resumed",
      operator_verified: "Recovery verified by operator",
      legacy_resolution: "Resolution imported from an earlier version",
    })[reason] || "Resolved";
  }

  function incidentStep(step) {
    if (!step) return '<p class="muted">No verified journal step available at observation time.</p>';
    const files = (step.confirmed_files || []).map(f => `<code>${esc(f)}</code>`).join(", ");
    return `<p>${esc(step.action || "Step")} · ${esc(step.agent || "Unknown agent")} · ${esc(step.tool)} · ${esc(incidentTime(step.at))}<br>
      Session <code>${esc(step.session || "Unknown")}</code> · ${files ? "Confirmed file: " + files : "No confirmed file recorded"}</p>`;
  }

  function historyRow(entry) {
    const data = entry.data || {};
    const labels = {opened: "First signal", repeated: "Repeated signal", acknowledged: "Acknowledged",
      assigned: data.owner ? "Assigned to " + data.owner : "Unassigned", resolved: resolutionLabel(data.reason),
      legacy_snapshot: "Imported alert #" + data.source_id};
    const hasEvidence = data.evidence && Object.keys(data.evidence).length;
    return `<li><strong>${esc(labels[entry.kind] || entry.kind)}</strong>${entry.actor ? ` · ${esc(entry.actor)}` : ""}
      <time>${esc(incidentTime(entry.at))}</time>
      ${hasEvidence || data.last_step ? `<details><summary>Recorded evidence</summary>
        ${hasEvidence ? `<pre>${esc(JSON.stringify(data.evidence, null, 2))}</pre>` : ""}
        ${data.last_step ? incidentStep(data.last_step) : ""}</details>` : ""}
    </li>`;
  }

  function renderIncident(page) {
    const a = page.alert;
    const step = a.last_step;
    const active = a.status !== "RESOLVED";
    const manage = canAck() && active && Array.isArray(page.assignees);
    const previous = a.previous_id ? `<button class="btn" type="button" data-case-previous="${esc(a.previous_id)}">Previous incident #${esc(a.previous_id)}</button>` : "";
    el("incident-heading").textContent = `Incident #${a.id} · ${a.status}`;
    el("incident-content").innerHTML = `
      <h3>${esc(a.title)}</h3><p>${esc(a.summary)}</p>
      <dl class="kv">
        <dt>Host / rule</dt><dd>${esc(a.host_id)} · <code>${esc(a.rule_code)}</code></dd>
        <dt>Signals</dt><dd>${a.count_is_minimum ? "At least " : ""}<strong id="incident-count">${esc(a.occurrence_count)}</strong> · Last observed ${esc(incidentTime(a.last_seen_at))}</dd>
        <dt>Owner</dt><dd id="incident-current-owner">${esc(a.owner || "Unassigned")}</dd>
        <dt>Acknowledgement</dt><dd>${a.acked_at ? `${esc(a.acked_by || "Unknown")} · ${esc(incidentTime(a.acked_at))}` : "None recorded"}</dd>
        <dt>Resolution</dt><dd>${active ? "Awaiting recovery" : `${esc(resolutionLabel(a.resolution))} · ${esc(a.resolved_by || "Unknown")} · ${esc(incidentTime(a.resolved_at))}`}</dd>
      </dl>
      ${previous}
      <h3>Last observed step on this host</h3>
      ${incidentStep(step)}
      ${step ? '<p class="muted">The journal recorded this step on the host. Its connection to the alert is unverified.</p>' : ""}
      ${manage ? `<div class="incident-controls">
        <label for="incident-owner">Owner</label><select id="incident-owner"><option value="">Unassigned</option>
          ${a.owner && !page.assignees.some(m => m.username === a.owner) ? `<option selected disabled>${esc(a.owner)} (former operator)</option>` : ""}
          ${page.assignees.map(m => `<option value="${esc(m.id)}"${m.username === a.owner ? " selected" : ""}>${esc(m.username)}</option>`).join("")}
        </select><button type="button" class="btn" data-case-action="owner">Save owner</button>
        ${a.status === "OPEN" ? `<button type="button" class="btn primary" data-case-action="ack">Acknowledge</button>` : ""}
        <button type="button" class="btn" data-case-action="resolve">Confirm recovery</button></div>` : ""}
      <h3>Incident history</h3>
      <ol id="incident-history" class="incident-history">${page.history.map(historyRow).join("")}</ol>
      <button type="button" class="btn" id="incident-older" ${page.next_before ? "" : "hidden"}>Earlier history</button>`;
  }

  async function loadIncident(view, before = null) {
    if (view.busy) return;
    view.busy = true;
    el("incident-feedback").textContent = "Loading…";
    try {
      const qs = new URLSearchParams({organization_id: view.org});
      if (before) qs.set("before", before);
      const p = await api(`/api/v1/alerts/${encodeURIComponent(view.id)}?${qs}`);
      if (view !== caseView || String(p.organization) !== view.org) return;
      view.id = p.alert.id; // A v1 alias resolves to its canonical episode.
      if (before) {
        el("incident-history").insertAdjacentHTML("beforeend", p.history.map(historyRow).join(""));
        el("incident-older").hidden = !p.next_before;
      } else {
        renderIncident(p);
        view.updated = p.alert.updated_at;
        el("incident-refresh").textContent = "Refresh";
        const record = normalizeFeedRecord({...p.alert, kind: "alert"});
        const visible = state.feedMap.get(record.key) || state.historyMap.get(record.key);
        if (visible && record.ts >= visible.ts) {
          state.feedMap.set(record.key, record);
          markPoolDirty();
          if (!state.paused) render();
        }
      }
      view.before = p.next_before;
      el("incident-feedback").textContent = "";
    } catch (err) {
      if (view !== caseView) return;
      if ([401, 403, 409].includes(err.status)) {
        closeIncident();
        toast(err.message);
      } else el("incident-feedback").textContent = err.message;
    } finally { view.busy = false; }
  }

  function openIncident(id) {
    if (!/^[1-9]\d{0,18}$/.test(String(id)) || !state.org) return;
    caseView = {id, org: String(state.org.id), before: null, busy: false};
    el("incident-content").replaceChildren();
    el("incident-heading").textContent = `Incident #${id}`;
    if (!caseDialog.open) caseDialog.showModal();
    loadIncident(caseView);
  }

  el("incident-close").addEventListener("click", closeIncident);
  caseDialog.addEventListener("close", () => { if (!caseDialog.open) closeIncident(); });
  el("incident-refresh").addEventListener("click", () => { if (caseView) loadIncident(caseView); });
  el("incident-content").addEventListener("click", async (event) => {
    const btn = event.target.closest("button");
    const view = caseView;
    if (!btn || !view || view.busy) return;
    if (btn.dataset.casePrevious) { openIncident(btn.dataset.casePrevious); return; }
    if (btn.id === "incident-older") { if (view.before) loadIncident(view, view.before); return; }
    const action = btn.dataset.caseAction;
    if (!action || !canAck()) return;
    const data = {organization_id: view.org};
    if (action === "resolve") data.reason = "operator_verified";
    if (action === "owner") {
      const option = el("incident-owner").selectedOptions[0];
      if (!option || option.disabled) return;
      data.owner_id = option.value ? Number(option.value) : null;
    }
    view.busy = true;
    try {
      await api(`/api/v1/alerts/${view.id}/${action}`, {method: "POST", body: JSON.stringify(data)});
      if (caseView !== view) return;
      view.busy = false;
      await loadIncident(view);
      if (caseView === view) await poll(true);
    } catch (err) {
      if (caseView !== view) return;
      if ([401, 403, 409].includes(err.status)) { closeIncident(); toast(err.message); }
      else el("incident-feedback").textContent = err.message;
    } finally { view.busy = false; }
  });

  /* ---------- Cursor Feed + Multi-Stream Polling ---------- */
  function clearState() {
    closeIncident();
    closeEventPopup({ skipFocus: true });
    state.generation++;
    state.feedMap.clear();
    state.historyMap.clear();
    state.workMap.clear();
    state.collabMap.clear();
    state.auditMap.clear();
    state.evidenceCache.clear();
    evidenceInFlight.clear();
    state.mergedCache = [];
    state.mergedDirty = true;
    state.hosts = [];
    state.feedCursor = null;
    state.historyCursor = null;
    state.lastRichAt = 0;
    state.lastOverviewAt = 0;
    state.lastExplorerSig = "";
    state.lastExplorerAt = 0;
    state.lastSyncedUrl = "";
    state.renderLimit = DEFAULT_RENDER_LIMIT;
    state.renderedFilteredTotal = 0;
    state.seenKeys = new Set();
    state.newKeys = new Set();
    state.bufferedWhilePaused = 0;
    state.displaySnapshot = null;
    state.selectedKey = "";
    state.scopeHost = "";
    state.scopeAgent = "";
    state.scopeWorkspace = "";
    state.scopeProgram = "";
    state.scopeTask = "";
    state.scopeSession = "";
    state.scopeFile = "";
    state.scopeRuntime = "";
    state.timeFrom = 0;
    state.timeTo = 0;
    state.filterSource = "";
    state.filterHttp = "";
    ensureHttpFilterOption("");
    state.pendingEventKey = "";
    state.linksByTask = {};
    state.linksBySession = {};
    el("load-older")?.classList.add("hidden");
    el("show-more-rows")?.classList.add("hidden");
    syncLiveUrl();
    updatePauseUi();
    tbody.innerHTML = "";
    emptyEl.textContent = "Loading live records…";
    emptyEl.hidden = false;
    renderDetails(null, []);
  }

  function applySession(me) {
    state.user = me.user || null;
    state.org = me.organization || { id: "default", name: "Default Organization" };
    state.memberships = Array.isArray(me.memberships) && me.memberships.length
      ? me.memberships
      : [{ id: state.org.id, name: state.org.name, role: roleOf() }];
    el("user-label").textContent = state.user?.username || "";
    el("role-badge").textContent = roleOf().toUpperCase();
    if (state.memberships.length > 1) {
      orgSwitcher.innerHTML = state.memberships
        .map((m) => `<option value="${esc(m.id)}"${m.id === state.org.id ? " selected" : ""}>${esc(m.name)} (${esc(m.role)})</option>`)
        .join("");
      orgSwitcher.classList.remove("hidden");
      orgBadge.classList.add("hidden");
    } else {
      orgBadge.textContent = state.org.name;
      orgBadge.classList.remove("hidden");
      orgSwitcher.classList.add("hidden");
    }
  }

  function sameActiveOrg(orgId) {
    return orgId === undefined || orgId === null || !state.org || String(orgId) === String(state.org.id);
  }

  async function seedLiveHistory(gen) {
    try {
      const data = await api("/api/v1/live-records");
      if (gen !== state.generation || !sameActiveOrg(data.organization)) return;
      for (const rec of data.records || []) {
        const norm = normalizeFeedRecord(rec);
        if (!state.historyMap.has(norm.key)) {
          state.historyMap.set(norm.key, norm);
          state.seenKeys.add(norm.key);
        }
      }
      markPoolDirty();
      state.historyCursor = data.next || null;
      el("load-older")?.classList.toggle("hidden", !state.historyCursor);
    } catch (err) {
      if (err.status === 401 || err.status === 403) throw err;
    }
  }

  async function pullEventFeed(gen) {
    if (!state.useEventFeed) return { used: false, added: [], updated: [], sawReset: false };
    let loops = 0;
    const added = [];
    const updated = [];
    let sawReset = false;
    while (loops < 8) {
      loops++;
      const qs = state.feedCursor ? `?cursor=${encodeURIComponent(state.feedCursor)}&limit=500` : "?limit=500";
      let res;
      try {
        res = await api(`/api/v1/event-feed${qs}`);
      } catch (err) {
        if (err.status === 404) {
          state.useEventFeed = false;
          feedModeBadge.textContent = "POLL";
          return { used: false, added: [], updated: [], sawReset: false };
        }
        if (err.status === 400 && state.feedCursor) {
          state.feedCursor = null;
          continue;
        }
        throw err;
      }
      if (gen !== state.generation) return { used: true, added, updated, sawReset };
      feedModeBadge.textContent = "CURSOR FEED";
      if (res.reset) {
        sawReset = true;
        state.feedMap.clear();
        state.historyMap.clear();
        state.historyCursor = null;
        markPoolDirty();
      }
      for (const rec of res.records || []) {
        const norm = normalizeFeedRecord(rec);
        const current = state.feedMap.get(norm.key) || state.historyMap.get(norm.key);
        // A just-refreshed incident can be newer than a poll already in flight.
        if (current && norm.kind === "Alert" && norm.ts < current.ts) continue;
        state.feedMap.set(norm.key, norm);
        if (!current) added.push(norm);
        else updated.push(norm);
      }
      if (res.cursor) state.feedCursor = res.cursor;
      if (!res.more) break;
    }
    if (sawReset) await seedLiveHistory(gen);
    if (gen !== state.generation) return { used: true, added, updated, sawReset };
    if (state.paused && added.length > 0) {
      state.bufferedWhilePaused += added.length;
      updatePauseUi();
    }
    return { used: true, added, updated, sawReset };
  }

  async function pullLegacyFeed(gen) {
    const [liveData, alertsData] = await Promise.all([
      api("/api/v1/live-records").catch((e) => (e.status === 401 ? Promise.reject(e) : null)),
      api("/api/v1/alerts?status=ALL").catch((e) => (e.status === 401 ? Promise.reject(e) : { alerts: [] })),
    ]);
    if (gen !== state.generation) return { changed: false };
    let added = 0;
    const next = new Map();

    // Index full alert payloads (evidence + acked_by) so live-records alert rows get complete metadata
    const alertMeta = new Map();
    for (const a of alertsData.alerts || []) {
      alertMeta.set(String(a.id), a);
      const norm = normalizeFeedRecord({ ...a, kind: "alert", source: a.rule_code, ts: a.updated_at || a.created_at, details: a.evidence });
      if (!state.feedMap.has(norm.key)) added++;
      next.set(norm.key, norm);
    }

    if (liveData && Array.isArray(liveData.records)) {
      feedModeBadge.textContent = "LIVE HISTORY";
      if (!state.historyMap.size) state.historyCursor = liveData.next || null;
      el("load-older")?.classList.toggle("hidden", !state.historyCursor);
      for (const rec of liveData.records) {
        if (String(rec.kind || "").toLowerCase() === "alert" && alertMeta.has(String(rec.id))) {
          continue; // already added with full evidence & acked_by above
        }
        const norm = normalizeFeedRecord(rec);
        if (!state.feedMap.has(norm.key)) added++;
        next.set(norm.key, norm);
      }
    } else {
      feedModeBadge.textContent = "POLL";
      const eventsData = await api("/api/v1/events").catch((e) => (e.status === 401 ? Promise.reject(e) : { events: [] }));
      if (gen !== state.generation) return { changed: false };
      for (const e of eventsData.events || []) {
        const norm = normalizeFeedRecord({ ...e, kind: "event", source: e.event_type, ts: e.created_at, details: e.metadata });
        if (!state.feedMap.has(norm.key)) added++;
        next.set(norm.key, norm);
      }
    }
    state.feedMap = next;
    markPoolDirty();
    if (state.paused && added > 0) {
      state.bufferedWhilePaused += added;
      updatePauseUi();
    }
    return { changed: true };
  }

  async function loadOlderHistory() {
    if (!state.historyCursor) return;
    const btn = el("load-older");
    const gen = state.generation;
    btn.disabled = true;
    btn.textContent = "Loading…";
    try {
      let loaded = 0;
      let pages = 0;
      while (state.historyCursor && loaded === 0 && pages < 6) {
        pages++;
        const data = await api(`/api/v1/live-records?before=${encodeURIComponent(state.historyCursor)}`);
        if (gen !== state.generation || !sameActiveOrg(data.organization)) return;
        for (const rec of data.records || []) {
          const norm = normalizeFeedRecord(rec);
          const alreadyKnown = state.feedMap.has(norm.key) || state.historyMap.has(norm.key);
          state.historyMap.set(norm.key, norm);
          state.seenKeys.add(norm.key);
          if (!alreadyKnown) loaded++;
        }
        state.historyCursor = data.next || null;
      }
      if (loaded > 0) {
        markPoolDirty();
        state.renderLimit = Math.max(state.renderLimit + Math.max(loaded, 400), 1400);
      }
      btn.classList.toggle("hidden", !state.historyCursor);
      toast(loaded ? `Loaded ${loaded} older history record${loaded === 1 ? "" : "s"}.` : "Reached end of persisted history.");
      render();
    } catch (err) {
      toast(err.message || "Could not load older history.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Load older history";
    }
  }

  async function pullScopedRecords(gen) {
    const reqs = [];
    if (state.scopeTask) {
      reqs.push(api(`/api/v1/live-records?task_id=${encodeURIComponent(state.scopeTask)}`).catch((e) => (e.status === 401 ? Promise.reject(e) : null)));
    }
    if (state.scopeSession && state.scopeHost && state.scopeAgent && state.scopeRuntime) {
      const qs = new URLSearchParams({
        session: state.scopeSession,
        host: state.scopeHost,
        agent: state.scopeAgent,
        runtime: state.scopeRuntime,
      });
      reqs.push(api(`/api/v1/live-records?${qs.toString()}`).catch((e) => (e.status === 401 ? Promise.reject(e) : null)));
    }
    let any = false;
    if (reqs.length) {
      const pages = await Promise.all(reqs);
      if (gen !== state.generation) return;
      for (const data of pages) {
        if (!data || !sameActiveOrg(data.organization)) continue;
        for (const rec of data.records || []) {
          const norm = normalizeFeedRecord(rec);
          state.historyMap.set(norm.key, norm);
          any = true;
        }
      }
    }
    const pending = state.pendingEventKey;
    if (pending && !state.feedMap.has(pending) && !state.historyMap.has(pending) && state.org) {
      const evMatch = /^event:([1-9]\d{0,18})$/.exec(pending);
      const alertMatch = /^alert:([1-9]\d{0,18})$/.exec(pending);
      if (evMatch) {
        const qs = new URLSearchParams({ organization_id: String(state.org.id) });
        const ev = await api(`/api/v1/events/${encodeURIComponent(evMatch[1])}/evidence?${qs.toString()}`).catch((e) => (e.status === 401 ? Promise.reject(e) : null));
        if (gen !== state.generation) return;
        if (ev && sameActiveOrg(ev.organization) && ev.record) {
          state.evidenceCache.set(`${state.org.id}:${evMatch[1]}`, ev);
          const norm = normalizeFeedRecord(ev.record);
          state.historyMap.set(norm.key, norm);
          any = true;
        }
      } else if (alertMatch) {
        const qs = new URLSearchParams({ organization_id: String(state.org.id) });
        const page = await api(`/api/v1/alerts/${encodeURIComponent(alertMatch[1])}?${qs.toString()}`).catch((e) => (e.status === 401 ? Promise.reject(e) : null));
        if (gen !== state.generation) return;
        if (page && sameActiveOrg(page.organization) && page.alert) {
          const norm = normalizeFeedRecord({ ...page.alert, kind: "alert" });
          state.historyMap.set(norm.key, norm);
          any = true;
        }
      }
    }
    if (any) markPoolDirty();
  }

  async function poll(forceAll = false) {
    if (state.busy) return;
    if (!forceAll && document.hidden) return;
    state.busy = true;
    const gen = state.generation;
    state.pollSeq++;
    const nowMs = Date.now();
    const fetchRich = forceAll || (nowMs - state.lastRichAt >= RICH_POLL_MS);
    const fetchOverview = forceAll || (nowMs - state.lastOverviewAt >= OVERVIEW_POLL_MS);
    try {
      const feedRes = await pullEventFeed(gen);
      if (gen !== state.generation) return;
      let legacyChanged = false;
      if (!feedRes.used) {
        const leg = await pullLegacyFeed(gen);
        legacyChanged = Boolean(leg?.changed);
      }
      if (gen !== state.generation) return;
      if (forceAll) await pullScopedRecords(gen);
      if (gen !== state.generation) return;

      let richChanged = false;
      if (fetchRich || fetchOverview) {
        const [overview, activity, workBoard] = await Promise.all([
          fetchOverview ? api("/api/v1/overview").catch((e) => (e.status === 401 ? Promise.reject(e) : null)) : Promise.resolve(null),
          fetchRich ? api("/api/v1/activity").catch((e) => (e.status === 401 ? Promise.reject(e) : null)) : Promise.resolve(null),
          fetchRich ? api("/api/v1/work-board").catch((e) => (e.status === 401 ? Promise.reject(e) : null)) : Promise.resolve(null),
        ]);
        if (gen !== state.generation) return;
        if (fetchOverview && overview) {
          state.lastOverviewAt = Date.now();
          state.hosts = Array.isArray(overview.hosts) ? overview.hosts : [];
          state.auditMap = normalizeAudit(overview);
          richChanged = true;
        }
        if (fetchRich && (activity || workBoard)) {
          state.lastRichAt = Date.now();
          const prevWorkCount = state.workMap.size;
          if (activity) state.workMap = normalizeActivitySessions(activity);
          if (workBoard) {
            state.collabMap = normalizeCollaboration(workBoard);
            state.linksByTask = workBoard?.links?.by_task && typeof workBoard.links.by_task === "object" ? workBoard.links.by_task : {};
            state.linksBySession = workBoard?.links?.by_session && typeof workBoard.links.by_session === "object" ? workBoard.links.by_session : {};
          }
          if (state.paused && state.workMap.size > prevWorkCount) {
            state.bufferedWhilePaused += state.workMap.size - prevWorkCount;
            updatePauseUi();
          }
          richChanged = true;
        }
        if (richChanged) markPoolDirty();
      }

      const fresh = new Set();
      const hadSeen = state.seenKeys.size > 0;
      if (feedRes.used && !feedRes.sawReset && !richChanged && !forceAll) {
        for (let i = 0; i < feedRes.added.length; i++) {
          const k = feedRes.added[i].key;
          if (hadSeen && !state.seenKeys.has(k)) fresh.add(k);
          state.seenKeys.add(k);
        }
        for (let i = 0; i < feedRes.updated.length; i++) {
          state.seenKeys.add(feedRes.updated[i].key);
        }
      } else {
        for (const r of state.feedMap.values()) { if (hadSeen && !state.seenKeys.has(r.key)) fresh.add(r.key); state.seenKeys.add(r.key); }
        for (const r of state.workMap.values()) { if (hadSeen && !state.seenKeys.has(r.key)) fresh.add(r.key); state.seenKeys.add(r.key); }
        for (const r of state.collabMap.values()) { if (hadSeen && !state.seenKeys.has(r.key)) fresh.add(r.key); state.seenKeys.add(r.key); }
        for (const r of state.auditMap.values()) { if (hadSeen && !state.seenKeys.has(r.key)) fresh.add(r.key); state.seenKeys.add(r.key); }
      }
      state.newKeys = fresh;

      const nextLiveMode = state.paused ? "paused" : "live";
      if (liveBadge.dataset.mode !== nextLiveMode) {
        liveBadge.dataset.mode = nextLiveMode;
        liveBadge.className = `live-pill ${nextLiveMode}`;
        liveBadge.innerHTML = `<i aria-hidden="true"></i>${state.paused ? "PAUSED" : "LIVE"}`;
      }
      syncEl.textContent = state.paused
        ? `Display paused (${state.bufferedWhilePaused} new buffered) · ${new Date().toLocaleTimeString()}`
        : `Connected · Synced ${new Date().toLocaleTimeString()}`;

      if (!state.paused) {
        refreshOpenCommandEvidence(forceAll);
        const canIncremental =
          feedRes.used &&
          !forceAll &&
          !richChanged &&
          !feedRes.sawReset &&
          !legacyChanged &&
          state.groupMode === "none" &&
          state.sortKey === "ts" &&
          state.sortDir === "desc";

        if (canIncremental) {
          if (feedRes.added.length === 0 && feedRes.updated.length === 0) {
            return; // Nothing changed on this tick — skip DOM work completely
          }
          if (!state.mergedDirty && Array.isArray(state.mergedCache) && feedRes.updated.length === 0) {
            for (let i = 0; i < feedRes.added.length; i++) {
              state.mergedCache.unshift(feedRes.added[i]);
            }
            if (state.mergedCache.length > MAX_RECORDS) {
              state.mergedCache.length = MAX_RECORDS;
            }
          } else {
            markPoolDirty();
          }
          applyIncrementalUpdate(feedRes.added, feedRes.updated);
        } else {
          if (feedRes.added.length > 0 || feedRes.updated.length > 0) markPoolDirty();
          render();
        }
      }
    } catch (err) {
      if (gen !== state.generation) return;
      if (err.status === 401 || err.status === 403) {
        stopTimer();
        clearState();
        appEl.classList.add("hidden");
        authGate.classList.remove("hidden");
        return;
      }
      liveBadge.dataset.mode = "offline";
      liveBadge.className = "live-pill offline";
      liveBadge.innerHTML = '<i aria-hidden="true"></i>RETRYING';
      syncEl.textContent = `Disconnected (${err.message}) · retrying…`;
    } finally {
      state.busy = false;
    }
  }

  function startTimer() {
    stopTimer();
    state.timer = setInterval(() => poll(false), state.intervalMs);
  }
  function stopTimer() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
  }

  function updatePauseUi() {
    const btn = el("pause");
    btn.setAttribute("aria-pressed", String(state.paused));
    btn.textContent = state.paused
      ? state.bufferedWhilePaused > 0
        ? `Resume (+${state.bufferedWhilePaused} new)`
        : "Resume"
      : "Pause";
  }

  function togglePause() {
    state.paused = !state.paused;
    if (state.paused) {
      state.displaySnapshot = allMergedRecords();
      state.bufferedWhilePaused = 0;
    } else {
      state.displaySnapshot = null;
      state.bufferedWhilePaused = 0;
      markPoolDirty();
      render();
    }
    updatePauseUi();
    liveBadge.dataset.mode = state.paused ? "paused" : "live";
    liveBadge.className = `live-pill ${state.paused ? "paused" : "live"}`;
    liveBadge.innerHTML = `<i aria-hidden="true"></i>${state.paused ? "PAUSED" : "LIVE"}`;
  }

  async function ackAlert(id) {
    const gen = state.generation;
    try {
      const result = await api(`/api/v1/alerts/${encodeURIComponent(id)}/ack`, {
        method: "POST", body: JSON.stringify({organization_id: state.org?.id})
      });
      if (gen !== state.generation || !sameActiveOrg(result.organization)) return;
      if (result.alert) {
        const updated = normalizeFeedRecord({...result.alert, kind: "alert"});
        state.feedMap.set(updated.key, updated);
        markPoolDirty();
      }
      toast("Alert acknowledged.");
      if (state.paused) togglePause();
      render();
      if (state.busy) setTimeout(() => poll(true), 350);
      else await poll(true);
    } catch (err) {
      toast(err.message || "Could not acknowledge alert.");
    }
  }

  function downloadFile(content, mime, filename) {
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function exportCsv() {
    const rows = getFiltered(allMergedRecords());
    const cols = ["severity", "kind", "categoryLabel", "status", "http_status", "program", "ts", "host_id", "agent", "harness", "workspace", "where", "message", "summary"];
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const valOf = (r, c) => {
      if (c === "ts") return r.ts ? new Date(r.ts * 1000).toISOString() : "";
      if (c === "http_status") return r.httpStatus ?? "";
      return r[c];
    };
    const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => q(valOf(r, c))).join(","))].join("\n");
    downloadFile(csv, "text/csv;charset=utf-8", `swarmcontrol-live-${Date.now()}.csv`);
    toast(`Exported ${rows.length} rows to CSV.`);
  }

  function exportJson() {
    const rows = getFiltered(allMergedRecords());
    const records = rows.map((r) => ({ ...r, http_status: r.httpStatus ?? null }));
    downloadFile(JSON.stringify({ organization: state.org?.name, exported_at: new Date().toISOString(), count: records.length, filters: { http: state.filterHttp || null, host: state.scopeHost || null, program: state.scopeProgram || null, source: state.filterSource || null }, records }, null, 2), "application/json;charset=utf-8", `swarmcontrol-live-${Date.now()}.json`);
    toast(`Exported ${records.length} rows to JSON.`);
  }

  /* ---------- Event Wiring ---------- */
  el("sidebar-toggle").addEventListener("click", (e) => {
    const collapsed = el("sidebar").classList.toggle("collapsed");
    e.currentTarget.setAttribute("aria-expanded", String(!collapsed));
  });
  el("mobile-tree-btn").addEventListener("click", (e) => {
    const opened = el("sidebar").classList.toggle("mobile-open");
    e.currentTarget.setAttribute("aria-expanded", String(opened));
  });

  el("sidebar").addEventListener("click", (e) => {
    const pBtn = e.target.closest("[data-persp]");
    if (pBtn) {
      state.perspective = pBtn.dataset.persp;
      state.scopeHost = ""; state.scopeAgent = ""; state.scopeWorkspace = ""; state.scopeFile = "";
      el("sidebar").classList.remove("mobile-open");
      render();
      return;
    }
    const hBtn = e.target.closest("[data-scope-host]");
    if (hBtn) {
      state.scopeHost = state.scopeHost === hBtn.dataset.scopeHost ? "" : hBtn.dataset.scopeHost;
      el("sidebar").classList.remove("mobile-open");
      render();
      return;
    }
    const aBtn = e.target.closest("[data-scope-agent]");
    if (aBtn) {
      state.scopeAgent = state.scopeAgent === aBtn.dataset.scopeAgent ? "" : aBtn.dataset.scopeAgent;
      el("sidebar").classList.remove("mobile-open");
      render();
      return;
    }
    const wBtn = e.target.closest("[data-scope-ws]");
    if (wBtn) {
      state.scopeWorkspace = state.scopeWorkspace === wBtn.dataset.scopeWs ? "" : wBtn.dataset.scopeWs;
      el("sidebar").classList.remove("mobile-open");
      render();
      return;
    }
    const fBtn = e.target.closest("[data-scope-file]");
    if (fBtn) {
      state.scopeFile = state.scopeFile === fBtn.dataset.scopeFile ? "" : fBtn.dataset.scopeFile;
      el("sidebar").classList.remove("mobile-open");
      render();
    }
  });

  tbody.addEventListener("click", (e) => {
    const row = e.target.closest("tr[data-key]");
    if (!row) return;
    selectRowKey(row.dataset.key);
  });

  tbody.addEventListener("dblclick", (e) => {
    const row = e.target.closest("tr[data-key]");
    if (!row) return;
    selectRowKey(row.dataset.key);
    openEventPopup(row.dataset.key, row);
  });

  if (eventDialog) {
    el("event-dialog-close")?.addEventListener("click", () => closeEventPopup());
    el("event-dialog-copy")?.addEventListener("click", () => {
      const it = getRecordByKey(state.eventModalKey);
      if (!it) return;
      const evId = getEvidenceEventId(it);
      const ev = evId && state.org ? state.evidenceCache.get(`${state.org.id}:${evId}`) : null;
      navigator.clipboard?.writeText(JSON.stringify({ record: it, evidence: ev || null }, null, 2)).then(() => {
        toast("Event JSON copied.");
      }).catch(() => {});
    });
    eventDialog.addEventListener("click", (e) => {
      const originBtn = e.target.closest("[data-open-origin-event]");
      if (originBtn) {
        openVerificationTest(originBtn, originBtn.dataset.openOriginEvent, originBtn.dataset.org);
        return;
      }
      const test = e.target.closest("[data-verification-test]");
      if (test) { openVerificationTest(test); return; }
      if (e.target === eventDialog) {
        closeEventPopup();
        return;
      }
      const zoomBtn = e.target.closest("[data-zoom-src]");
      if (zoomBtn) {
        openImageZoom(zoomBtn.dataset.zoomSrc, zoomBtn.dataset.zoomLabel, zoomBtn.dataset.zoomSource);
        return;
      }
      const fileBtn = e.target.closest("[data-scope-file]");
      if (fileBtn) {
        state.scopeFile = fileBtn.dataset.scopeFile;
        closeEventPopup({ skipFocus: true });
        render();
        return;
      }
      const copyEvBtn = e.target.closest('[data-act="copy-ev-cmd"]');
      if (copyEvBtn) {
        const it = getRecordByKey(copyEvBtn.dataset.evKey || state.eventModalKey);
        const evId = getEvidenceEventId(it);
        const ev = evId && state.org ? state.evidenceCache.get(`${state.org.id}:${evId}`) : null;
        const txt = (ev && ev.command_input) || (it && it.command) || "";
        if (txt) {
          navigator.clipboard?.writeText(txt).then(() => {
            copyEvBtn.textContent = "Copied ✓";
            setTimeout(() => { copyEvBtn.textContent = "Copy command"; }, 1100);
            toast("Command copied.");
          }).catch(() => {});
        }
      }
    });
    eventDialog.addEventListener("close", () => {
      // The native close event can arrive after another row has already opened.
      if (!eventDialog.open && state.eventModalKey) closeEventPopup({ fromNativeClose: true });
    });
  }

  document.querySelector(".tbl thead").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-sort]");
    if (!btn) return;
    const k = btn.dataset.sort;
    if (state.sortKey === k) state.sortDir = state.sortDir === "desc" ? "asc" : "desc";
    else { state.sortKey = k; state.sortDir = k === "ts" || k === "severity" ? "desc" : "asc"; }
    render({ skipExplorer: true });
  });

  document.querySelector(".statusbar").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-quick-sev]");
    if (!btn) return;
    const sev = btn.dataset.quickSev;
    state.filterSev = state.filterSev === sev ? "" : sev;
    el("severity").value = state.filterSev;
    render({ skipExplorer: true });
  });

  document.querySelector(".detail-tabs").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-dtab]");
    if (!btn) return;
    state.detailTab = btn.dataset.dtab;
    const pool = allMergedRecords();
    renderDetails(getRecordByKey(state.selectedKey), pool);
  });

  document.querySelector(".detail-tabs").addEventListener("keydown", (e) => {
    const tabs = [...document.querySelectorAll('.detail-tabs [role="tab"]')];
    const cur = tabs.indexOf(e.target.closest('[role="tab"]'));
    if (cur < 0 || !tabs.length) return;
    let next = -1;
    if (e.key === "ArrowRight") next = (cur + 1) % tabs.length;
    else if (e.key === "ArrowLeft") next = (cur - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = tabs.length - 1;
    if (next < 0) return;
    e.preventDefault();
    const targetTab = tabs[next];
    state.detailTab = targetTab.dataset.dtab;
    renderDetails(getRecordByKey(state.selectedKey), allMergedRecords());
    targetTab.focus();
  });

  el("details").addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !state.zoomOverlay && !(eventDialog && eventDialog.open) && !caseDialog.open) {
      e.preventDefault();
      const row = state.selectedKey ? tbody.querySelector(`tr[data-key="${CSS.escape(state.selectedKey)}"]`) : tbody.querySelector("tr[data-key]");
      if (row) row.focus();
      else el("table-wrap")?.focus();
      announceA11y("Returned focus to live event stream");
    }
  });

  el("details").addEventListener("click", (e) => {
    const originBtn = e.target.closest("[data-open-origin-event]");
    if (originBtn) {
      openVerificationTest(originBtn, originBtn.dataset.openOriginEvent, originBtn.dataset.org);
      return;
    }
    const gapBtn = e.target.closest("[data-gap-search]");
    if (gapBtn) {
      state.search = gapBtn.dataset.gapSearch || "";
      if (el("search")) el("search").value = state.search;
      render({ skipExplorer: true });
      return;
    }
    const test = e.target.closest("[data-verification-test]");
    if (test) { openVerificationTest(test); return; }
    const zoomBtn = e.target.closest("[data-zoom-src]");
    if (zoomBtn) {
      openImageZoom(zoomBtn.dataset.zoomSrc, zoomBtn.dataset.zoomLabel, zoomBtn.dataset.zoomSource);
      return;
    }
    const fileBtn = e.target.closest("[data-scope-file]");
    if (fileBtn) {
      state.scopeFile = state.scopeFile === fileBtn.dataset.scopeFile ? "" : fileBtn.dataset.scopeFile;
      render();
      return;
    }
    const jump = e.target.closest("[data-jump]");
    if (jump) {
      state.detailTab = jump.hasAttribute("data-file-event") ? "files" : "general";
      if (tbody.querySelector(`tr[data-key="${CSS.escape(jump.dataset.jump)}"]`)) {
        selectRowKey(jump.dataset.jump, { scrollIntoView: true });
      } else {
        state.selectedKey = jump.dataset.jump;
        render({ skipExplorer: true });
        tbody.querySelector(`tr[data-key="${CSS.escape(state.selectedKey)}"]`)?.scrollIntoView({ block: "nearest" });
      }
      return;
    }
    const act = e.target.closest("[data-act]");
    if (!act) return;
    const kind = act.dataset.act;
    if (kind === "open-popup") {
      if (state.selectedKey) openEventPopup(state.selectedKey, act);
    } else if (kind === "ack") ackAlert(act.dataset.id);
    else if (kind === "incident") openIncident(act.dataset.id);
    else if (kind === "scope-host") { state.scopeHost = act.dataset.val; render(); }
    else if (kind === "scope-agent") { state.scopeAgent = act.dataset.val; render(); }
    else if (kind === "scope-ws") { state.scopeWorkspace = act.dataset.val; render(); }
    else if (kind === "copy-json") {
      const it = getRecordByKey(state.selectedKey);
      if (it) navigator.clipboard?.writeText(JSON.stringify(it, null, 2)).then(() => {
        act.classList.add("copied");
        setTimeout(() => act.classList.remove("copied"), 1100);
        toast("Event JSON copied.");
      }).catch(() => {});
    } else if (kind === "copy-cmd" || kind === "copy-ev-cmd") {
      const it = getRecordByKey(act.dataset.evKey || state.selectedKey);
      const evId = getEvidenceEventId(it);
      const ev = evId && state.org ? state.evidenceCache.get(`${state.org.id}:${evId}`) : null;
      const txt = (ev && ev.command_input) || (it && it.command) || "";
      if (txt) navigator.clipboard?.writeText(txt).then(() => {
        act.classList.add("copied");
        const prev = act.textContent;
        act.textContent = "Copied ✓";
        setTimeout(() => { act.classList.remove("copied"); act.textContent = prev; }, 1100);
        toast("Command copied.");
      }).catch(() => {});
    }
  });

  el("search").addEventListener("input", (e) => {
    state.search = e.target.value;
    clearTimeout(state.searchDebounce);
    state.searchDebounce = setTimeout(() => render({ skipExplorer: true, skipDetailsIfSame: true }), 15);
  });
  el("window").addEventListener("change", (e) => { state.windowSec = e.target.value; render({ skipExplorer: true }); });
  el("severity").addEventListener("change", (e) => { state.filterSev = e.target.value; render({ skipExplorer: true }); });
  el("kind").addEventListener("change", (e) => { state.filterKind = e.target.value; render({ skipExplorer: true }); });
  el("category").addEventListener("change", (e) => { state.filterCat = e.target.value; render({ skipExplorer: true }); });
  el("status").addEventListener("change", (e) => { state.filterStatus = e.target.value; render({ skipExplorer: true }); });
  el("http-filter")?.addEventListener("change", (e) => {
    state.filterHttp = normalizeHttpFilter(e.target.value);
    render({ skipExplorer: true });
    announceA11y(state.filterHttp ? `Filtered by ${formatHttpFilterLabel(state.filterHttp)}` : "Cleared HTTP status filter");
  });
  el("group-mode").addEventListener("change", (e) => { state.groupMode = e.target.value; render({ skipExplorer: true }); });

  el("copy-link")?.addEventListener("click", async () => {
    syncLiveUrl();
    const fullUrl = `${window.location.origin}${currentLiveUrl()}`;
    try {
      await navigator.clipboard.writeText(fullUrl);
      toast("Diagnostic view link copied.");
      announceA11y("Copied diagnostic view link to clipboard");
    } catch {
      toast("Copy unavailable. Copy the diagnostic link from your address bar.");
    }
  });

  el("tint-btn").addEventListener("click", (e) => {
    state.rowTint = !state.rowTint;
    e.currentTarget.classList.toggle("active", state.rowTint);
    e.currentTarget.setAttribute("aria-pressed", String(state.rowTint));
    appEl.classList.toggle("row-tint", state.rowTint);
  });

  function applyDensity(comfortable) {
    state.comfortable = Boolean(comfortable);
    const btn = el("density-btn");
    if (btn) {
      btn.textContent = state.comfortable ? "Comfortable" : "Compact";
      btn.classList.toggle("active", state.comfortable);
      btn.setAttribute("aria-pressed", String(state.comfortable));
    }
    try { localStorage.setItem("sc_live_density", state.comfortable ? "comfortable" : "compact"); } catch {}
    appEl.classList.toggle("comfortable", state.comfortable);
  }
  el("density-btn")?.addEventListener("click", () => applyDensity(!state.comfortable));

  el("ack-selected").addEventListener("click", () => {
    const it = getRecordByKey(state.selectedKey);
    if (it && it.canAck) ackAlert(it.rawId);
  });
  el("export-csv").addEventListener("click", exportCsv);
  el("export-json").addEventListener("click", exportJson);

  function resetAllFilters() {
    state.perspective = "all"; state.scopeHost = ""; state.scopeAgent = ""; state.scopeWorkspace = "";
    state.scopeProgram = ""; state.scopeTask = ""; state.scopeSession = ""; state.scopeFile = ""; state.scopeRuntime = "";
    state.windowSec = "all"; state.timeFrom = 0; state.timeTo = 0;
    state.filterSev = ""; state.filterKind = ""; state.filterCat = ""; state.filterStatus = "";
    state.filterSource = ""; state.filterHttp = "";
    state.search = ""; state.groupMode = "none";
    el("search").value = ""; el("window").value = "all"; el("severity").value = ""; el("kind").value = "";
    el("category").value = ""; el("status").value = ""; ensureHttpFilterOption(""); el("group-mode").value = "none";
    syncLiveUrl();
    render();
    announceA11y("All filters cleared");
  }
  el("reset-filters").addEventListener("click", resetAllFilters);
  el("clear-scope").addEventListener("click", resetAllFilters);

  el("active-chips")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-clear-chip]");
    if (!btn) return;
    const id = btn.dataset.clearChip;
    if (id === "perspective") state.perspective = "all";
    else if (id === "scopeTask") state.scopeTask = "";
    else if (id === "scopeSession") { state.scopeSession = ""; state.scopeRuntime = ""; }
    else if (id === "scopeFile") state.scopeFile = "";
    else if (id === "scopeHost") state.scopeHost = "";
    else if (id === "scopeAgent") state.scopeAgent = "";
    else if (id === "scopeWorkspace") state.scopeWorkspace = "";
    else if (id === "scopeProgram") state.scopeProgram = "";
    else if (id === "windowSec") { state.windowSec = "all"; el("window").value = "all"; }
    else if (id === "timeBounds") { state.timeFrom = 0; state.timeTo = 0; }
    else if (id === "filterSev") { state.filterSev = ""; el("severity").value = ""; }
    else if (id === "filterKind") { state.filterKind = ""; el("kind").value = ""; }
    else if (id === "filterCat") { state.filterCat = ""; el("category").value = ""; }
    else if (id === "filterStatus") { state.filterStatus = ""; el("status").value = ""; }
    else if (id === "filterSource") { state.filterSource = ""; }
    else if (id === "filterHttp") { state.filterHttp = ""; ensureHttpFilterOption(""); }
    else if (id === "search") { state.search = ""; el("search").value = ""; }
    syncLiveUrl();
    render();
  });

  /* ---------- Draggable Split-Pane Resizer ---------- */
  (function initSplitResizer() {
    const handle = el("split-handle");
    if (!handle) return;
    const setH = (px) => {
      const clamped = Math.round(Math.max(180, Math.min(window.innerHeight * 0.62, px)));
      document.documentElement.style.setProperty("--sc-detail-h", `${clamped}px`);
      handle.setAttribute("aria-valuenow", String(clamped));
      try { localStorage.setItem("sc_live_detail_h", String(clamped)); } catch {}
    };
    try {
      const saved = Number(localStorage.getItem("sc_live_detail_h"));
      if (Number.isFinite(saved) && saved >= 180) setH(saved);
      if (localStorage.getItem("sc_live_density") === "comfortable") state.comfortable = true;
    } catch {}
    let dragging = false;
    handle.addEventListener("pointerdown", (e) => {
      dragging = true;
      handle.classList.add("dragging");
      handle.setPointerCapture?.(e.pointerId);
      e.preventDefault();
    });
    handle.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      setH(window.innerHeight - e.clientY);
    });
    const endDrag = () => { dragging = false; handle.classList.remove("dragging"); };
    handle.addEventListener("pointerup", endDrag);
    handle.addEventListener("pointercancel", endDrag);
    handle.addEventListener("keydown", (e) => {
      const cur = Number(handle.getAttribute("aria-valuenow")) || 272;
      if (e.key === "ArrowUp") { e.preventDefault(); setH(cur + 28); }
      else if (e.key === "ArrowDown") { e.preventDefault(); setH(cur - 28); }
    });
  })();

  /* ---------- Quick Command Palette (Ctrl+K / Cmd+K) ---------- */
  function buildCmdkActions() {
    const pool = allMergedRecords();
    const items = [
      { cat: "View", label: "All Live Stream", hint: "Reset scope", run: () => resetAllFilters() },
      { cat: "View", label: "Agent Work (All)", hint: "Perspective", run: () => { state.perspective = "agent_work"; render(); } },
      { cat: "View", label: "File Edits Only", hint: "Perspective", run: () => { state.perspective = "file_edits"; render(); } },
      { cat: "View", label: "Files & Media", hint: "Perspective", run: () => { state.perspective = "files_touched"; render(); } },
      { cat: "View", label: "Commands & Tests", hint: "Perspective", run: () => { state.perspective = "shell_cmds"; render(); } },
      { cat: "View", label: "Open Alerts", hint: "Perspective", run: () => { state.perspective = "open_alerts"; render(); } },
      { cat: "View", label: "Critical & Warning", hint: "Perspective", run: () => { state.perspective = "crit_warn"; render(); } },
      { cat: "View", label: "Collaboration Tasks", hint: "Perspective", run: () => { state.perspective = "collab"; render(); } },
      { cat: "Group", label: "Group by Severity (SCOM)", hint: "Grouping", run: () => { state.groupMode = "severity"; el("group-mode").value = "severity"; render({ skipExplorer: true }); } },
      { cat: "Group", label: "Group by Agent", hint: "Grouping", run: () => { state.groupMode = "agent"; el("group-mode").value = "agent"; render({ skipExplorer: true }); } },
      { cat: "Group", label: "Group by Workspace", hint: "Grouping", run: () => { state.groupMode = "workspace"; el("group-mode").value = "workspace"; render({ skipExplorer: true }); } },
      { cat: "Group", label: "Flat Timeline", hint: "Grouping", run: () => { state.groupMode = "none"; el("group-mode").value = "none"; render({ skipExplorer: true }); } },
      { cat: "Action", label: state.paused ? "Resume Live Display" : "Pause Display (Buffer New)", hint: "P", run: () => togglePause() },
      { cat: "Action", label: state.comfortable ? "Switch to Compact Density" : "Switch to Comfortable Density", hint: "D", run: () => applyDensity(!state.comfortable) },
      { cat: "Action", label: "Filter HTTP 4xx Errors", hint: "4xx", run: () => { state.filterHttp = "4xx"; ensureHttpFilterOption("4xx"); render({ skipExplorer: true }); } },
      { cat: "Action", label: "Filter HTTP 5xx Errors", hint: "5xx", run: () => { state.filterHttp = "5xx"; ensureHttpFilterOption("5xx"); render({ skipExplorer: true }); } },
      { cat: "Action", label: "Copy Diagnostic View Link", hint: "URL", run: () => el("copy-link")?.click() },
      { cat: "Action", label: "Export Filtered CSV", hint: "CSV", run: () => exportCsv() },
      { cat: "Action", label: "Export Filtered JSON", hint: "JSON", run: () => exportJson() },
      { cat: "Nav", label: "Back to Main Control Room", hint: "/", run: () => { window.location.href = "/"; } },
    ];
    const agents = [...new Set(pool.filter((r) => r.kind === "Agent Work" || r.kind === "Collaboration").map((r) => r.agent).filter(Boolean))].slice(0, 10);
    for (const ag of agents) {
      items.push({ cat: "Agent", label: `Filter agent: ${ag}`, hint: "Scope", run: () => { state.scopeAgent = ag; render(); } });
    }
    const hosts = [...new Set(pool.map((r) => r.host_id).filter(Boolean))].slice(0, 8);
    for (const h of hosts) {
      items.push({ cat: "Host", label: `Filter host: ${h}`, hint: "Scope", run: () => { state.scopeHost = h; render(); } });
    }
    return items;
  }

  function renderCmdkList() {
    const q = (el("cmdk-input")?.value || "").trim().toLowerCase();
    const all = buildCmdkActions();
    state.cmdkItems = q ? all.filter((it) => `${it.cat} ${it.label} ${it.hint}`.toLowerCase().includes(q)) : all;
    if (state.cmdkIdx >= state.cmdkItems.length) state.cmdkIdx = 0;
    const list = el("cmdk-list");
    if (!list) return;
    list.innerHTML = state.cmdkItems.length
      ? state.cmdkItems
          .map(
            (it, i) => `<li><button type="button" class="cmdk-item${i === state.cmdkIdx ? " active" : ""}" data-cmdk-idx="${i}">
              <span><span class="cmdk-cat">${esc(it.cat)}</span>${esc(it.label)}</span>
              <kbd>${esc(it.hint)}</kbd>
            </button></li>`
          )
          .join("")
      : '<li class="muted" style="padding:12px;text-align:center;">No matching command or scope.</li>';
  }

  function openCmdk() {
    const ov = el("cmdk-overlay");
    if (!ov) return;
    state.cmdkOpen = true;
    state.cmdkIdx = 0;
    ov.classList.remove("hidden");
    const inp = el("cmdk-input");
    if (inp) { inp.value = ""; inp.focus(); }
    renderCmdkList();
  }

  function closeCmdk() {
    state.cmdkOpen = false;
    el("cmdk-overlay")?.classList.add("hidden");
  }

  el("cmdk-btn")?.addEventListener("click", openCmdk);
  el("cmdk-overlay")?.addEventListener("click", (e) => {
    if (e.target === el("cmdk-overlay")) { closeCmdk(); return; }
    const btn = e.target.closest("[data-cmdk-idx]");
    if (btn) {
      const it = state.cmdkItems[Number(btn.dataset.cmdkIdx)];
      closeCmdk();
      if (it) it.run();
    }
  });
  el("cmdk-input")?.addEventListener("input", () => { state.cmdkIdx = 0; renderCmdkList(); });
  el("cmdk-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); closeCmdk(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); state.cmdkIdx = (state.cmdkIdx + 1) % Math.max(1, state.cmdkItems.length); renderCmdkList(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); state.cmdkIdx = (state.cmdkIdx - 1 + Math.max(1, state.cmdkItems.length)) % Math.max(1, state.cmdkItems.length); renderCmdkList(); }
    else if (e.key === "Enter") {
      e.preventDefault();
      const it = state.cmdkItems[state.cmdkIdx];
      closeCmdk();
      if (it) it.run();
    }
  });

  el("pause").addEventListener("click", togglePause);
  el("load-older")?.addEventListener("click", loadOlderHistory);
  el("show-more-rows")?.addEventListener("click", () => {
    state.renderLimit += 200;
    render({ skipExplorer: true, skipDetails: true });
  });
  el("refresh").addEventListener("click", () => {
    if (state.paused) togglePause();
    poll(true);
  });
  el("interval").addEventListener("change", (e) => {
    state.intervalMs = Number(e.target.value) || 2500;
    startTimer();
  });

  el("fullscreen").addEventListener("click", async () => {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch { toast("Browser full screen unavailable."); }
  });
  document.addEventListener("fullscreenchange", () => {
    el("fullscreen").textContent = document.fullscreenElement ? "Exit full screen" : "Full screen";
  });

  orgSwitcher.addEventListener("change", async () => {
    const orgId = orgSwitcher.value;
    if (!orgId || orgId === state.org?.id) return;
    try {
      const res = await api("/api/v1/auth/switch", { method: "POST", body: JSON.stringify({ organization_id: orgId }) });
      clearState();
      applySession(res);
      toast(`Switched to ${res.organization?.name || "organization"}.`);
      await poll(true);
    } catch (err) {
      toast(err.message || "Could not switch organization.");
    }
  });

  el("logout").addEventListener("click", async () => {
    await api("/api/v1/auth/logout", { method: "POST", body: "{}" }).catch(() => {});
    stopTimer();
    clearState();
    appEl.classList.add("hidden");
    authGate.classList.remove("hidden");
  });

  document.addEventListener("keydown", (e) => {
    if (state.zoomOverlay && e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      closeImageZoom();
      return;
    }
    if (caseDialog.open || (eventDialog && eventDialog.open)) return;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (state.cmdkOpen) closeCmdk();
      else openCmdk();
      return;
    }
    if (state.cmdkOpen) {
      if (e.key === "Escape") { e.preventDefault(); closeCmdk(); }
      return;
    }
    const tag = (e.target.tagName || "").toLowerCase();
    const typing = tag === "input" || tag === "textarea" || tag === "select";
    if (e.key === "/" && !typing) { e.preventDefault(); el("search").focus(); return; }
    if (typing) return;
    if (e.key === "Enter" && state.selectedKey && tag !== "button" && tag !== "a") {
      const focusedRow = e.target.closest?.("tr[data-key]") || tbody.querySelector(`tr[data-key="${CSS.escape(state.selectedKey)}"]`);
      e.preventDefault();
      openEventPopup(state.selectedKey, focusedRow);
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const inDetailsOrSidebar = Boolean(e.target.closest?.("#details, #sidebar"));
      if (inDetailsOrSidebar) return;
      const visibleRows = [...tbody.querySelectorAll("tr[data-key]")];
      if (!visibleRows.length) return;
      e.preventDefault();
      const idx = visibleRows.findIndex((tr) => tr.dataset.key === state.selectedKey);
      const next = e.key === "ArrowDown" ? Math.min(visibleRows.length - 1, idx + 1) : Math.max(0, idx - 1);
      const targetRow = visibleRows[next];
      if (targetRow) {
        selectRowKey(targetRow.dataset.key, { scrollIntoView: true });
        targetRow.focus({ preventScroll: true });
      }
    } else if (e.key === "a" || e.key === "A") {
      const it = getRecordByKey(state.selectedKey);
      if (it && it.canAck) ackAlert(it.rawId);
    } else if (e.key === "p" || e.key === "P") {
      togglePause();
    } else if (e.key === "d" || e.key === "D") {
      applyDensity(!state.comfortable);
    } else if (e.key === "f" || e.key === "F") {
      el("fullscreen").click();
    }
  });

  async function boot() {
    const initial = new URLSearchParams(window.location.search);
    applyUrlParams();
    try {
      const me = await api("/api/v1/auth/me");
      if (!me.authenticated) throw new Error("unauthenticated");
      applySession(me);
      authGate.classList.add("hidden");
      appEl.classList.remove("hidden");
      const dBtn = el("density-btn");
      if (dBtn && state.comfortable) {
        dBtn.textContent = "Comfortable";
        dBtn.classList.add("active");
        dBtn.setAttribute("aria-pressed", "true");
      }
      await poll(true);
      if (initial.has("incident") && initial.get("organization") === String(state.org?.id)) {
        openIncident(initial.get("incident"));
      }
      startTimer();
    } catch (_) {
      appEl.classList.add("hidden");
      authGate.classList.remove("hidden");
    }
  }

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !state.paused) poll(false);
  });
  window.addEventListener("focus", () => { if (!state.paused && !document.hidden) poll(false); });
  boot();
})();
