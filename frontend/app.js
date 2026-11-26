/* NeuroSwarm Product Console — Multi-tenant Auth, Onboarding, Roles & Installers
   Vanilla JS, zero external CDN dependencies, 100% CSP-safe (no inline handlers). */

const loginView = document.getElementById("login-view");
const appView = document.getElementById("app-view");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const inviteAcceptForm = document.getElementById("invite-accept-form");
const loginError = document.getElementById("login-error");
const registerError = document.getElementById("register-error");
const inviteAcceptError = document.getElementById("invite-accept-error");
const tokenError = document.getElementById("token-error");
const operatorLabel = document.getElementById("operator-label");
const roleBadge = document.getElementById("role-badge");
const orgBadge = document.getElementById("org-badge");
const orgSwitcher = document.getElementById("org-switcher");
const fleetBadge = document.getElementById("fleet-badge");
const auditIntegrityBadge = document.getElementById("audit-integrity-badge");
const alertFilter = document.getElementById("alert-filter");
const statusToast = document.getElementById("status-toast");

let refreshTimer = null;
let toastTimer = null;
let viewGeneration = 0;
let workBoardRequest = 0;
let mfaPendingPassword = "";

const sessionState = {
  user: null,
  organization: null,
  memberships: [],
  publicUrl: "",
  dismissedOnboardingOrgs: new Set(),
  lastCreatedToken: null,
  installPlatform: "unix",
  collabInitialized: false,
  links: { version: "1", by_task: {}, by_session: {} },
  focusedTaskId: "",
  taskFocusApplied: false,
};

function safeRelativeUrl(raw) {
  const s = String(raw || "").trim();
  if (!s || !s.startsWith("/") || s.startsWith("//") || /[\r\n\0]/.test(s)) return "";
  return s;
}

function currentHomeReturnUrl(anchor = "#agent-work") {
  const u = new URL(window.location.href);
  u.searchParams.delete("return_to");
  const qs = u.searchParams.toString();
  return "/" + (qs ? "?" + qs : "") + (anchor || "");
}

function buildLiveLink(params, anchor = "#agent-work") {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null && String(v).trim() !== "") qs.set(k, String(v).trim());
  }
  qs.set("from", currentHomeReturnUrl(anchor));
  return `/live?${qs.toString()}`;
}

function renderReturnBanner() {
  const main = document.getElementById("main-content");
  if (!main) return;
  const params = new URLSearchParams(window.location.search);
  const ret = safeRelativeUrl(params.get("return_to"));
  let banner = document.getElementById("return-nav-banner");
  if (!ret) {
    if (banner) banner.remove();
    return;
  }
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "return-nav-banner";
    banner.className = "return-nav-banner";
    banner.setAttribute("role", "region");
    banner.setAttribute("aria-label", "Return navigation");
    main.prepend(banner);
  }
  const destLabel = ret.startsWith("/live") ? "Return to Live NOC (filters preserved)" : "Return to previous view (filters preserved)";
  banner.innerHTML = `<a href="${esc(ret)}" class="btn small primary" id="return-prev-link">← ${esc(destLabel)}</a>
    <span class="muted small">Explicit navigation context active</span>
    <button type="button" class="link-dismiss-btn" id="dismiss-return-banner" title="Dismiss return bar">Dismiss</button>`;
  document.getElementById("dismiss-return-banner")?.addEventListener("click", () => {
    const u = new URL(window.location.href);
    u.searchParams.delete("return_to");
    if (history.replaceState) history.replaceState(null, "", u.pathname + (u.search ? u.search : "") + u.hash);
    banner.remove();
  });
}

function esc(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeClass(str, fallback = "waiting") {
  const cleaned = String(str ?? "").toLowerCase().replace(/[^a-z0-9_-]/g, "");
  return cleaned || fallback;
}

function showToast(message) {
  if (!statusToast || !message) return;
  statusToast.textContent = message;
  statusToast.classList.remove("hidden");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    statusToast.classList.add("hidden");
  }, 4500);
}

function showError(el, msg) {
  if (!el) return;
  if (!msg) {
    el.textContent = "";
    el.classList.add("hidden");
    return;
  }
  el.textContent = msg;
  el.classList.remove("hidden");
}

function fmtAge(ts) {
  if (!ts) return "never";
  const diff = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function roleOf() {
  return String(sessionState.user?.role || "viewer").toLowerCase();
}
function isAdmin() {
  return roleOf() === "admin";
}
function canAckAlerts() {
  const r = roleOf();
  return r === "admin" || r === "operator";
}

function friendlyFolder(folder) {
  const raw = String(folder || "").trim();
  if (!raw) return "";
  const parts = raw.replace(/\\/g, "/").split("/").filter(Boolean);
  if (parts.length <= 3) return raw;
  return `…/${parts.slice(-3).join("/")}`;
}

function sanitizeRoots(raw, sep) {
  const cleaned = String(raw || "")
    .split(/[:,;]+/)
    .map((s) => s.trim().replace(/["'`$\r\n]/g, ""))
    .filter(Boolean);
  return cleaned.join(sep);
}

function buildInstallSnippet(created, platform) {
  const token = created?.token ? String(created.token) : "";
  const scope = String(created?.scope || "ingest").toLowerCase();
  const baseUrl = String(created?.install_base_url || sessionState.publicUrl || window.location.origin).replace(/\/+$/, "");
  const rawRoots = document.getElementById("token-activity-roots")?.value || "";

  if (scope === "read") {
    return `# Read-only API Bearer token (monitoring GET routes only)\ncurl -fsSL -H "Authorization: Bearer ${token}" "${baseUrl}/api/v1/overview"`;
  }

  const unixRoots = sanitizeRoots(rawRoots, ":");
  if (platform === "windows") {
    const quote = (value) => "'" + value.replace(/'/g, "''") + "'";
    const roots = rawRoots.split(/[,;\r\n]+/).map((path) => path.trim()).filter(Boolean);
    return [
      'Write-Host "[NeuroSwarm] Downloading the Windows installer..."',
      `$env:SWARMCONTROL_TOKEN=${quote(token)}`,
      ...(roots.length ? [`$env:SWARMCONTROL_ACTIVITY_ROOTS=${quote(roots.join(";"))}`] : []),
      `irm -ErrorAction Stop ${quote(baseUrl + "/install.ps1")} | iex`,
    ].join("\n");
  }
  if (platform === "repo") {
    const rootsFlag = unixRoots ? ` --activity-roots "${unixRoots}"` : "";
    return [
      "# 1. Preview locally-redacted payload before sending anything:",
      `python3 agent/swarmcontrol_agent.py --preview-activity${rootsFlag || ' --activity-roots "/path/to/workspace"'}`,
      "",
      "# 2. Run a single authenticated check-in from the repository:",
      `SWARMCONTROL_TOKEN=${token} python3 agent/swarmcontrol_agent.py --server "${baseUrl}"${rootsFlag} --once`,
    ].join("\n");
  }
  if (platform === "docker") {
    return [
      "# Self-host the NeuroSwarm server with Docker Compose:",
      "docker compose up -d",
      "# Then enroll remote machines using the Linux/macOS/WSL or Windows tab.",
    ].join("\n");
  }
  const envRoots = unixRoots ? ` SWARMCONTROL_ACTIVITY_ROOTS="${unixRoots}"` : "";
  if (!unixRoots && created && typeof created.install_command === "string" && created.install_command.includes("SWARMCONTROL_TOKEN=")) {
    return created.install_command;
  }
  return `curl -fsSL ${baseUrl}/install.sh | SWARMCONTROL_TOKEN=${token}${envRoots} bash`;
}

function renderInstallOutput() {
  const box = document.getElementById("install-output");
  const cmdEl = document.getElementById("install-cmd");
  const titleEl = document.getElementById("install-output-title");
  const noteEl = document.getElementById("install-cmd-note");
  const tabsEl = document.getElementById("install-platform-tabs");
  const created = sessionState.lastCreatedToken;
  if (!box || !cmdEl || !created) return;

  const isRead = String(created.scope || "ingest").toLowerCase() === "read";
  if (tabsEl) tabsEl.classList.toggle("hidden", isRead);
  if (titleEl) {
    titleEl.textContent = isRead
      ? "Read-only API token created."
      : "Run on the host you want to monitor.";
  }
  if (noteEl) {
    noteEl.textContent = isRead
      ? "Save this token now. It grants read-only GET access to this organization's monitoring routes and is shown only once."
      : "Save this command now. The single-host ingest token is shown only once and binds to the first reporting host.";
  }
  cmdEl.textContent = buildInstallSnippet(created, sessionState.installPlatform);
  box.classList.remove("hidden");
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || data.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.data = data;
    const retryHeader = res.headers.get("Retry-After");
    const retryRaw = data.retry_after ?? (retryHeader !== null ? Number(retryHeader) : null);
    if (retryRaw !== null && Number.isFinite(Number(retryRaw))) {
      err.retryAfter = Math.max(1, Math.ceil(Number(retryRaw)));
    }
    throw err;
  }
  return data;
}

/* ---------- Auth tabs & invite deep-link ---------- */
function switchAuthTab(tabName) {
  document.querySelectorAll("[data-auth-tab]").forEach((btn) => {
    const active = btn.dataset.authTab === tabName;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  ["signin", "register", "invite"].forEach((name) => {
    const panel = document.getElementById(`panel-${name}`);
    if (panel) panel.classList.toggle("hidden", name !== tabName);
  });
  showError(loginError, "");
  showError(registerError, "");
  showError(inviteAcceptError, "");
}

function readInviteFromUrl() {
  try {
    const qs = new URLSearchParams(window.location.search);
    const fromQuery = qs.get("invite") || qs.get("invitation");
    if (fromQuery) return fromQuery.trim();
    const hash = window.location.hash || "";
    const m = hash.match(/invite=([A-Za-z0-9._-]+)/);
    return m ? m[1] : "";
  } catch (_) {
    return "";
  }
}

function clearOrgViews() {
  document.getElementById("mission-preview")?.replaceChildren();
  workBoardRequest++;
  sessionState.collabInitialized = false;
  sessionState.links = { version: "1", by_task: {}, by_session: {} };
  sessionState.focusedTaskId = "";
  sessionState.taskFocusApplied = false;
  const wb = document.getElementById("work-board");
  if (wb) wb.innerHTML = '<p class="muted small">Loading workspace evidence…</p>';
  const alertsEl = document.getElementById("alerts-list");
  if (alertsEl) alertsEl.innerHTML = "";
  const hostsEl = document.getElementById("hosts-list");
  if (hostsEl) hostsEl.innerHTML = "";
  const eventsEl = document.getElementById("events-list");
  if (eventsEl) eventsEl.innerHTML = "";
  const auditEl = document.getElementById("audit-list");
  if (auditEl) auditEl.innerHTML = "";
  const tokensEl = document.getElementById("tokens-list");
  if (tokensEl) tokensEl.innerHTML = "";
}

/* ---------- View transitions ---------- */
const publicSections = ["#intro", "#self-host", "#trace-example"];
function scrollToPublicSection() {
  if (publicSections.includes(window.location.hash)) {
    document.getElementById(window.location.hash.slice(1))?.scrollIntoView?.({behavior: "instant"});
  }
}

function showLogin(preferredTab) {
  viewGeneration++;
  if (refreshTimer) clearInterval(refreshTimer);
  clearOrgViews();
  sessionState.user = null;
  sessionState.organization = null;
  sessionState.memberships = [];
  sessionState.lastCreatedToken = null;
  appView.classList.add("hidden");
  loginView.classList.remove("hidden");

  const urlInvite = readInviteFromUrl();
  if (urlInvite || window.location.hash === "#access" || (window.location.hash && !publicSections.includes(window.location.hash))) {
    document.getElementById("access")?.scrollIntoView?.({behavior: "instant"});
  }
  scrollToPublicSection();
  if (preferredTab) {
    switchAuthTab(preferredTab);
  } else if (urlInvite) {
    const invInput = document.getElementById("inv-token");
    if (invInput && !invInput.value) invInput.value = urlInvite;
    switchAuthTab("invite");
  } else {
    switchAuthTab("signin");
  }
}

function applySession(payload) {
  sessionState.user = payload.user || null;
  sessionState.organization = payload.organization || { id: "default", name: "Default Organization" };
  sessionState.memberships = Array.isArray(payload.memberships) && payload.memberships.length
    ? payload.memberships
    : [
        {
          id: sessionState.organization.id,
          name: sessionState.organization.name,
          role: roleOf(),
        },
      ];
  sessionState.publicUrl = payload.public_url || window.location.origin;

  const orgName = sessionState.organization.name || "Organization";
  if (operatorLabel) operatorLabel.textContent = sessionState.user?.username || "";
  if (roleBadge) {
    roleBadge.textContent = roleOf().toUpperCase();
    roleBadge.title = `Current organization role: ${roleOf()}`;
  }
  const overviewKicker = document.getElementById("overview-org-kicker");
  if (overviewKicker) overviewKicker.textContent = orgName.toUpperCase();
  const obOrgName = document.getElementById("onboarding-org-name");
  if (obOrgName) obOrgName.textContent = orgName;
  const orgSectionBadge = document.getElementById("org-section-badge");
  if (orgSectionBadge) orgSectionBadge.textContent = orgName;

  if (orgSwitcher && orgBadge) {
    if (sessionState.memberships.length > 1) {
      orgSwitcher.innerHTML = sessionState.memberships
        .map((m) => `<option value="${esc(m.id)}"${m.id === sessionState.organization.id ? " selected" : ""}>${esc(m.name)} (${esc(m.role)})</option>`)
        .join("");
      orgSwitcher.classList.remove("hidden");
      orgBadge.classList.add("hidden");
    } else {
      orgBadge.textContent = orgName;
      orgBadge.classList.remove("hidden");
      orgSwitcher.classList.add("hidden");
    }
  }

  applyRoleVisibility();
  renderSecurityPanel();
}

function applyRoleVisibility() {
  const admin = isAdmin();
  const tokenForm = document.getElementById("token-form");
  const enrollNote = document.getElementById("enrollment-readonly-note");
  if (tokenForm) tokenForm.classList.toggle("hidden", !admin);
  if (enrollNote) enrollNote.classList.toggle("hidden", admin);

  const orgAdmin = document.getElementById("org-admin-panel");
  const orgNonAdmin = document.getElementById("org-nonadmin-note");
  const nonAdminRole = document.getElementById("nonadmin-role-label");
  if (orgAdmin) orgAdmin.classList.toggle("hidden", !admin);
  if (orgNonAdmin) orgNonAdmin.classList.toggle("hidden", admin);
  if (nonAdminRole) nonAdminRole.textContent = roleOf();

  const memBox = document.getElementById("org-memberships-box");
  const memSummary = document.getElementById("org-memberships-summary");
  if (memBox && memSummary) {
    if (sessionState.memberships.length > 0) {
      memSummary.textContent = sessionState.memberships.map((m) => `${m.name} (${m.role})`).join(" · ");
      memBox.classList.remove("hidden");
    } else {
      memBox.classList.add("hidden");
    }
  }

  const navAudit = document.getElementById("nav-audit-link");
  if (navAudit) navAudit.classList.toggle("hidden", !admin);
}

function showApp(sessionPayload, notifyOrgSwitch = false) {
  viewGeneration++;
  if (notifyOrgSwitch) clearOrgViews();
  const entering = !loginView.classList.contains("hidden");
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  applySession(sessionPayload);
  if (entering && (!location.hash || location.hash === "#access" || publicSections.includes(location.hash))) {
    const destination = new URL(window.location.href);
    destination.hash = "";
    window.history.replaceState({}, document.title, destination);
    window.scrollTo({top: 0, behavior: "instant"});
  }

  if (readInviteFromUrl()) {
    try {
      const url = new URL(window.location.href);
      url.searchParams.delete("invite");
      url.searchParams.delete("invitation");
      if (url.hash.startsWith("#invite=")) url.hash = "";
      window.history.replaceState({}, document.title, url);
    } catch (_) {}
  }

  if (notifyOrgSwitch) {
    document.dispatchEvent(
      new CustomEvent("swarm-org-changed", {
        detail: { organization: sessionState.organization, user: sessionState.user },
      })
    );
  }
  loadAll();
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(loadAll, 10000);
}

async function checkAuth() {
  if (new URLSearchParams(window.location.search).get("view") === "home" && !readInviteFromUrl()) {
    loginView.classList.remove("hidden");
    document.getElementById("access").hidden = true;
    document.querySelector(".folio-enter").href = "/#access";
    scrollToPublicSection();
    return;
  }
  try {
    const data = await api("/api/v1/auth/me");
    if (data.authenticated) {
      showApp(data);
      return;
    }
  } catch (_) {}
  showLogin();
}

/* ---------- Data loading ---------- */
async function loadAll() {
  const generation = viewGeneration;
  const admin = isAdmin();
  try {
    const reqs = [
      api("/api/v1/overview"),
      admin ? api("/api/v1/tokens").catch((err) => (err.status === 401 ? Promise.reject(err) : { tokens: [] })) : Promise.resolve({ tokens: [] }),
      admin
        ? api("/api/v1/audit/verify").catch((err) => {
            if (err.status === 401) throw err;
            return { __unavailable: true };
          })
        : Promise.resolve({ __restricted: true }),
      admin ? api("/api/v1/members").catch((err) => (err.status === 401 ? Promise.reject(err) : { members: [] })) : Promise.resolve({ members: [] }),
      admin ? api("/api/v1/invitations").catch((err) => (err.status === 401 ? Promise.reject(err) : { invitations: [] })) : Promise.resolve({ invitations: [] }),
    ];
    const [overview, tokenData, auditVerify, memberData, inviteData] = await Promise.all(reqs);
    if (generation !== viewGeneration || appView.classList.contains("hidden")) return;

    renderOnboarding(overview.hosts || []);
    renderDigest(overview.digest || {});
    renderAlerts(overview.alerts || []);
    renderHosts(overview.hosts || []);
    renderEvents(overview.events || []);
    loadWorkBoard(overview.events || []);
    renderAudit(overview.audit || []);
    renderAuditIntegrity(auditVerify);
    renderTokens(tokenData.tokens || []);
    if (admin) {
      renderMembers(memberData.members || []);
      renderInvitations(inviteData.invitations || []);
    }
  } catch (err) {
    if (generation === viewGeneration && err.status === 401) showLogin();
  }
}

/* ---------- Renderers ---------- */
function renderOnboarding(hosts) {
  const banner = document.getElementById("onboarding-banner");
  if (!banner) return;
  const orgId = sessionState.organization?.id || "default";
  const dismissed = sessionState.dismissedOnboardingOrgs.has(orgId);
  const hasHosts = Array.isArray(hosts) && hosts.length > 0;
  const stepHost = document.getElementById("ob-step-host");
  const stepTeam = document.getElementById("ob-step-team");
  if (stepHost) stepHost.classList.toggle("done", hasHosts);
  if (stepTeam) stepTeam.classList.toggle("done", Boolean(sessionState.user?.mfa_enabled));

  banner.classList.toggle("hidden", dismissed || hasHosts);
}

function renderAuditIntegrity(verifyData) {
  if (!auditIntegrityBadge) return;
  if (verifyData && verifyData.__restricted) {
    auditIntegrityBadge.className = "pill neutral";
    auditIntegrityBadge.textContent = "ADMIN ONLY";
    auditIntegrityBadge.title = "Audit verification is restricted to organization admins";
    return;
  }
  if (!verifyData || verifyData.__unavailable || typeof verifyData.ok !== "boolean") {
    auditIntegrityBadge.className = "pill waiting";
    auditIntegrityBadge.textContent = "UNVERIFIED";
    auditIntegrityBadge.title = "Audit chain verification endpoint unavailable";
    return;
  }
  const entries = Number.isFinite(Number(verifyData.entries)) ? Number(verifyData.entries) : 0;
  const headHint = verifyData.head ? ` · head ${String(verifyData.head).slice(0, 12)}` : "";
  if (verifyData.ok) {
    auditIntegrityBadge.className = "pill healthy";
    auditIntegrityBadge.textContent = `SHA-256 OK (${entries})`;
    auditIntegrityBadge.title = `Audit SHA-256 hash chain verified across ${entries} entries${headHint}`;
    return;
  }
  const brokenId = verifyData.broken_at !== null && verifyData.broken_at !== undefined ? ` #${verifyData.broken_at}` : "";
  auditIntegrityBadge.className = "pill critical";
  auditIntegrityBadge.textContent = `CHAIN BROKEN${brokenId}`;
  auditIntegrityBadge.title = `Audit SHA-256 integrity check failed${brokenId ? ` at entry${brokenId}` : ""} (${entries} entries${headHint})`;
}

function renderDigest(digest) {
  const status = safeClass(digest.fleet_status, "waiting");
  fleetBadge.textContent = digest.fleet_status || "WAITING";
  fleetBadge.className = `pill ${status}`;
  document.getElementById("digest-headline").textContent = digest.headline || "Waiting for your first enrolled host.";
  document.getElementById("digest-time").textContent = digest.generated_at ? `Updated ${fmtAge(digest.generated_at)}` : "";
  const ul = document.getElementById("digest-bullets");
  ul.innerHTML = (digest.bullets || []).map((b) => `<li>${esc(b)}</li>`).join("");

  const m = digest.metrics || {};
  document.getElementById("kpi-hosts").textContent = m.hosts ?? 0;
  document.getElementById("kpi-procs").textContent = m.active_agent_processes ?? 0;
  document.getElementById("kpi-harnesses").textContent = (m.running_harnesses || []).length;
  document.getElementById("kpi-alerts").textContent = m.open_alerts ?? 0;
  document.getElementById("kpi-scan").textContent = `${m.observer_max_scan_ms ?? 0} ms`;
}

function renderAlerts(alerts) {
  const mode = alertFilter.value;
  const filtered = alerts.filter(a => mode === "ALL" || (mode === "ACTIVE" ? a.status !== "RESOLVED" : a.status === "OPEN"));
  const orgId = sessionState.organization?.id;
  const el = document.getElementById("alerts-list");
  if (!filtered.length) {
    el.innerHTML = `<div class="muted small">No matching incidents in this organization.</div>`;
    return;
  }
  const allowAck = canAckAlerts();
  el.innerHTML = filtered
    .map(
      (a) => `
      <div class="item-row">
        <div>
          <div class="item-title">
            <span class="pill ${safeClass(a.severity, "info")}">${esc(a.severity)}</span>
            ${esc(a.title)}
          </div>
          <div class="item-meta">${esc(a.summary)}</div>
          <div class="item-meta"><code>${esc(a.rule_code)}</code> · ${esc(a.host_id)} · ${fmtAge(a.updated_at)}</div>
          <div class="item-meta">
            <a href="/live?incident=${encodeURIComponent(a.id)}&amp;organization=${encodeURIComponent(orgId)}&amp;event=alert%3A${encodeURIComponent(a.id)}">Incident #${esc(a.id)}</a>
            · ${a.count_is_minimum ? "At least " : ""}${esc(a.occurrence_count ?? 1)} signals · ${esc(a.owner || "Unassigned")}
            ${a.previous_id ? ` · Recurrence after #${esc(a.previous_id)}` : ""}
          </div>
        </div>
        <div>
          ${
            a.status === "OPEN"
              ? allowAck
                ? `<button class="btn small secondary" data-ack="${esc(a.id)}">Acknowledge</button>`
                : `<span class="pill waiting">OPEN</span>`
              : a.status === "RESOLVED"
                ? `<span class="pill resolved">RESOLVED</span>`
                : `<span class="pill ${safeClass(a.status, "acked")}">${esc(a.status || "ACKED")}</span>`
          }
        </div>
      </div>`
    )
    .join("");
  el.querySelectorAll("[data-ack]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/v1/alerts/${encodeURIComponent(btn.dataset.ack)}/ack`, { method: "POST", body: JSON.stringify({ organization_id: orgId }) });
        loadAll();
      } catch (err) {
        if (err.status === 401) showLogin();
        else showToast(err.message || "Could not acknowledge the incident.");
      }
    });
  });
}

function renderRuntimeEvidence(host, runtime, expanded) {
  const evidence = Array.isArray(runtime.evidence) ? runtime.evidence.map(String) : [];
  const processes = Number(runtime.process_count) || 0;
  const installed = evidence.some((v) => v.startsWith("bin:") || v.startsWith("managed:"));
  const foldersOnly = evidence.length > 0 && evidence.every((v) => v.startsWith("dir:") || v.startsWith("runtime-dir:") || v.startsWith("openbot-runtime:"));
  const status = processes > 0 || evidence.some((v) => v.startsWith("service:"))
    ? "running"
    : installed
      ? "installed"
      : foldersOnly
        ? "configured"
        : runtime.status || "unknown";
  const statusText = { running: "Running", installed: "Installed", configured: "Folder only" }[status] || status;
  const versions = evidence
    .filter((v) => v.startsWith("managed:"))
    .map((v) => v.split("/")[2])
    .filter(Boolean);
  if (runtime.version && !versions.includes(runtime.version)) versions.unshift(runtime.version);
  const key = JSON.stringify([host.host_id, runtime.id]);
  const labels = {
    bin: "Executable on PATH",
    managed: "Managed runtime",
    dir: "Config directory",
    service: "Active service",
    "runtime-dir": "Runtime directory",
    "openbot-runtime": "Managed runtime directory",
  };
  const details = evidence.map((value) => {
    const i = value.indexOf(":");
    const type = i >= 0 ? value.slice(0, i) : "";
    const path = i >= 0 ? value.slice(i + 1) : value;
    return `<li>${esc(labels[type] || "Observer evidence")} · <code>${esc(path)}</code></li>`;
  });
  if (processes) details.unshift(`<li>${processes} matched process${processes === 1 ? "" : "es"} in this sample.</li>`);
  const workspaceCount = Number(runtime.workspace_agents) || 0;
  if (workspaceCount) details.push(`<li>${workspaceCount} agent workspace directories found on this host.</li>`);
  if (!details.length) details.push("<li>No detection details in this sample.</li>");
  return `<details class="runtime-proof" data-inventory="${esc(key)}"${expanded.has(key) ? " open" : ""}>
    <summary><span class="runtime-name">${esc(runtime.name)}</span> <span class="pill ${safeClass(status)}">${esc(statusText)}</span>
    <span class="runtime-meta">${versions.length ? "v" + esc([...new Set(versions)].join(" / v")) + " · " : ""}${processes} proc</span></summary>
    <ul>${details.join("")}</ul></details>`;
}

function renderProcessFolders(processes) {
  const folders = new Map();
  for (const process of processes) {
    if (!process.workspace) continue;
    const names = folders.get(process.workspace) || new Set();
    names.add(process.harness || "Unknown runtime");
    folders.set(process.workspace, names);
  }
  if (!folders.size) return '<p class="muted small">No project folder identified in the sampled processes.</p>';
  const items = Array.from(
    folders,
    ([folder, names]) =>
      `<li><code title="${esc(folder)}">${esc(friendlyFolder(folder))}</code><span class="muted small">${esc([...names].join(", "))}</span></li>`
  ).join("");
  return `<h4 class="host-subhead">Observed working folders</h4><ul class="process-folders">${items}</ul>
    <p class="muted small">A process was seen in each folder. This observation does not identify who edited a file.</p>`;
}

/* What each collector on a host may share, as it last reported it (issue #11). Older collectors report nothing: Unknown. */
const CAPTURE_SWITCHES = [
  ["activity", "Agent activity"], ["commands", "Command text"], ["command_output", "Command output"],
  ["file_previews", "File previews"], ["line_survival", "Lines still in the code"],
];
const CAPTURE_SOURCES = { observer: "Observer", journal: "Local activity journal" };
function renderCaptureSettings(h) {
  const reports = Array.isArray(h.capture_settings) ? h.capture_settings.filter((r) => r && CAPTURE_SOURCES[r.source]) : [];
  if (!reports.some((r) => r.source === "observer")) reports.unshift({ source: "observer", settings: null, reported_at: null });
  const state = (settings, key) => {
    const v = settings && typeof settings[key] === "boolean" ? settings[key] : null;
    return v === null ? ["unknown", "Unknown"] : v ? ["on", "On"] : ["off", "Off"];
  };
  const rows = reports.map((r) => {
    const s = r.settings && typeof r.settings === "object" ? r.settings : null;
    const folders = s && Number.isInteger(s.shared_folders) ? ` · ${s.shared_folders} shared folder${s.shared_folders === 1 ? "" : "s"}` : "";
    const when = r.reported_at ? `reported ${fmtAge(r.reported_at)}` : "never reported";
    const chips = CAPTURE_SWITCHES.map(([key, label]) => {
      const [cls, text] = state(s, key);
      return `<li class="capture-switch is-${cls}" data-capture="${esc(key)}"><span>${esc(label)}</span><strong>${esc(text)}</strong></li>`;
    }).join("");
    const note = s ? "" : `<p class="muted small">This collector did not report its capture settings. Update it to the current version to see them.</p>`;
    return `<div class="capture-source" data-capture-source="${esc(r.source)}">
        <div class="capture-source-head"><strong>${esc(CAPTURE_SOURCES[r.source])}</strong><span class="muted small">${esc(when)}${esc(folders)}</span></div>
        <ul class="capture-switches" aria-label="${esc(CAPTURE_SOURCES[r.source])} capture settings">${chips}</ul>${note}
      </div>`;
  }).join("");
  return `<h4 class="host-subhead">Capture settings</h4><div class="capture-settings">${rows}</div>`;
}

function renderHosts(hosts) {
  const el = document.getElementById("hosts-list");
  if (!hosts.length) {
    el.innerHTML = `<div class="muted small">No hosts reporting for this organization yet. Use <a href="#enrollment">Install &amp; enroll</a> to connect your first Linux, macOS, or Windows machine.</div>`;
    return;
  }
  const expanded = new Set(Array.from(el.querySelectorAll("details[data-inventory][open]"), (d) => d.dataset.inventory));
  const focused = el.contains(document.activeElement) ? document.activeElement.closest("[data-inventory]")?.dataset.inventory : null;
  el.innerHTML = hosts
    .map((h) => {
      const memTotal = Number(h.mem_total_mb) || 0;
      const memUsed = Number(h.mem_used_mb) || 0;
      const memPct = memTotal > 0 ? Math.min(100, Math.max(0, Math.round((memUsed / memTotal) * 100))) : 0;
      const cpuCount = Math.max(1, Number(h.cpu_count) || 1);
      const load1m = Number(h.load_1m) || 0;
      const loadPct = Math.min(100, Math.max(0, Math.round((load1m / cpuCount) * 100)));
      const memTone = memPct >= 88 ? "crit" : memPct >= 72 ? "warn" : "ok";
      const loadTone = loadPct >= 90 ? "crit" : loadPct >= 70 ? "warn" : "ok";
      const harnessesHtml = (h.harnesses || []).map((hr) => renderRuntimeEvidence(h, hr, expanded)).join("");
      const topProcs = (h.processes || []).slice(0, 6);
      const procsHtml = topProcs.length
        ? `<table class="proc-table">
            <thead><tr><th>Harness</th><th>Process</th><th>PID</th><th>CPU%</th><th>RSS</th></tr></thead>
            <tbody>
              ${topProcs
                .map(
                  (p) => `<tr>
                    <td>${esc(p.harness)}</td>
                    <td>${esc(p.comm)}</td>
                    <td>${esc(p.pid)}</td>
                    <td>${esc(p.cpu_pct)}%</td>
                    <td>${esc(p.rss_mb)} MB</td>
                  </tr>`
                )
                .join("")}
            </tbody>
          </table>`
        : `<div class="muted small">No active harness processes running right now.</div>`;

      return `
        <div class="host-card">
          <div class="card-head compact">
            <div>
              <strong>${esc(h.hostname)}</strong>${h.hostname !== h.host_id ? ` <small>(${esc(h.host_id)})</small>` : ""}
              <span class="muted small">(${esc(h.os_name)}/${esc(h.arch)})</span>
            </div>
            <span class="pill ${safeClass(h.status, "waiting")}">${esc(h.status)}</span>
          </div>
          <div class="host-meters" aria-label="Host resource utilization">
            <div class="meter-row">
              <div class="meter-head"><span>RAM</span><strong>${Math.round(memUsed)} / ${Math.round(memTotal)} MB (${memPct}%)</strong></div>
              <div class="meter-bar"><div class="meter-fill ${memTone}" style="width:${memPct}%"></div></div>
            </div>
            <div class="meter-row">
              <div class="meter-head"><span>Load 1m (${esc(h.cpu_count)} CPU)</span><strong>${esc(h.load_1m)} (${loadPct}%)</strong></div>
              <div class="meter-bar"><div class="meter-fill ${loadTone}" style="width:${loadPct}%"></div></div>
            </div>
          </div>
          <div class="item-meta">
            Observer: ${esc(h.agent_rss_mb)} MB / ${esc(h.scan_duration_ms)} ms · Seen ${fmtAge(h.last_seen_at)}
          </div>
          ${renderCaptureSettings(h)}
          <h4 class="host-subhead">Runtime inventory</h4>
          <div class="runtime-inventory">${harnessesHtml || '<span class="muted small">No harnesses detected</span>'}</div>
          ${renderProcessFolders(h.processes || [])}
          ${procsHtml}
        </div>`;
    })
    .join("");
  if (focused) {
    const previous = Array.from(el.querySelectorAll("[data-inventory]")).find((d) => d.dataset.inventory === focused);
    previous?.querySelector("summary")?.focus({ preventScroll: true });
  }
}

function renderTokens(tokens) {
  const el = document.getElementById("tokens-list");
  if (!isAdmin()) {
    el.innerHTML = `<div class="muted small">Only organization admins can view or revoke tokens.</div>`;
    return;
  }
  if (!tokens.length) {
    el.innerHTML = `<div class="muted small">No tokens created for this organization yet.</div>`;
    return;
  }
  el.innerHTML = tokens
    .slice(0, 10)
    .map((t) => {
      const scope = String(t.scope || "ingest").toLowerCase();
      return `
      <div class="item-row">
        <div>
          <div class="item-title">
            ${esc(t.name)} <code class="small">${esc(t.token_prefix)}…</code>
            <span class="pill ${scope === "read" ? "info" : "neutral"}">${esc(scope)}</span>
            ${
              scope === "read"
                ? ""
                : t.bound_host_id
                  ? `<span class="pill bound" title="Token bound to host">host: <code>${esc(t.bound_host_id)}</code></span>`
                  : `<span class="pill unbound" title="Binds to first host on ingest">unbound</span>`
            }
          </div>
          <div class="item-meta">
            Created by ${esc(t.created_by)} · Last used: ${t.last_used_at ? fmtAge(t.last_used_at) : "never"}
            ${t.revoked_at ? " · REVOKED" : ""}
          </div>
        </div>
        ${t.revoked_at ? "" : `<button class="btn small danger" data-revoke="${esc(t.id)}">Revoke</button>`}
      </div>`;
    })
    .join("");
  el.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/v1/tokens/${encodeURIComponent(btn.dataset.revoke)}`, { method: "DELETE" });
        sessionState.lastCreatedToken = null;
        document.getElementById("install-output")?.classList.add("hidden");
        const cmdEl = document.getElementById("install-cmd");
        if (cmdEl) cmdEl.textContent = "";
        showToast("Token revoked.");
        loadAll();
      } catch (err) {
        if (err.status === 401) showLogin();
        else showError(tokenError, err.message);
      }
    });
  });
}

function renderMembers(members) {
  const el = document.getElementById("members-list");
  if (!el) return;
  if (!members.length) {
    el.innerHTML = `<div class="muted small">No members listed.</div>`;
    return;
  }
  const meId = sessionState.user?.id;
  el.innerHTML = members
    .map(
      (m) => `
      <div class="item-row">
        <div>
          <div class="item-title">${esc(m.username)} ${m.id === meId ? '<span class="pill healthy">You</span>' : ""}</div>
          <div class="item-meta">Role: <strong>${esc(m.role)}</strong></div>
        </div>
        <div class="member-actions">
          <label class="sr-only" for="role-${esc(m.id)}">Role for ${esc(m.username)}</label>
          <select id="role-${esc(m.id)}" class="select" data-member-role="${esc(m.id)}">
            ${["admin", "operator", "viewer"]
              .map((r) => `<option value="${r}"${m.role === r ? " selected" : ""}>${r}</option>`)
              .join("")}
          </select>
          <button type="button" class="btn small danger" data-remove-member="${esc(m.id)}">Remove</button>
        </div>
      </div>`
    )
    .join("");

  const membersError = document.getElementById("members-error");
  el.querySelectorAll("[data-member-role]").forEach((sel) => {
    sel.addEventListener("change", async () => {
      showError(membersError, "");
      try {
        await api(`/api/v1/members/${encodeURIComponent(sel.dataset.memberRole)}/role`, {
          method: "POST",
          body: JSON.stringify({ role: sel.value }),
        });
        showToast("Member role updated.");
        checkAuth();
      } catch (err) {
        if (err.status === 401) showLogin();
        else showError(membersError, err.message || "Failed to update role");
        loadAll();
      }
    });
  });
  el.querySelectorAll("[data-remove-member]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      showError(membersError, "");
      try {
        await api(`/api/v1/members/${encodeURIComponent(btn.dataset.removeMember)}`, { method: "DELETE" });
        showToast("Member removed from organization.");
        loadAll();
      } catch (err) {
        if (err.status === 401) showLogin();
        else showError(membersError, err.message || "Could not remove member");
      }
    });
  });
}

function renderInvitations(invitations) {
  const el = document.getElementById("invitations-list");
  if (!el) return;
  if (!invitations.length) {
    el.innerHTML = `<div class="muted small">No invitations created yet.</div>`;
    return;
  }
  const now = Date.now() / 1000;
  el.innerHTML = invitations
    .slice(0, 10)
    .map((inv) => {
      const stateLabel = inv.revoked_at
        ? "revoked"
        : inv.accepted_at
          ? "accepted"
          : inv.expires_at && inv.expires_at < now
            ? "expired"
            : "pending";
      const pillCls = stateLabel === "accepted" ? "healthy" : stateLabel === "pending" ? "info" : "waiting";
      const canRevoke = stateLabel === "pending";
      return `
      <div class="item-row">
        <div>
          <div class="item-title">
            ${esc(inv.username)} <span class="pill neutral">${esc(inv.role)}</span>
            <span class="pill ${pillCls}">${esc(stateLabel)}</span>
          </div>
          <div class="item-meta">
            Expires: ${inv.expires_at ? esc(new Date(inv.expires_at * 1000).toLocaleString()) : "—"}
          </div>
        </div>
        ${canRevoke ? `<button type="button" class="btn small danger" data-revoke-invite="${esc(inv.id)}">Revoke</button>` : ""}
      </div>`;
    })
    .join("");

  const inviteErr = document.getElementById("invite-create-error");
  el.querySelectorAll("[data-revoke-invite]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      showError(inviteErr, "");
      try {
        await api(`/api/v1/invitations/${encodeURIComponent(btn.dataset.revokeInvite)}`, { method: "DELETE" });
        showToast("Invitation revoked.");
        loadAll();
      } catch (err) {
        if (err.status === 401) showLogin();
        else showError(inviteErr, err.message || "Failed to revoke invitation");
      }
    });
  });
}

function renderSecurityPanel() {
  const enabled = Boolean(sessionState.user?.mfa_enabled);
  const badge = document.getElementById("mfa-status-badge");
  const setupSec = document.getElementById("mfa-setup-section");
  const disableSec = document.getElementById("mfa-disable-section");
  if (badge) {
    badge.textContent = enabled ? "2FA ENABLED" : "2FA OFF";
    badge.className = `pill ${enabled ? "healthy" : "waiting"}`;
  }
  if (setupSec) setupSec.classList.toggle("hidden", enabled);
  if (disableSec) disableSec.classList.toggle("hidden", !enabled);
}

function renderTaskLinkStrip(taskId, linkObj) {
  const tid = String(taskId || "").trim();
  if (!tid) {
    return `<div class="link-strip is-unknown" data-link-status="unknown" data-link-basis="none">
      <span class="pill waiting">Link unknown</span>
      <span class="muted small">No task identifier recorded for this item.</span>
    </div>`;
  }
  const link = linkObj && typeof linkObj === "object" ? linkObj : null;
  if (!link || link.status !== "linked") {
    const basis = String(link?.basis || "none");
    const reason = String(link?.reason || "No explicit session or step link recorded for this assignment.");
    const recSess = link?.session_id ? ` <span class="link-meta-code">Session: <code>${esc(link.session_id)}</code></span>` : "";
    return `<div class="link-strip is-unknown" data-link-status="unknown" data-link-basis="${esc(basis)}" data-link-task="${esc(tid)}">
      <span class="pill waiting">Link unknown</span>
      <span class="muted small">${esc(reason)}${recSess}</span>
    </div>`;
  }
  const sid = String(link.session_id || "");
  const lastStep = link.last_step && typeof link.last_step === "object" ? link.last_step : null;
  const stepHref = buildLiveLink({
    task: tid,
    session: sid,
    host: link.host_id,
    agent: link.agent,
    runtime: link.runtime,
    event: lastStep?.key || "",
  });
  const confFile = String(link.confirmed_file || "");
  const fileHref = confFile
    ? buildLiveLink({
        task: tid,
        session: sid,
        host: link.host_id,
        agent: link.agent,
        runtime: link.runtime,
        file: confFile,
        event: link.confirmed_file_event_id ? `event:${link.confirmed_file_event_id}` : lastStep?.key || "",
      })
    : "";
  const basisLabel = link.basis === "explicit_task_id" ? "Explicit task_id" : "Orchestrator turn";
  const stepLabel = lastStep?.message ? (lastStep.message.length > 52 ? lastStep.message.slice(0, 51) + "…" : lastStep.message) : `${link.step_count} step(s)`;
  return `<div class="link-strip is-linked" data-link-status="linked" data-link-basis="${esc(link.basis)}" data-link-task="${esc(tid)}">
    <span class="pill healthy" title="${esc(link.reason || basisLabel)}">Linked · ${esc(basisLabel)}</span>
    ${sid ? `<button type="button" class="link-hop-btn" data-open-session="${esc(sid)}" data-from-task="${esc(tid)}" title="Open linked session in Activity map">Session: <code>${esc(sid)}</code> ↗</button>` : ""}
    ${lastStep ? `<a href="${esc(stepHref)}" class="link-hop-btn" data-hop="step" title="Open latest linked step in Live NOC">Last step: ${esc(stepLabel)} ↗</a>` : ""}
    ${
      confFile
        ? `<a href="${esc(fileHref)}" class="link-hop-btn is-file" data-hop="file" title="Open confirmed file edit in Live NOC">Confirmed file: <code>${esc(confFile)}</code> ↗</a>`
        : `<span class="link-none-chip" data-confirmed-file="none">Confirmed file: None recorded</span>`
    }
  </div>`;
}

function renderWorkReports(reports, expanded) {
  const stages = { plan: "Planned", task_plan: "Planned", work_started: "Started", work_done: "Finished" };
  const groups = new Map();
  for (const report of reports) {
    if (!Object.hasOwn(stages, report.event_type)) continue;
    const task = report.metadata?.task_id;
    const key = JSON.stringify([report.host_id, report.harness, report.agent_name, task || null, task ? null : report.id]);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(report);
  }
  if (!groups.size) return '<p class="muted small">No agent has reported a plan, a start, or a finished result for this organization yet.</p>';
  const byTask = sessionState.links?.by_task || {};
  const cards = Array.from(groups, ([key, entries]) => {
    const latest = entries[0];
    const name = latest.metadata?.task_id;
    const workspace = latest.metadata?.workspace;
    const commonFolder = workspace && entries.every((e) => e.metadata?.workspace === workspace);
    const isFocused = Boolean(name && sessionState.focusedTaskId && name === sessionState.focusedTaskId);
    const history = entries
      .slice()
      .reverse()
      .map((r) => {
        const meta = r.metadata || {};
        const files = Array.isArray(meta.files) ? meta.files.filter((f) => typeof f === "string" && f) : [];
        return `<li class="step-${safeClass(r.event_type)}"><strong>${esc(stages[r.event_type])}</strong> · <time>${esc(new Date(r.created_at * 1000).toLocaleString())}</time>
        <p>${esc(r.message)}</p>
        ${meta.workspace && !commonFolder ? `<div>Workspace · <code>${esc(meta.workspace)}</code></div>` : ""}
        ${meta.method ? `<div>Method · ${esc(meta.method)}</div>` : ""}
        ${files.length ? `<div class="step-files">Reported files<ul>${files.map((f) => `<li><code>${esc(f)}</code></li>`).join("")}</ul></div>` : ""}</li>`;
      })
      .join("");
    const linkStrip = renderTaskLinkStrip(name, name ? byTask[name] : null);
    return `<div class="report-card${isFocused ? " is-linked-target" : ""}"${name ? ` data-task-id="${esc(name)}"` : ""}>
      <details class="report-disclosure" data-report="${esc(key)}"${expanded.has(key) || isFocused ? " open" : ""}><summary>
      <strong>${esc(latest.agent_name)}</strong> · ${esc(latest.harness)} · ${esc(latest.host_id)}
      <span class="pill ${latest.event_type === "work_done" ? "acked" : "info"}">${esc(stages[latest.event_type])}</span>
      <span class="report-summary">${esc(latest.message)}</span>
      <span class="muted small">${name ? esc(name) + " · " : ""}${entries.length} report${entries.length === 1 ? "" : "s"} · ${esc(fmtAge(latest.created_at))}</span>
      </summary>${commonFolder ? `<div class="report-folder">Workspace · <code>${esc(workspace)}</code></div>` : ""}<ol class="report-steps">${history}</ol></details>
      ${linkStrip}
    </div>`;
  });
  return '<div class="report-grid">' + cards.join("") + "</div>";
}

function renderWorkspaceActivity(board, expanded) {
  const workspace = board.workspace_activity;
  if (!workspace && (!board.files || !board.files.length)) return "";
  const date = (ts) => esc(new Date(ts * 1000).toLocaleString());
  const projectName = board.project || sessionState.organization?.name || "Workspace";
  const prefix = `<h3>Project workspace · ${esc(projectName)}</h3>`;
  if (!workspace) {
    return prefix + "<ul>" + (board.files || []).map((f) => `<li><code>${esc(f.path)}</code> · ${date(f.modified)}</li>`).join("") + "</ul>";
  }
  const folders = (workspace.folders || [])
    .map(
      (folder) => `<details class="runtime-proof" data-folder="${esc(folder.path)}"${expanded.has(folder.path) ? " open" : ""}>
    <summary><strong>${esc(folder.path)}/</strong> <span class="muted small">· ${esc(folder.total)} file${folder.total === 1 ? "" : "s"}</span></summary>
    <ul>${(folder.recent || []).map((f) => `<li><code>${esc(f.path.split("/").pop())}</code> · ${date(f.modified)}</li>`).join("")}</ul></details>`
    )
    .join("");
  const verbs = { appeared: "Appeared", updated: "Metadata changed", missing: "No longer present" };
  const changes = (workspace.changes || [])
    .map((f) => `<li><strong>${esc(verbs[f.change] || f.change)}</strong> · <code>${esc(f.path)}</code> · ${date(f.observed)}</li>`)
    .join("");
  return (
    prefix +
    `<p class="muted small">Open a source folder for its latest file timestamps. File metadata alone cannot identify an editor.</p>
    <div class="report-grid">${folders || '<span class="muted small">No local workspace files configured for this organization.</span>'}</div>
    <h4>Changes between dashboard samples</h4><p class="muted small">First sample · ${date(workspace.since)}. A server restart begins a new window.</p>
    ${changes ? "<ul>" + changes + "</ul>" : '<p class="muted small">No changes observed between samples yet.</p>'}
    ${(workspace.unavailable || []).length ? '<p class="muted small">Unavailable folders · ' + esc(workspace.unavailable.join(", ")) + "</p>" : ""}`
  );
}

function fmtUnixTime(ts) {
  const n = Number(ts);
  if (!Number.isFinite(n) || n <= 0) return "";
  const dt = new Date(n * 1000);
  if (Number.isNaN(dt.getTime())) return "";
  const hhmm = dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return `<time class="collab-task-time" datetime="${esc(dt.toISOString())}" title="${esc(dt.toLocaleString())}">${esc(hhmm)} · ${esc(fmtAge(n))}</time>`;
}

function collabStatusMeta(raw) {
  const s = String(raw || "").trim().toLowerCase();
  if (["done", "completed", "finished", "succeeded", "ok"].includes(s)) {
    return { cls: "healthy", label: "Completed", done: true };
  }
  if (["running", "in_progress", "in-progress", "active", "working", "started"].includes(s)) {
    return { cls: "running", label: "In progress", done: false };
  }
  if (["failed", "error", "blocked", "cancelled", "canceled"].includes(s)) {
    return { cls: "critical", label: s.charAt(0).toUpperCase() + s.slice(1), done: false };
  }
  if (["queued", "pending", "planned", "waiting", "open"].includes(s)) {
    return { cls: "waiting", label: s.charAt(0).toUpperCase() + s.slice(1), done: false };
  }
  return { cls: "neutral", label: s ? s.replace(/[_-]+/g, " ") : "Recorded", done: false };
}

function buildCollaborationTree(tasks) {
  const list = Array.isArray(tasks) ? tasks.filter((t) => t && typeof t === "object") : [];
  const byId = new Map();
  list.forEach((t, idx) => {
    const key = t.id !== undefined && t.id !== null && String(t.id) !== "" ? String(t.id) : `task-${idx}`;
    byId.set(key, { ...t, _key: key, _children: [] });
  });

  const roots = [];
  for (const node of byId.values()) {
    const pid = node.parent_id !== undefined && node.parent_id !== null && String(node.parent_id) !== "" ? String(node.parent_id) : "";
    if (pid && pid !== node._key && byId.has(pid)) {
      byId.get(pid)._children.push(node);
    } else {
      roots.push(node);
    }
  }
  return { roots, byId, total: byId.size };
}

function renderCollaborationNode(node, parentNode, visited, depth) {
  if (visited.has(node._key)) return "";
  visited.add(node._key);

  const st = collabStatusMeta(node.status);
  const agent = String(node.agent || "").trim() || "Unassigned agent";
  const title = String(node.title || "").trim() || "Assigned task";
  const result = String(node.result || "").trim();
  const timeHtml = fmtUnixTime(node.updated_at);
  let relTag = "";
  if (parentNode) {
    const pLabel = String(parentNode.agent || parentNode.title || parentNode._key).slice(0, 40);
    relTag = `<span class="collab-rel" title="Subtask under ${esc(pLabel)}">↳ Subtask of ${esc(pLabel)}</span>`;
  } else if (node.parent_id) {
    relTag = `<span class="collab-rel">↳ Linked task</span>`;
  } else if (node._children.length > 0) {
    relTag = `<span class="collab-rel">Coordinator · ${node._children.length} subtask${node._children.length === 1 ? "" : "s"}</span>`;
  }

  const linkObj = sessionState.links?.by_task?.[node._key] || null;
  const linkHtml = renderTaskLinkStrip(node._key, linkObj);
  const isFocused = Boolean(sessionState.focusedTaskId && sessionState.focusedTaskId === node._key);

  const childrenHtml = node._children
    .map((child) => renderCollaborationNode(child, node, visited, Math.min(depth + 1, 4)))
    .filter(Boolean)
    .join("");

  return `<li class="collab-task-node" data-task-id="${esc(node._key)}" data-depth="${depth}">
    <div class="collab-task-card${isFocused ? " is-linked-target" : ""}">
      <div class="collab-task-head">
        <div class="collab-task-who">
          <span class="collab-task-agent">${esc(agent)}</span>
          <span class="pill ${safeClass(st.cls, "neutral")}">${esc(st.label)}</span>
          ${relTag}
        </div>
        ${timeHtml || '<span class="collab-task-time">Time not recorded</span>'}
      </div>
      <p class="collab-task-title">${esc(title)}</p>
      ${linkHtml}
      ${
        result
          ? `<div class="collab-result"><span class="collab-result-lbl">Latest recorded result</span><p>${esc(result)}</p></div>`
          : '<p class="muted small collab-no-result">No result recorded yet.</p>'
      }
    </div>
    ${childrenHtml ? `<ol class="collab-children" aria-label="Subtasks of ${esc(agent)}">${childrenHtml}</ol>` : ""}
  </li>`;
}

function renderCollaboration(collaboration, expandedChanges, initialized) {
  const changes = Array.isArray(collaboration?.changes)
    ? collaboration.changes.filter((c) => c && typeof c === "object")
    : [];
  const header = `<div class="collab-head">
    <h3 id="collab-heading">Collaboration by change</h3>
    <span class="muted small">Goal, assigned agents, task relationships, status, and latest recorded result</span>
  </div>`;

  if (!changes.length) {
    return `<section class="collab-section" aria-labelledby="collab-heading">
      ${header}
      <div class="notice-box collab-empty" data-collab-empty="1">
        <p class="small"><strong>No collaborative changes recorded for this organization yet.</strong></p>
        <p class="muted small">Multi-agent work coordinated in this organization appears here automatically when configured—no GitHub integration required.</p>
      </div>
    </section>`;
  }

  const cards = changes
    .map((ch, idx) => {
      const cid = ch.id !== undefined && ch.id !== null && String(ch.id) !== "" ? String(ch.id) : `change-${idx}`;
      const title = String(ch.title || "").trim() || "Untitled change";
      const st = collabStatusMeta(ch.status);
      const { roots, byId, total } = buildCollaborationTree(ch.tasks);
      const allTasks = Array.from(byId.values());
      const doneCount = allTasks.filter((t) => collabStatusMeta(t.status).done).length;
      const agents = [...new Set(allTasks.map((t) => String(t.agent || "").trim()).filter(Boolean))];
      const timeHtml = fmtUnixTime(ch.updated_at);
      const containsFocused = Boolean(sessionState.focusedTaskId && byId.has(sessionState.focusedTaskId));
      const isOpen = containsFocused || (initialized ? expandedChanges.has(cid) : idx === 0);

      // Optional future repository / PR metadata (omitted cleanly when absent)
      const extMeta = [];
      if (ch.repo) extMeta.push(`<span class="pill neutral">${esc(ch.repo)}</span>`);
      if (ch.pr) extMeta.push(`<span class="pill info">PR ${esc(ch.pr)}</span>`);

      const visited = new Set();
      let treeHtml = roots.map((r) => renderCollaborationNode(r, null, visited, 0)).join("");
      // Render any cyclic tasks that were not reached from roots
      for (const node of allTasks) {
        if (!visited.has(node._key)) {
          treeHtml += renderCollaborationNode(node, null, visited, 0);
        }
      }

      const agentsHtml = agents.length
        ? `<div class="collab-agents" aria-label="Participating agents">${agents.map((a) => `<span class="collab-agent-chip">${esc(a)}</span>`).join("")}</div>`
        : "";

      return `<details class="collab-change status-${safeClass(ch.status, "neutral")}" data-change-id="${esc(cid)}"${isOpen ? " open" : ""}>
        <summary>
          <div class="collab-summary-top">
            <div class="collab-title-wrap">
              <span class="collab-caret" aria-hidden="true">▸</span>
              <span class="collab-title">${esc(title)}</span>
              <span class="pill ${safeClass(st.cls, "neutral")}">${esc(st.label)}</span>
              ${extMeta.join("")}
            </div>
            ${timeHtml}
          </div>
          <div class="collab-summary-meta">
            <span>${total ? `${doneCount}/${total} task${total === 1 ? "" : "s"} completed` : "No tasks linked yet"}</span>
            ${agents.length ? `<span>· ${agents.length} agent${agents.length === 1 ? "" : "s"}</span>` : ""}
          </div>
          ${agentsHtml}
        </summary>
        <div class="collab-body">
          ${
            treeHtml
              ? `<ol class="collab-tree" aria-label="Tasks for ${esc(title)}">${treeHtml}</ol>`
              : '<p class="muted small">No individual agent tasks recorded for this change yet.</p>'
          }
        </div>
      </details>`;
    })
    .join("");

  return `<section class="collab-section" aria-labelledby="collab-heading">
    ${header}
    <div class="collab-list">${cards}</div>
  </section>`;
}

async function loadWorkBoard(events) {
  const request = ++workBoardRequest;
  const el = document.getElementById("work-board");
  if (!el) return;
  try {
    const board = await api("/api/v1/work-board?missions=1" + (appView.dataset.includeActivity ? "&include=activity" : ""));
    if (request !== workBoardRequest || appView.classList.contains("hidden")) return;
    sessionState.links = board.links && typeof board.links === "object" ? board.links : { version: "1", by_task: {}, by_session: {} };
    const preview = document.getElementById("mission-preview");
    if (preview) {
      preview.replaceChildren(...(board.missions || []).slice(0, 3).map(mission => {
        const event = mission.events[0];
        const row = document.createElement("p");
        const link = document.createElement("a");
        link.href = "/missions?" + new URLSearchParams({mission: mission.source + "/" + mission.id});
        link.textContent = mission.title;
        row.append(link, " · ", event.agent, event.to ? " → " + event.to : "", " · ", event.text || event.kind);
        return row;
      }));
    }
    const urlTask = new URLSearchParams(window.location.search).get("task") || "";
    if (urlTask && !sessionState.focusedTaskId) sessionState.focusedTaskId = urlTask;
    renderReturnBanner();
    const expandedReports = new Set(Array.from(el.querySelectorAll("[data-report][open]"), (d) => d.dataset.report));
    const expandedFolders = new Set(Array.from(el.querySelectorAll("[data-folder][open]"), (d) => d.dataset.folder));
    const expandedChanges = new Set(Array.from(el.querySelectorAll("[data-change-id][open]"), (d) => d.dataset.changeId));
    const collabHtml = renderCollaboration(board.collaboration, expandedChanges, sessionState.collabInitialized);
    sessionState.collabInitialized = true;

    const reports = board.reports || events.filter((e) => ["plan", "task_plan", "work_started", "work_done"].includes(e.event_type));
    document.dispatchEvent(new CustomEvent("agent-reports", { detail: { reports, activity: board.activity, links: sessionState.links } }));

    const runtimes = Array.isArray(board.runtimes) ? board.runtimes : [];
    const runtimeSection = runtimes.length
      ? `<h3>Detected runtimes</h3><div class="harness-tags">${runtimes
          .map(
            (r) =>
              `<details class="host-card"><summary><strong>${esc(r.name)}</strong>${r.version ? ` · ${esc(r.version)}` : ""}</summary><code>${esc(r.binary || r.source || "")}</code></details>`
          )
          .join("")}</div>`
      : "";

    el.innerHTML = `${collabHtml}
      <h3>Tasks and plans reported by agents</h3>
      <p class="muted small">Open a report to see its timeline, method, and files.</p>${renderWorkReports(reports, expandedReports)}
      ${runtimeSection}
      <p class="muted small">Live sessions across enrolled hosts (what each agent did, plans, steps, and files) appear in <a href="#activity">Activity map</a>.</p>
      ${renderWorkspaceActivity(board, expandedFolders)}`;

    el.querySelectorAll("[data-open-session]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const sid = btn.dataset.openSession || "";
        const tid = btn.dataset.fromTask || "";
        if (!sid) return;
        document.dispatchEvent(new CustomEvent("swarm-open-session", { detail: { sessionId: sid, fromTaskId: tid } }));
        document.getElementById("activity")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });

    el.querySelectorAll('a.link-hop-btn[href^="/live"]').forEach((anchor) => {
      const syncReturnHref = () => {
        try {
          const u = new URL(anchor.getAttribute("href"), window.location.origin);
          u.searchParams.set("from", currentHomeReturnUrl("#agent-work"));
          anchor.setAttribute("href", u.pathname + u.search + u.hash);
        } catch {}
      };
      anchor.addEventListener("pointerdown", syncReturnHref);
      anchor.addEventListener("click", syncReturnHref);
    });

    if (sessionState.focusedTaskId && !sessionState.taskFocusApplied) {
      const targetEl = el.querySelector(`[data-task-id="${CSS.escape(sessionState.focusedTaskId)}"]`);
      if (targetEl) {
        sessionState.taskFocusApplied = true;
        targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }
  } catch (err) {
    if (request !== workBoardRequest || appView.classList.contains("hidden")) return;
    if (err.status === 401) {
      showLogin();
      return;
    }
    document.dispatchEvent(new CustomEvent("agent-reports", { detail: { reports: events } }));
    el.innerHTML = renderCollaboration(null, new Set(), false) + "<h3>Recent agent reports</h3>" + renderWorkReports(events, new Set());
  }
}

function renderEvents(events) {
  const el = document.getElementById("events-list");
  if (!events.length) {
    el.innerHTML = `<div class="muted small">No agent events ingested for this organization yet.</div>`;
    return;
  }
  el.innerHTML = events
    .slice(0, 12)
    .map(
      (e) => `
      <div class="item-row">
        <div>
          <div class="item-title">
            <span class="pill ${safeClass(e.severity, "info")}">${esc(e.event_type)}</span>
            ${esc(e.harness)} / ${esc(e.agent_name)}
          </div>
          <div class="item-meta">${esc(e.message)}</div>
          <div class="item-meta">Host: ${esc(e.host_id)} · ${fmtAge(e.created_at)}</div>
        </div>
      </div>`
    )
    .join("");
}

function renderAudit(audit) {
  const el = document.getElementById("audit-list");
  if (!isAdmin()) {
    el.innerHTML = `<div class="muted small">Audit trail entries are restricted to organization admins.</div>`;
    return;
  }
  if (!audit.length) {
    el.innerHTML = `<div class="muted small">No audit entries yet.</div>`;
    return;
  }
  el.innerHTML = audit
    .slice(0, 12)
    .map(
      (a) => `
      <div class="item-row">
        <div>
          <div class="item-title">${esc(a.action)} <span class="muted small">by ${esc(a.actor)}</span></div>
          <div class="item-meta">${esc(a.detail)} · ${fmtAge(a.created_at)}</div>
        </div>
      </div>`
    )
    .join("");
}

/* ---------- Event Listeners ---------- */
document.querySelectorAll("[data-auth-tab]").forEach((btn) => {
  btn.addEventListener("click", () => switchAuthTab(btn.dataset.authTab));
});

loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  showError(loginError, "");
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const otpInput = document.getElementById("login-otp");
  const otpGroup = document.getElementById("login-otp-group");
  const otp = otpInput ? otpInput.value.trim() : "";
  const body = otp ? { username, password, otp } : { username, password };
  try {
    const res = await api("/api/v1/auth/login", { method: "POST", body: JSON.stringify(body) });
    if (otpInput) otpInput.value = "";
    if (otpGroup) otpGroup.classList.add("hidden");
    showApp(res, true);
  } catch (err) {
    if (err.status === 401 && err.data && err.data.code === "mfa_required") {
      if (otpGroup) otpGroup.classList.remove("hidden");
      showError(loginError, "Two-factor authentication is enabled on this account. Enter your 6-digit code to continue.");
      otpInput?.focus();
      return;
    }
    if (err.status === 429) {
      const waitSec = err.retryAfter;
      showError(loginError, waitSec ? `Too many login attempts. Please wait ${waitSec}s.` : err.message || "Too many login attempts.");
    } else {
      showError(loginError, err.message || "Sign in failed");
    }
  }
});

if (registerForm) {
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showError(registerError, "");
    const organization = document.getElementById("reg-org").value.trim();
    const username = document.getElementById("reg-username").value.trim();
    const password = document.getElementById("reg-password").value;
    try {
      const res = await api("/api/v1/auth/register", {
        method: "POST",
        body: JSON.stringify({ organization, username, password }),
      });
      registerForm.reset();
      showApp(res, true);
      showToast(`Organization "${res.organization?.name || organization}" created.`);
    } catch (err) {
      showError(registerError, err.message || "Registration failed");
    }
  });
}

if (inviteAcceptForm) {
  inviteAcceptForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showError(inviteAcceptError, "");
    const token = document.getElementById("inv-token").value.trim();
    const username = document.getElementById("inv-username").value.trim();
    const password = document.getElementById("inv-password").value;
    const otpInput = document.getElementById("inv-otp");
    const otpGroup = document.getElementById("invite-otp-group");
    const otp = otpInput ? otpInput.value.trim() : "";
    const body = otp ? { token, username, password, otp } : { token, username, password };
    try {
      const res = await api("/api/v1/auth/accept-invitation", {
        method: "POST",
        body: JSON.stringify(body),
      });
      inviteAcceptForm.reset();
      if (otpGroup) otpGroup.classList.add("hidden");
      showApp(res, true);
      showToast(`Joined "${res.organization?.name || "organization"}".`);
    } catch (err) {
      if (err.status === 401 && err.data && err.data.code === "mfa_required") {
        if (otpGroup) otpGroup.classList.remove("hidden");
        showError(inviteAcceptError, "This existing account has 2FA enabled. Enter your 6-digit authenticator code.");
        otpInput?.focus();
        return;
      }
      showError(inviteAcceptError, err.message || "Could not accept invitation");
    }
  });
}

if (orgSwitcher) {
  orgSwitcher.addEventListener("change", async () => {
    const orgId = orgSwitcher.value;
    if (!orgId || orgId === sessionState.organization?.id) return;
    try {
      const res = await api("/api/v1/auth/switch", {
        method: "POST",
        body: JSON.stringify({ organization_id: orgId }),
      });
      sessionState.lastCreatedToken = null;
      document.getElementById("install-output")?.classList.add("hidden");
      document.getElementById("invite-created-box")?.classList.add("hidden");
      showApp(res, true);
      showToast(`Switched to ${res.organization?.name || "organization"}.`);
    } catch (err) {
      if (err.status === 401) showLogin();
      else showToast(err.message || "Could not switch organization.");
    }
  });
}

document.getElementById("logout-btn").addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST", body: "{}" }).catch(() => {});
  showLogin("signin");
});

document.getElementById("refresh-btn").addEventListener("click", loadAll);
alertFilter.addEventListener("change", loadAll);

document.getElementById("dismiss-onboarding-btn")?.addEventListener("click", () => {
  const orgId = sessionState.organization?.id || "default";
  sessionState.dismissedOnboardingOrgs.add(orgId);
  document.getElementById("onboarding-banner")?.classList.add("hidden");
});

/* ---------- Enrollment & Multi-platform Installer ---------- */
const tokenScopeSelect = document.getElementById("token-scope");
const activityRootsWrap = document.getElementById("activity-roots-wrap");
if (tokenScopeSelect && activityRootsWrap) {
  tokenScopeSelect.addEventListener("change", () => {
    activityRootsWrap.classList.toggle("hidden", tokenScopeSelect.value === "read");
  });
}

document.getElementById("token-activity-roots")?.addEventListener("input", () => {
  if (sessionState.lastCreatedToken) renderInstallOutput();
});

document.querySelectorAll("[data-platform]").forEach((btn) => {
  btn.addEventListener("click", () => {
    sessionState.installPlatform = btn.dataset.platform;
    document.querySelectorAll("[data-platform]").forEach((b) => {
      const active = b.dataset.platform === sessionState.installPlatform;
      b.classList.toggle("active", active);
      b.setAttribute("aria-selected", active ? "true" : "false");
    });
    renderInstallOutput();
  });
});

document.getElementById("token-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showError(tokenError, "");
  const nameInput = document.getElementById("token-name");
  const name = nameInput.value.trim();
  const scope = tokenScopeSelect ? tokenScopeSelect.value : "ingest";
  if (!name) return;
  try {
    const created = await api("/api/v1/tokens", {
      method: "POST",
      body: JSON.stringify({ name, scope }),
    });
    nameInput.value = "";
    sessionState.lastCreatedToken = { ...created, scope: created.scope || scope };
    renderInstallOutput();
    showToast(`Created ${scope} token "${name}".`);
    loadAll();
  } catch (err) {
    if (err.status === 401) {
      showLogin();
      return;
    }
    showError(tokenError, err.message || "Failed to create token");
  }
});

async function copyText(text, btn, idleLabel) {
  try {
    await navigator.clipboard?.writeText(text);
    btn.textContent = "Copied ✓";
    btn.classList.add("copied");
    setTimeout(() => {
      btn.textContent = idleLabel;
      btn.classList.remove("copied");
    }, 1400);
  } catch (_) {}
}

document.getElementById("copy-cmd-btn").addEventListener("click", () => {
  const btn = document.getElementById("copy-cmd-btn");
  const cmd = document.getElementById("install-cmd").textContent;
  copyText(cmd, btn, "Copy");
});

/* ---------- Invitations ---------- */
document.getElementById("invite-create-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const errEl = document.getElementById("invite-create-error");
  showError(errEl, "");
  const userIn = document.getElementById("invite-username");
  const roleIn = document.getElementById("invite-role");
  const username = userIn.value.trim();
  const role = roleIn.value;
  if (!username) return;
  try {
    const created = await api("/api/v1/invitations", {
      method: "POST",
      body: JSON.stringify({ username, role }),
    });
    userIn.value = "";
    const base = String(sessionState.publicUrl || window.location.origin).replace(/\/+$/, "");
    const link = `${base}/#invite=${encodeURIComponent(created.token)}`;
    document.getElementById("invite-created-link").textContent = link;
    document.getElementById("invite-created-token").textContent = created.token;
    document.getElementById("invite-created-box").classList.remove("hidden");
    showToast(`Invitation created for ${username} (${role}).`);
    loadAll();
  } catch (err) {
    if (err.status === 401) showLogin();
    else showError(errEl, err.message || "Failed to create invitation");
  }
});

document.getElementById("copy-invite-btn")?.addEventListener("click", () => {
  const btn = document.getElementById("copy-invite-btn");
  const link = document.getElementById("invite-created-link").textContent;
  copyText(link, btn, "Copy link");
});

/* ---------- 2FA TOTP Setup / Confirm / Disable ---------- */
document.getElementById("mfa-start-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const mfaErr = document.getElementById("mfa-error");
  showError(mfaErr, "");
  const pwInput = document.getElementById("mfa-start-password");
  const password = pwInput.value;
  try {
    const res = await api("/api/v1/auth/2fa/setup", {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    mfaPendingPassword = password;
    document.getElementById("mfa-secret-code").textContent = res.secret || "";
    document.getElementById("mfa-otpauth-uri").textContent = res.otpauth_uri || "";
    document.getElementById("mfa-confirm-box").classList.remove("hidden");
    document.getElementById("mfa-confirm-otp")?.focus();
  } catch (err) {
    if (err.status === 401) showError(mfaErr, err.message || "Invalid password");
    else showError(mfaErr, err.message || "Could not start 2FA setup");
  }
});

document.getElementById("copy-mfa-secret-btn")?.addEventListener("click", () => {
  const btn = document.getElementById("copy-mfa-secret-btn");
  const sec = document.getElementById("mfa-secret-code").textContent;
  copyText(sec, btn, "Copy secret");
});

document.getElementById("mfa-confirm-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const mfaErr = document.getElementById("mfa-error");
  showError(mfaErr, "");
  const otp = document.getElementById("mfa-confirm-otp").value.trim();
  const password = mfaPendingPassword || document.getElementById("mfa-start-password").value;
  try {
    const res = await api("/api/v1/auth/2fa/confirm", {
      method: "POST",
      body: JSON.stringify({ password, otp }),
    });
    mfaPendingPassword = "";
    document.getElementById("mfa-start-form")?.reset();
    document.getElementById("mfa-confirm-form")?.reset();
    document.getElementById("mfa-confirm-box")?.classList.add("hidden");
    applySession(res);
    showToast("Two-factor authentication enabled.");
    loadAll();
  } catch (err) {
    showError(mfaErr, err.message || "Invalid verification code");
  }
});

document.getElementById("mfa-disable-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const mfaErr = document.getElementById("mfa-error");
  showError(mfaErr, "");
  const password = document.getElementById("mfa-disable-password").value;
  const otp = document.getElementById("mfa-disable-otp").value.trim();
  try {
    const res = await api("/api/v1/auth/2fa/disable", {
      method: "POST",
      body: JSON.stringify({ password, otp }),
    });
    document.getElementById("mfa-disable-form")?.reset();
    applySession(res);
    showToast("Two-factor authentication disabled.");
    loadAll();
  } catch (err) {
    showError(mfaErr, err.message || "Could not disable 2FA");
  }
});

/* ---------- Scroll-Spy Navigation & Quick Command Palette (Ctrl+K / Cmd+K) ---------- */
(function initScrollSpy() {
  const links = [...document.querySelectorAll('.section-nav a[href^="#"]')];
  if (!links.length || typeof IntersectionObserver === "undefined") return;
  const setActive = (id) => {
    links.forEach((a) => a.classList.toggle("is-active", a.getAttribute("href") === `#${id}`));
  };
  const targets = links.map((a) => document.getElementById(a.getAttribute("href").slice(1))).filter(Boolean);
  if (!targets.length) return;
  setActive(targets[0].id);
  const io = new IntersectionObserver(
    (entries) => {
      const visible = entries.filter((en) => en.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio);
      if (visible[0]) setActive(visible[0].target.id);
    },
    { rootMargin: "-15% 0px -65% 0px", threshold: [0.05, 0.25, 0.5] }
  );
  targets.forEach((t) => io.observe(t));
})();

function expandSectionFold(target) {
  if (!target) return;
  const fold = target.matches?.("details.section-fold")
    ? target
    : target.querySelector?.("details.section-fold") || target.closest?.("details.section-fold");
  if (fold) fold.open = true;
}

(function initSectionFolds() {
  const syncCue = (fold) => {
    const cue = fold.querySelector(".section-fold-cue");
    if (cue) cue.textContent = fold.open ? "Hide" : "Expand";
  };
  document.querySelectorAll("details.section-fold").forEach((fold) => {
    syncCue(fold);
    fold.addEventListener("toggle", () => syncCue(fold));
  });
  document.addEventListener("click", (e) => {
    const link = e.target.closest('a[href^="#"]');
    if (!link) return;
    const hash = link.getAttribute("href");
    if (!hash || hash === "#") return;
    const target = document.getElementById(hash.slice(1));
    if (target) expandSectionFold(target);
  });
  const openHashTarget = () => {
    const h = window.location.hash;
    if (h && h.length > 1 && !h.startsWith("#invite=")) {
      const target = document.getElementById(h.slice(1));
      if (target) expandSectionFold(target);
    }
  };
  window.addEventListener("hashchange", openHashTarget);
  openHashTarget();
})();

(function initCommandPalette() {
  const overlay = document.getElementById("cmdk-overlay");
  const input = document.getElementById("cmdk-input");
  const list = document.getElementById("cmdk-list");
  if (!overlay || !input || !list) return;
  let open = false;
  let activeIdx = 0;
  let items = [];

  const jumpTo = (hash) => {
    const target = document.querySelector(hash);
    if (target) {
      expandSectionFold(target);
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      if (history.replaceState) history.replaceState(null, "", hash);
    }
  };

  function getActions() {
    const actions = [
      { cat: "Live", label: "Open Full-Screen Live NOC Console", hint: "/live", run: () => { window.location.href = "/live"; } },
      { cat: "Section", label: "Fleet Overview & KPIs", hint: "#main-content", run: () => jumpTo("#main-content") },
      { cat: "Section", label: "Activity Map (Agent Sessions)", hint: "#activity", run: () => jumpTo("#activity") },
      { cat: "Section", label: "Guardrail Alerts", hint: "#alerts", run: () => jumpTo("#alerts") },
      { cat: "Section", label: "Install & Enroll a Host", hint: "#enrollment", run: () => jumpTo("#enrollment") },
      { cat: "Section", label: "Agent Work & Collaboration", hint: "#agent-work", run: () => jumpTo("#agent-work") },
      { cat: "Section", label: "Enrolled Hosts & Processes", hint: "#hosts", run: () => jumpTo("#hosts") },
      { cat: "Section", label: "Organization & Roles", hint: "#organization", run: () => jumpTo("#organization") },
      { cat: "Section", label: "Account & 2FA Security", hint: "#security", run: () => jumpTo("#security") },
      { cat: "Section", label: "Recent Events", hint: "#events", run: () => jumpTo("#events") },
      { cat: "Action", label: "Refresh Fleet Telemetry Now", hint: "Sync", run: () => { loadAll(); showToast("Fleet telemetry refreshed."); } },
    ];
    if (isAdmin()) {
      actions.push({ cat: "Section", label: "Audit Trail & SHA-256 Integrity", hint: "#audit", run: () => jumpTo("#audit") });
    }
    for (const m of sessionState.memberships || []) {
      if (m.id !== sessionState.organization?.id) {
        actions.push({
          cat: "Org",
          label: `Switch organization: ${m.name} (${m.role})`,
          hint: "Tenant",
          run: () => {
            if (orgSwitcher) {
              orgSwitcher.value = String(m.id);
              orgSwitcher.dispatchEvent(new Event("change"));
            }
          },
        });
      }
    }
    return actions;
  }

  function renderList() {
    const q = input.value.trim().toLowerCase();
    const all = getActions();
    items = q ? all.filter((it) => `${it.cat} ${it.label} ${it.hint}`.toLowerCase().includes(q)) : all;
    if (activeIdx >= items.length) activeIdx = 0;
    list.innerHTML = items.length
      ? items
          .map(
            (it, i) => `<li><button type="button" class="cmdk-item${i === activeIdx ? " active" : ""}" data-cmdk-idx="${i}">
              <span><span class="cmdk-cat">${esc(it.cat)}</span>${esc(it.label)}</span>
              <kbd>${esc(it.hint)}</kbd>
            </button></li>`
          )
          .join("")
      : '<li class="muted" style="padding:12px;text-align:center;">No matching section or action.</li>';
  }

  function openPalette() {
    if (appView.classList.contains("hidden")) return;
    open = true;
    activeIdx = 0;
    overlay.classList.remove("hidden");
    input.value = "";
    input.focus();
    renderList();
  }

  function closePalette() {
    open = false;
    overlay.classList.add("hidden");
  }

  document.getElementById("cmdk-btn")?.addEventListener("click", openPalette);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) { closePalette(); return; }
    const btn = e.target.closest("[data-cmdk-idx]");
    if (btn) {
      const it = items[Number(btn.dataset.cmdkIdx)];
      closePalette();
      if (it) it.run();
    }
  });
  input.addEventListener("input", () => { activeIdx = 0; renderList(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); closePalette(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); activeIdx = (activeIdx + 1) % Math.max(1, items.length); renderList(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); activeIdx = (activeIdx - 1 + Math.max(1, items.length)) % Math.max(1, items.length); renderList(); }
    else if (e.key === "Enter") {
      e.preventDefault();
      const it = items[activeIdx];
      closePalette();
      if (it) it.run();
    }
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (open) closePalette();
      else openPalette();
    } else if (open && e.key === "Escape") {
      e.preventDefault();
      closePalette();
    }
  });
})();

document.addEventListener("swarm-focus-task", (e) => {
  const tid = String(e.detail?.taskId || "").trim();
  if (!tid) return;
  sessionState.focusedTaskId = tid;
  sessionState.taskFocusApplied = false;
  const wb = document.getElementById("work-board");
  const target = wb?.querySelector(`[data-task-id="${CSS.escape(tid)}"]`);
  if (target) {
    const parentChange = target.closest("details.collab-change");
    if (parentChange) parentChange.open = true;
    if (target.tagName === "DETAILS") target.open = true;
    const innerDetails = target.querySelector("details.report-disclosure");
    if (innerDetails) innerDetails.open = true;
    wb.querySelectorAll(".is-linked-target").forEach((n) => n.classList.remove("is-linked-target"));
    (target.querySelector(".collab-task-card") || target).classList.add("is-linked-target");
    target.scrollIntoView({ behavior: "smooth", block: "center" });
    sessionState.taskFocusApplied = true;
  } else {
    loadAll();
  }
});

checkAuth();
