/* NeuroSwarm Needs Attention Dashboard Module
   - Displays explicit permission requests, failed test runs, and exhausted quotas
     with age, exact event links, and resolution history.
   - Displays heartbeat-stale hosts in a strictly separate "No signal" panel
     without inferring any cause from missing telemetry.
   - Zero inline handlers, zero external URLs (100% CSP-safe). */
(() => {
  "use strict";

  const root = document.getElementById("needs-attention-body");
  const statusPill = document.getElementById("na-status-pill");
  const app = document.getElementById("app-view");
  if (!root) return;

  const state = {
    data: null,
    filter: "all",
    resolvedOpen: false,
    expanded: false,
    busy: false,
    pending: null,
  };

  function esc(v) {
    return String(v ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function safeRelativeHref(raw) {
    const s = String(raw || "").trim();
    if (!s || !s.startsWith("/") || s.startsWith("//") || /[\r\n\0]/.test(s)) return "";
    return s;
  }

  function safeCatClass(raw) {
    const c = String(raw || "").toLowerCase().replace(/[^a-z0-9_]/g, "");
    return c || "info";
  }

  function categoryGlyph(kind) {
    const shapes = {
      permission: '<polygon class="na-glyph-cel" points="6,1.1 10.9,6 6,10.9 1.1,6"/><path d="M6 3.7v2.4M6 8.3h.01"/>',
      failed_test: '<rect class="na-glyph-cel" x="1.4" y="1.4" width="9.2" height="9.2" rx="2"/><path d="M4.1 4.1l3.8 3.8M7.9 4.1l-3.8 3.8"/>',
      quota_exhausted: '<rect class="na-glyph-cel" x="1.5" y="6.6" width="2.2" height="4" rx=".6"/><rect class="na-glyph-cel" x="4.9" y="4.2" width="2.2" height="6.4" rx=".6"/><rect class="na-glyph-cel" x="8.3" y="1.6" width="2.2" height="9" rx=".6"/>',
      no_signal: '<rect class="na-glyph-cel" x="1.8" y="1.8" width="8.4" height="8.4" rx="2" stroke-dasharray="2.1 1.7"/>',
      resolved: '<rect class="na-glyph-cel" x="1.4" y="1.4" width="9.2" height="9.2" rx="2"/><path d="M3.5 6.2l1.7 1.7 3.3-3.5"/>',
    };
    const inner = shapes[kind] || '<rect class="na-glyph-cel" x="1.8" y="1.8" width="8.4" height="8.4" rx="2"/>';
    return `<svg class="na-glyph" viewBox="0 0 12 12" aria-hidden="true">${inner}</svg>`;
  }

  function fmtAge(seconds) {
    const s = Math.max(0, Math.floor(Number(seconds) || 0));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (h < 24) return m ? `${h}h ${m}m ago` : `${h}h ago`;
    const d = Math.floor(h / 24);
    const remH = h % 24;
    return remH ? `${d}d ${remH}h ago` : `${d}d ago`;
  }

  function fmtTs(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return "";
    const d = new Date(n * 1000);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
  }

  function signedOut() {
    return !app || app.classList.contains("hidden");
  }

  function reset() {
    if (state.pending) {
      state.pending.abort();
      state.pending = null;
    }
    state.data = null;
    state.filter = "all";
    state.resolvedOpen = false;
    state.expanded = false;
    root.classList.remove("is-expanded");
    if (statusPill) {
      statusPill.className = "pill waiting";
      statusPill.textContent = "CHECKING";
    }
    root.innerHTML = '<p class="na-empty">Loading attention signals…</p>';
  }

  function renderAttentionItem(it, isResolved) {
    const catCls = safeCatClass(it.category);
    const eventHref = safeRelativeHref(it.link);
    const mapHref = safeRelativeHref(it.session_map_link);
    const incHref = safeRelativeHref(it.incident_link);
    const resHref = safeRelativeHref(it.resolved_link);
    const ageText = fmtAge(it.age_seconds);
    const sinceTitle = fmtTs(it.since);

    const chips = [];
    if (it.host_id) chips.push(`<span class="na-chip" title="Host">${esc(it.host_id)}</span>`);
    if (it.agent) chips.push(`<span class="na-chip" title="Agent">${esc(it.agent)}</span>`);
    if (it.session) chips.push(`<span class="na-chip" title="Session">${esc(it.session)}</span>`);
    if (it.workspace) chips.push(`<span class="na-chip" title="Workspace">${esc(it.workspace)}</span>`);
    if (it.exit_code !== null && it.exit_code !== undefined) {
      chips.push(`<span class="na-chip">exit ${esc(it.exit_code)}</span>`);
    }

    const actions = [];
    if (eventHref) {
      const lbl = it.event_id ? `Inspect event #${esc(it.event_id)} ↗` : "Open in Live ↗";
      actions.push(`<a href="${esc(eventHref)}" class="btn small primary" data-na-link="event">${lbl}</a>`);
    }
    if (incHref && incHref !== eventHref) {
      actions.push(`<a href="${esc(incHref)}" class="btn small" data-na-link="incident">Incident ↗</a>`);
    }
    if (mapHref) {
      actions.push(`<a href="${esc(mapHref)}" class="btn small" data-na-link="session">Activity map ↗</a>`);
    }
    if (isResolved && resHref) {
      actions.push(`<a href="${esc(resHref)}" class="btn small" data-na-link="resolution">Resolving event ↗</a>`);
    }

    const resolvedLine = isResolved
      ? `<p class="na-detail"><strong>Resolved:</strong> ${esc(it.resolution_reason || "Resolved")} · ${esc(fmtAge(it.resolved_age_seconds))}</p>`
      : "";

    return `
      <li class="na-item cat-${catCls}${isResolved ? " is-resolved" : ""}" data-na-category="${esc(it.category)}" data-na-event-id="${esc(it.event_id ?? "")}">
        <div class="na-item-top">
          <div class="na-item-badges">
            <span class="na-cat-pill cat-${catCls}">${categoryGlyph(catCls)}${esc(it.category_label || it.category)}</span>
            ${isResolved ? `<span class="na-cat-pill cat-resolved">${categoryGlyph("resolved")}Resolved</span>` : ""}
          </div>
          <time class="na-age" data-age-sec="${esc(it.age_seconds)}" title="${esc(sinceTitle)}">${esc(ageText)}</time>
        </div>
        <p class="na-title">${esc(it.title)}</p>
        ${it.detail ? `<p class="na-detail">${esc(it.detail)}</p>` : ""}
        ${resolvedLine}
        <div class="na-meta-row">
          <div class="na-meta-chips">${chips.join("")}</div>
          <div class="na-actions">${actions.join("")}</div>
        </div>
      </li>`;
  }

  function renderNoSignalItem(h) {
    const href = safeRelativeHref(h.link);
    const ageText = fmtAge(h.age_seconds);
    const lastSeenTitle = fmtTs(h.last_seen_at);
    return `
      <li class="na-item cat-no_signal" data-na-host="${esc(h.host_id)}" data-cause-inferred="false">
        <div class="na-item-top">
          <div class="na-item-badges">
            <span class="na-cat-pill cat-no_signal">${categoryGlyph("no_signal")}No signal</span>
            <span class="na-cause-tag">Heartbeat only · cause not inferred</span>
          </div>
          <time class="na-age" data-age-sec="${esc(h.age_seconds)}" title="Last heartbeat: ${esc(lastSeenTitle)}">Last heartbeat ${esc(ageText)}</time>
        </div>
        <p class="na-title">${esc(h.hostname)}${h.hostname !== h.host_id ? ` (${esc(h.host_id)})` : ""}</p>
        <p class="na-detail">${esc(h.summary)}</p>
        <div class="na-meta-row">
          <div class="na-meta-chips">
            <span class="na-chip">${esc(h.host_id)}</span>
            ${h.os_name ? `<span class="na-chip">${esc(h.os_name)}${h.arch ? "/" + esc(h.arch) : ""}</span>` : ""}
            <span class="na-chip">threshold ${esc(h.threshold_seconds)}s</span>
          </div>
          <div class="na-actions">
            ${href ? `<a href="${esc(href)}" class="btn small" data-na-link="no-signal">${h.incident_id ? `Incident #${esc(h.incident_id)} ↗` : "Host in Live ↗"}</a>` : ""}
          </div>
        </div>
      </li>`;
  }

  function render() {
    const data = state.data;
    if (!data) return;

    const counts = data.counts || {};
    const items = Array.isArray(data.items) ? data.items : [];
    const noSignal = Array.isArray(data.no_signal) ? data.no_signal : [];
    const resolved = Array.isArray(data.resolved) ? data.resolved : [];

    if (statusPill) {
      if (items.length > 0) {
        statusPill.className = "pill critical";
        statusPill.textContent = `${items.length} NEED ATTENTION`;
      } else if (noSignal.length > 0) {
        statusPill.className = "pill warning";
        statusPill.textContent = `${noSignal.length} NO SIGNAL`;
      } else {
        statusPill.className = "pill healthy";
        statusPill.textContent = "CLEAR";
      }
    }

    const filteredItems = state.filter === "all" ? items : items.filter((it) => it.category === state.filter);

    const filterBtns = [
      { id: "all", label: "All", count: items.length },
      { id: "permission", label: "Permissions", count: counts.permission || 0 },
      { id: "failed_test", label: "Failed tests", count: counts.failed_test || 0 },
      { id: "quota_exhausted", label: "Quota", count: counts.quota_exhausted || 0 },
    ]
      .map(
        (f) => `<button type="button" class="na-filter-btn${state.filter === f.id ? " active" : ""}" data-na-filter="${esc(f.id)}" aria-pressed="${state.filter === f.id ? "true" : "false"}">${esc(f.label)} <span class="na-filter-cnt">${esc(f.count)}</span></button>`
      )
      .join("");

    const attentionListHtml = filteredItems.length
      ? `<ul class="na-list" id="na-items-list">${filteredItems.map((it) => renderAttentionItem(it, false)).join("")}</ul>`
      : `<p class="na-empty" id="na-items-empty">${
          items.length
            ? "No active items in this category."
            : "No unresolved permission prompts, failed test runs, or exhausted quotas recorded in the last 24 hours."
        }</p>`;

    const noSignalHtml = noSignal.length
      ? `<ul class="na-list" id="na-no-signal-list">${noSignal.map(renderNoSignalItem).join("")}</ul>`
      : `<p class="na-empty" id="na-no-signal-empty">No stale hosts. Every reporting host sent a heartbeat within the last ${esc(data.stale_host_seconds || 90)}s.</p>`;

    const resolvedHtml = resolved.length
      ? `<details class="na-resolved-fold" id="na-resolved-fold"${state.resolvedOpen ? " open" : ""}>
          <summary>Recently resolved (${esc(resolved.length)})</summary>
          <ul class="na-list" id="na-resolved-list">${resolved.map((it) => renderAttentionItem(it, true)).join("")}</ul>
        </details>`
      : "";

    root.classList.toggle("is-expanded", state.expanded);
    const totalRecords = items.length + noSignal.length + resolved.length;
    const expandBtnHtml = totalRecords > 0
      ? `<button type="button" class="btn small na-expand-btn" data-na-toggle="expand" aria-expanded="${state.expanded ? "true" : "false"}">${state.expanded ? "Compact view" : `Expand all (${esc(totalRecords)})`}</button>`
      : "";

    root.innerHTML = `
      <div class="na-summary-bar">
        <div class="na-filters" role="group" aria-label="Filter attention items">${filterBtns}</div>
        <div class="na-summary-right">
          ${expandBtnHtml}
          <span class="na-updated">Updated ${esc(fmtTs(data.generated_at))}</span>
        </div>
      </div>
      <div class="na-grid">
        <div class="na-block" id="na-sessions-panel">
          <div class="na-block-head">
            <h3>Active attention items (${esc(filteredItems.length)})</h3>
            <span class="na-block-note">Explicit permissions, failed test runs, and exhausted quotas only</span>
          </div>
          ${attentionListHtml}
        </div>
        <div class="na-block na-no-signal-block" id="na-no-signal-panel">
          <div class="na-block-head">
            <h3>No signal — heartbeat (${esc(noSignal.length)})</h3>
            <span class="na-block-note">Measured strictly from host heartbeat age; cause is never inferred</span>
          </div>
          ${noSignalHtml}
        </div>
        ${resolvedHtml}
      </div>`;
  }

  root.addEventListener("click", (e) => {
    const expandBtn = e.target.closest("[data-na-toggle='expand']");
    if (expandBtn) {
      state.expanded = !state.expanded;
      render();
      return;
    }
    const btn = e.target.closest("[data-na-filter]");
    if (!btn) return;
    state.filter = btn.dataset.naFilter || "all";
    render();
  });

  root.addEventListener("toggle", (e) => {
    if (e.target && e.target.id === "na-resolved-fold") {
      state.resolvedOpen = Boolean(e.target.open);
    }
  }, true);

  async function load() {
    if (signedOut() || document.hidden) return;
    if (state.pending) state.pending.abort();
    const ctrl = new AbortController();
    state.pending = ctrl;
    try {
      const res = await fetch("/api/v1/needs-attention", {
        credentials: "same-origin",
        cache: "no-store",
        signal: ctrl.signal,
      });
      if (state.pending !== ctrl || signedOut()) return;
      if (res.status === 401) {
        reset();
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      state.data = await res.json();
      render();
    } catch (err) {
      if (err && err.name === "AbortError") return;
      if (state.pending !== ctrl || signedOut()) return;
      if (!state.data) {
        root.innerHTML = '<p class="na-empty">Could not load attention signals right now. Use Refresh to retry.</p>';
      }
    } finally {
      if (state.pending === ctrl) state.pending = null;
    }
  }

  document.addEventListener("swarm-org-changed", () => {
    reset();
    load();
  });
  document.getElementById("refresh-btn")?.addEventListener("click", load);
  window.addEventListener("online", load);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !signedOut()) load();
  });
  if (app) {
    new MutationObserver(() => {
      if (signedOut()) reset();
      else load();
    }).observe(app, { attributes: true, attributeFilter: ["class"] });
  }
  load();
  setInterval(load, 15000);
})();
