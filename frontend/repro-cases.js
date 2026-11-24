/* NeuroSwarm Reproducible Cases Module
   - Converts failed agent sessions into minimal redacted repro cases.
   - Allows operators/admins to record manual verification runs and compare them
     side by side against the captured baseline failure.
   - Strict security invariant: telemetry commands are NEVER auto-executed;
     zero inline event handlers, zero external URLs (100% CSP-safe). */
(() => {
  "use strict";

  const root = document.getElementById("repro-cases-body");
  const statusPill = document.getElementById("rc-status-pill");
  const app = document.getElementById("app-view");
  if (!root) return;

  const state = {
    data: null,
    selectedCaseId: null,
    selectedRunNumber: null,
    convertCandidate: null,
    runFormOpen: false,
    exportPreview: null,
    feedback: null,
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

  function fmtTs(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n <= 0) return "";
    const d = new Date(n * 1000);
    return Number.isNaN(d.getTime()) ? "" : d.toLocaleString();
  }

  function verdictClass(verdict) {
    if (verdict === "fixed") return "rc-verdict-fixed";
    if (verdict === "changed_failure") return "rc-verdict-changed";
    if (verdict === "inconclusive") return "rc-verdict-inconclusive";
    if (verdict === "still_failing") return "rc-verdict-failing";
    return "rc-verdict-baseline";
  }

  function signedOut() {
    return !app || app.classList.contains("hidden");
  }

  function hasActiveEditor() {
    const active = document.activeElement;
    if (active && root.contains(active) && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName)) {
      return true;
    }
    return Boolean(state.convertCandidate || state.runFormOpen);
  }

  function reset() {
    if (state.pending) {
      state.pending.abort();
      state.pending = null;
    }
    state.data = null;
    state.selectedCaseId = null;
    state.selectedRunNumber = null;
    state.convertCandidate = null;
    state.runFormOpen = false;
    state.exportPreview = null;
    state.feedback = null;
    state.busy = false;
    if (statusPill) {
      statusPill.className = "pill neutral";
      statusPill.textContent = "CHECKING";
    }
    root.innerHTML = '<p class="rc-empty">Loading failed sessions and reproducible cases…</p>';
  }

  function currentCase() {
    const cases = Array.isArray(state.data?.cases) ? state.data.cases : [];
    if (!cases.length) return null;
    const found = cases.find((c) => Number(c.id) === Number(state.selectedCaseId));
    return found || cases[0];
  }

  function renderDiff(lines, truncated) {
    if (!Array.isArray(lines) || !lines.length) {
      return '<p class="rc-empty">No text output difference lines between baseline and this run.</p>';
    }
    const body = lines
      .map((line) => {
        let cls = "";
        if (line.startsWith("+") && !line.startsWith("+++")) cls = " rc-diff-add";
        else if (line.startsWith("-") && !line.startsWith("---")) cls = " rc-diff-del";
        else if (line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++")) cls = " rc-diff-hunk";
        return `<span class="rc-diff-line${cls}">${esc(line)}</span>`;
      })
      .join("");
    const note = truncated ? '<p class="rc-sub">Diff output truncated to keep display compact.</p>' : "";
    return `<div class="rc-diff" id="rc-diff-view">${body}</div>${note}`;
  }

  function renderCandidate(cand, canWrite) {
    const eventHref = safeRelativeHref(cand.event_link);
    const chips = [
      cand.host_id ? `<span class="rc-chip">${esc(cand.host_id)}</span>` : "",
      cand.harness ? `<span class="rc-chip">${esc(cand.harness)}</span>` : "",
      cand.agent_name ? `<span class="rc-chip">${esc(cand.agent_name)}</span>` : "",
      cand.session_id ? `<span class="rc-chip">${esc(cand.session_id)}</span>` : "",
      cand.observed_exit_code !== null && cand.observed_exit_code !== undefined
        ? `<span class="rc-chip">exit ${esc(cand.observed_exit_code)}</span>`
        : "",
      cand.revision ? `<span class="rc-chip">rev ${esc(cand.revision)}</span>` : "",
      `<span class="rc-chip">${cand.has_command ? "cmd recorded" : "cmd absent"}</span>`,
      `<span class="rc-chip">${cand.has_output ? "output recorded" : "output absent"}</span>`,
    ]
      .filter(Boolean)
      .join("");

    const convertBtn = canWrite
      ? `<button type="button" class="btn small primary" data-rc-convert="${esc(cand.source_event_id)}">${
          cand.existing_case_id ? "Convert again" : "Convert to repro case"
        }</button>`
      : "";
    const existingBtn = cand.existing_case_id
      ? `<button type="button" class="btn small" data-rc-select="${esc(cand.existing_case_id)}">View case #${esc(cand.existing_case_id)}</button>`
      : "";
    const liveBtn = eventHref ? `<a href="${esc(eventHref)}" class="btn small">Inspect event ↗</a>` : "";

    return `
      <li class="rc-item rc-failed-item" data-rc-source-event="${esc(cand.source_event_id)}">
        <div class="rc-item-top">
          <p class="rc-title">${esc(cand.suggested_title || cand.failure_summary || "Failed session")}</p>
          <span class="rc-verdict rc-verdict-baseline">${esc(cand.observed_outcome || "failed")}</span>
        </div>
        ${cand.failure_summary ? `<p class="rc-sub">${esc(cand.failure_summary)}</p>` : ""}
        <div class="rc-chips">${chips}</div>
        <div class="rc-actions">${convertBtn}${existingBtn}${liveBtn}</div>
      </li>`;
  }

  function renderConvertForm(cand) {
    if (!cand) return "";
    return `
      <form class="rc-form" id="rc-convert-form">
        <div class="rc-panel-head">
          <h4>Create reproducible case from event #${esc(cand.source_event_id)}</h4>
          <span class="rc-panel-note">Exported command text stays inert; review/adjust expected result before saving.</span>
        </div>
        <div>
          <label for="rc-conv-title">Case title</label>
          <input id="rc-conv-title" name="title" type="text" maxlength="180" required value="${esc(cand.suggested_title || "")}">
        </div>
        <div class="rc-form-row">
          <div>
            <label for="rc-conv-revision">Revision (optional commit or ref)</label>
            <input id="rc-conv-revision" name="revision" type="text" maxlength="80" placeholder="Leave blank if unknown" value="${esc(cand.revision || "")}">
          </div>
          <div>
            <label for="rc-conv-cmd">Command (optional override, manual-only)</label>
            <input id="rc-conv-cmd" name="command_input" type="text" maxlength="1024" placeholder="Not recorded" value="${esc(cand.command_input || "")}">
          </div>
        </div>
        <div>
          <label for="rc-conv-expected">Expected result</label>
          <textarea id="rc-conv-expected" name="expected_result" maxlength="1024" placeholder="What should have succeeded?">${esc(cand.expected_result || "")}</textarea>
        </div>
        <div>
          <label for="rc-conv-notes">Operator context notes (optional)</label>
          <textarea id="rc-conv-notes" name="notes" maxlength="1024" placeholder="Minimal reproduction notes (secrets are automatically redacted)"></textarea>
        </div>
        <div class="rc-actions">
          <button type="submit" id="rc-conv-submit" class="btn small primary"${state.busy ? " disabled" : ""}>Save repro case</button>
          <button type="button" id="rc-conv-cancel" class="btn small">Cancel</button>
        </div>
      </form>`;
  }

  function renderCaseItem(c, activeId) {
    const selected = Number(c.id) === Number(activeId);
    const chips = [
      `<span class="rc-chip">#${esc(c.id)}</span>`,
      c.revision ? `<span class="rc-chip">rev ${esc(c.revision)}</span>` : '<span class="rc-chip">rev not recorded</span>',
      c.observed_exit_code !== null && c.observed_exit_code !== undefined
        ? `<span class="rc-chip">baseline exit ${esc(c.observed_exit_code)}</span>`
        : "",
      `<span class="rc-chip">${esc(c.run_count || 0)} run${c.run_count === 1 ? "" : "s"}</span>`,
    ]
      .filter(Boolean)
      .join("");

    return `
      <li class="rc-item rc-case-item${selected ? " is-selected" : ""}" data-rc-case-id="${esc(c.id)}">
        <div class="rc-item-top">
          <p class="rc-title">${esc(c.title)}</p>
          <span class="rc-verdict ${verdictClass(c.latest_verdict)}">${esc(c.latest_verdict_label || "Baseline failed")}</span>
        </div>
        <div class="rc-chips">${chips}</div>
        <div class="rc-actions">
          <button type="button" class="btn small${selected ? " primary" : ""}" data-rc-select="${esc(c.id)}">${
            selected ? "Selected" : "Open & compare"
          }</button>
        </div>
      </li>`;
  }

  function renderRunForm(c) {
    if (!state.runFormOpen) return "";
    return `
      <form class="rc-form" id="rc-run-form">
        <div class="rc-panel-head">
          <h4>Record manual verification run for case #${esc(c.id)}</h4>
          <span class="rc-panel-note">Run the command on your host manually, then record observed outcome here.</span>
        </div>
        <div class="rc-form-row">
          <div>
            <label for="rc-run-status">Run status</label>
            <select id="rc-run-status" name="status" class="select full-select">
              <option value="passed">Passed (fixed)</option>
              <option value="failed">Failed</option>
              <option value="inconclusive">Inconclusive</option>
            </select>
          </div>
          <div>
            <label for="rc-run-exit">Exit code (optional integer)</label>
            <input id="rc-run-exit" name="exit_code" type="number" step="1" placeholder="e.g. 0 or 1">
          </div>
        </div>
        <div class="rc-form-row">
          <div>
            <label for="rc-run-revision">Revision tested (optional)</label>
            <input id="rc-run-revision" name="revision" type="text" maxlength="80" value="${esc(c.revision || "")}" placeholder="e.g. commit SHA or branch">
          </div>
          <div>
            <label for="rc-run-cmd">Command used (optional)</label>
            <input id="rc-run-cmd" name="command_used" type="text" maxlength="1024" value="${esc(c.command_input || "")}">
          </div>
        </div>
        <div>
          <label for="rc-run-output">Observed output excerpt (optional, redacted on save)</label>
          <textarea id="rc-run-output" name="observed_output" maxlength="4096" placeholder="Paste relevant stdout/stderr excerpt"></textarea>
        </div>
        <div>
          <label for="rc-run-notes">Notes (optional)</label>
          <textarea id="rc-run-notes" name="notes" maxlength="1024" placeholder="What changed or was verified?"></textarea>
        </div>
        <div class="rc-actions">
          <button type="submit" id="rc-run-submit" class="btn small primary"${state.busy ? " disabled" : ""}>Save run &amp; compare</button>
          <button type="button" id="rc-run-cancel" class="btn small">Cancel</button>
        </div>
      </form>`;
  }

  function renderComparison(c) {
    const runs = Array.isArray(c.runs) ? c.runs : [];
    if (!runs.length) {
      return `
        <div class="rc-compare-box" id="rc-comparison">
          <div class="rc-panel-head">
            <h4>Baseline vs verification run</h4>
            <span class="rc-verdict rc-verdict-baseline">No runs recorded yet</span>
          </div>
          <p class="rc-empty">Export the bundle above, run the command manually in your environment, and use "Record new run" to compare results.</p>
        </div>`;
    }

    const activeRun =
      runs.find((r) => Number(r.run_number) === Number(state.selectedRunNumber)) || runs[runs.length - 1];
    const comp = activeRun.comparison || {};
    const options = runs
      .map(
        (r) =>
          `<option value="${esc(r.run_number)}"${Number(r.run_number) === Number(activeRun.run_number) ? " selected" : ""}>Run #${esc(
            r.run_number
          )} · ${esc(r.status)} (${esc(r.comparison?.verdict_label || "")})</option>`
      )
      .join("");

    const historyRows = runs
      .map(
        (r) => `
        <tr>
          <td>#${esc(r.run_number)}</td>
          <td><span class="rc-verdict ${verdictClass(r.comparison?.verdict)}">${esc(r.comparison?.verdict_label || r.status)}</span></td>
          <td>${esc(r.revision || "Not recorded")}</td>
          <td>${r.exit_code !== null && r.exit_code !== undefined ? esc(r.exit_code) : "—"}</td>
          <td>${esc(r.recorded_by || "")}</td>
          <td>${esc(fmtTs(r.recorded_at))}</td>
        </tr>`
      )
      .join("");

    return `
      <div class="rc-compare-box" id="rc-comparison">
        <div class="rc-panel-head">
          <div>
            <h4>Baseline vs Run #${esc(activeRun.run_number)}</h4>
            <p class="rc-sub">${esc(comp.summary || "")}</p>
          </div>
          <div class="rc-actions">
            <label for="rc-run-select" class="sr-only">Select verification run to compare</label>
            <select id="rc-run-select" class="select">${options}</select>
            <span class="rc-verdict ${verdictClass(comp.verdict)}" id="rc-compare-verdict">${esc(comp.verdict_label || activeRun.status)}</span>
          </div>
        </div>
        <table class="rc-compare-table">
          <thead>
            <tr>
              <th>Field</th>
              <th>Baseline (failed session)</th>
              <th>Run #${esc(activeRun.run_number)}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Outcome</strong></td>
              <td>${esc(c.observed_outcome || "failed")}</td>
              <td>${esc(activeRun.status)} (${esc(comp.verdict_label || "")})</td>
            </tr>
            <tr>
              <td><strong>Revision</strong></td>
              <td><code>${esc(c.revision || "Not recorded")}</code></td>
              <td><code>${esc(activeRun.revision || "Not recorded")}</code></td>
            </tr>
            <tr>
              <td><strong>Exit code</strong></td>
              <td><code>${c.observed_exit_code !== null && c.observed_exit_code !== undefined ? esc(c.observed_exit_code) : "Not recorded"}</code></td>
              <td><code>${activeRun.exit_code !== null && activeRun.exit_code !== undefined ? esc(activeRun.exit_code) : "Not recorded"}</code></td>
            </tr>
            <tr>
              <td><strong>Command</strong></td>
              <td><code>${esc(c.command_input || "Not recorded")}</code></td>
              <td><code>${esc(activeRun.command_used || "Not recorded")}</code></td>
            </tr>
          </tbody>
        </table>
        <div>
          <strong class="small">Observed output diff (baseline → run #${esc(activeRun.run_number)})</strong>
          ${renderDiff(comp.diff_lines, comp.diff_truncated)}
        </div>
        ${activeRun.notes ? `<p class="rc-sub"><strong>Run notes:</strong> ${esc(activeRun.notes)}</p>` : ""}
        <div>
          <strong class="small">Recorded runs (${esc(runs.length)})</strong>
          <table class="rc-compare-table" id="rc-runs-table">
            <thead>
              <tr><th>Run</th><th>Verdict</th><th>Revision</th><th>Exit</th><th>Recorded by</th><th>Time</th></tr>
            </thead>
            <tbody>${historyRows}</tbody>
          </table>
        </div>
      </div>`;
  }

  function renderDetail(c, canWrite) {
    if (!c) {
      return '<p class="rc-empty">Select a reproducible case (or convert a failed session) to inspect its redacted bundle and compare runs.</p>';
    }
    const eventHref = safeRelativeHref(c.event_link);
    const jsonHref = safeRelativeHref(c.export_urls?.json);
    const mdHref = safeRelativeHref(c.export_urls?.markdown);
    const steps = Array.isArray(c.context?.recent_steps) ? c.context.recent_steps : [];
    const stepsText = steps.length
      ? steps
          .map(
            (s) =>
              `[${s.tool || "step"} · ${s.outcome || "?"}${
                s.exit_code !== null && s.exit_code !== undefined ? ` · exit ${s.exit_code}` : ""
              }] ${s.summary || ""}`
          )
          .join("\n")
      : "No earlier session steps recorded.";
    const suppressedBanner = c.context?.output_suppressed_reason
      ? `<p class="rc-sub">Output omitted automatically (${esc(c.context.output_suppressed_reason)}).</p>`
      : "";

    const previewBox =
      state.exportPreview && Number(state.exportPreview.caseId) === Number(c.id) && state.exportPreview.open
        ? `<div id="rc-export-preview-wrap">
             <strong class="small">Redacted export preview (JSON · manual-only)</strong>
             <pre class="rc-pre" id="rc-export-preview">${esc(state.exportPreview.text || "")}</pre>
           </div>`
        : "";

    return `
      <div class="rc-detail" id="rc-detail" data-rc-active-case="${esc(c.id)}">
        <div class="rc-detail-head">
          <div>
            <h4>#${esc(c.id)} · ${esc(c.title)}</h4>
            <p class="rc-sub">Case key <code>${esc(c.case_key)}</code> · Created by ${esc(c.created_by || "operator")} · ${esc(fmtTs(c.created_at))}</p>
          </div>
          <span class="rc-verdict ${verdictClass(c.latest_verdict)}">${esc(c.latest_verdict_label || "Baseline failed")}</span>
        </div>

        <div class="rc-meta-grid">
          <div><span class="rc-meta-label">Host / Runtime</span>${esc(c.host_id)} · ${esc(c.harness)}</div>
          <div><span class="rc-meta-label">Agent / Session</span>${esc(c.agent_name)} · <code>${esc(c.session_id)}</code></div>
          <div><span class="rc-meta-label">Workspace</span><code>${esc(c.workspace || "Not recorded")}</code></div>
          <div><span class="rc-meta-label">Revision</span><code>${esc(c.revision || "Not recorded")}</code></div>
          <div><span class="rc-meta-label">Files</span>${c.files?.length ? c.files.map((f) => `<code>${esc(f)}</code>`).join(", ") : "None recorded"}</div>
        </div>

        <div class="rc-actions">
          ${jsonHref ? `<a href="${esc(jsonHref)}" download="repro-case-${esc(c.id)}.json" class="btn small" data-rc-export="json">Export JSON</a>` : ""}
          ${mdHref ? `<a href="${esc(mdHref)}" download="repro-case-${esc(c.id)}.md" class="btn small" data-rc-export="markdown">Export Markdown</a>` : ""}
          <button type="button" class="btn small" data-rc-preview="${esc(c.id)}">Preview redacted JSON</button>
          ${eventHref ? `<a href="${esc(eventHref)}" class="btn small">Inspect source event ↗</a>` : ""}
          ${
            canWrite
              ? `<button type="button" id="rc-toggle-run-form" class="btn small primary">${
                  state.runFormOpen ? "Close run form" : "Record new run"
                }</button>`
              : ""
          }
        </div>

        ${previewBox}
        ${renderRunForm(c)}

        <div>
          <div class="rc-panel-head">
            <strong class="small">Command (manual execution only — never run automatically by NeuroSwarm)</strong>
            ${c.command_input ? `<button type="button" class="btn small secondary" data-rc-copy-cmd="${esc(c.id)}">Copy command</button>` : ""}
          </div>
          <pre class="rc-pre rc-pre-cmd">${esc(c.command_input || "Not recorded (set SWARMCONTROL_SHARE_COMMANDS=1 on the host collector to include redacted commands).")}</pre>
        </div>

        <div class="rc-form-row">
          <div>
            <strong class="small">Expected result</strong>
            <pre class="rc-pre">${esc(c.expected_result || "Not recorded.")}</pre>
          </div>
          <div>
            <strong class="small">Baseline observed output (${
              c.observed_exit_code !== null && c.observed_exit_code !== undefined ? `exit ${esc(c.observed_exit_code)}` : esc(c.observed_outcome || "failed")
            })</strong>
            ${suppressedBanner}
            <pre class="rc-pre">${esc(c.observed_output || "No command output recorded.")}</pre>
          </div>
        </div>

        <details>
          <summary class="small">Minimal session steps context (${esc(steps.length)})</summary>
          <pre class="rc-pre">${esc(stepsText)}</pre>
        </details>

        ${renderComparison(c)}
      </div>`;
  }

  function render() {
    const data = state.data;
    if (!data) return;

    const failed = Array.isArray(data.failed_sessions) ? data.failed_sessions : [];
    const cases = Array.isArray(data.cases) ? data.cases : [];
    const counts = data.counts || {};
    const canWrite = Boolean(data.can_write);
    const active = currentCase();
    if (active) state.selectedCaseId = active.id;

    if (statusPill) {
      if ((counts.still_failing || 0) > 0 || (counts.baseline_only || 0) > 0) {
        statusPill.className = "pill warning";
        statusPill.textContent = `${cases.length} CASE${cases.length === 1 ? "" : "S"}`;
      } else if (failed.length > 0) {
        statusPill.className = "pill warning";
        statusPill.textContent = `${failed.length} FAILED SESSION${failed.length === 1 ? "" : "S"}`;
      } else {
        statusPill.className = "pill healthy";
        statusPill.textContent = cases.length ? `${cases.length} FIXED` : "NONE";
      }
    }

    const feedbackHtml = state.feedback
      ? `<div class="rc-feedback ${state.feedback.type === "error" ? "error" : "ok"}" role="status">${esc(state.feedback.text)}</div>`
      : "";

    const readonlyNotice = !canWrite
      ? '<p class="rc-sub" id="rc-readonly-note">Viewer role: you can inspect and export redacted repro cases, while converting sessions or recording verification runs requires the operator or admin role.</p>'
      : "";

    const failedListHtml = failed.length
      ? `<ul class="rc-list" id="rc-failed-list">${failed.map((f) => renderCandidate(f, canWrite)).join("")}</ul>`
      : '<p class="rc-empty" id="rc-failed-empty">No recent failed sessions detected in ingested telemetry.</p>';

    const casesListHtml = cases.length
      ? `<ul class="rc-list" id="rc-cases-list">${cases.map((c) => renderCaseItem(c, active?.id)).join("")}</ul>`
      : '<p class="rc-empty" id="rc-cases-empty">No reproducible cases saved yet. Convert a failed session from the left panel to create one.</p>';

    root.innerHTML = `
      <div class="rc-safety-note" id="rc-safety-banner">
        <span><strong>Manual-only execution:</strong> Telemetry commands and logs are exported as redacted inert text and are never executed automatically.</span>
      </div>
      ${readonlyNotice}
      ${feedbackHtml}
      <div class="rc-summary-bar">
        <div class="rc-kpis">
          <span class="rc-stat-chip">Failed sessions: ${esc(counts.failed_sessions ?? failed.length)}</span>
          <span class="rc-stat-chip">Saved cases: ${esc(counts.cases ?? cases.length)}</span>
          <span class="rc-stat-chip">Fixed: ${esc(counts.fixed ?? 0)}</span>
        </div>
        <span class="rc-updated">Updated ${esc(fmtTs(data.generated_at))}</span>
      </div>
      <div class="rc-grid">
        <div class="rc-panel" id="rc-failed-panel">
          <div class="rc-panel-head">
            <h3>Failed sessions (${esc(failed.length)})</h3>
            <span class="rc-panel-note">Select a failure to export a minimal repro bundle</span>
          </div>
          ${failedListHtml}
          ${canWrite ? renderConvertForm(state.convertCandidate) : ""}
        </div>
        <div class="rc-panel" id="rc-cases-panel">
          <div class="rc-panel-head">
            <h3>Saved repro cases (${esc(cases.length)})</h3>
            <span class="rc-panel-note">Inspect bundle, export JSON/Markdown, and compare runs</span>
          </div>
          ${casesListHtml}
        </div>
      </div>
      ${renderDetail(active, canWrite)}`;
  }

  async function apiJson(url, opts = {}) {
    const res = await fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(body.error || body.message || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return body;
  }

  async function load(force = false) {
    if (signedOut() || (document.hidden && !force)) return;
    if (!force && hasActiveEditor()) return;
    if (state.pending) state.pending.abort();
    const ctrl = new AbortController();
    state.pending = ctrl;
    try {
      const res = await fetch("/api/v1/repro-cases", {
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
        root.innerHTML = '<p class="rc-empty">Could not load reproducible cases right now. Use Refresh to retry.</p>';
      }
    } finally {
      if (state.pending === ctrl) state.pending = null;
    }
  }

  root.addEventListener("click", async (e) => {
    const convertBtn = e.target.closest("[data-rc-convert]");
    if (convertBtn) {
      const evId = Number(convertBtn.dataset.rcConvert);
      const cand = (state.data?.failed_sessions || []).find((f) => Number(f.source_event_id) === evId);
      if (cand) {
        state.convertCandidate = cand;
        state.feedback = null;
        render();
        document.getElementById("rc-conv-title")?.focus();
      }
      return;
    }

    if (e.target.id === "rc-conv-cancel") {
      state.convertCandidate = null;
      render();
      return;
    }

    const selectBtn = e.target.closest("[data-rc-select]");
    if (selectBtn) {
      state.selectedCaseId = Number(selectBtn.dataset.rcSelect);
      state.selectedRunNumber = null;
      state.runFormOpen = false;
      state.exportPreview = null;
      render();
      return;
    }

    if (e.target.id === "rc-toggle-run-form") {
      state.runFormOpen = !state.runFormOpen;
      state.feedback = null;
      render();
      if (state.runFormOpen) document.getElementById("rc-run-status")?.focus();
      return;
    }

    if (e.target.id === "rc-run-cancel") {
      state.runFormOpen = false;
      render();
      return;
    }

    const copyBtn = e.target.closest("[data-rc-copy-cmd]");
    if (copyBtn) {
      const c = currentCase();
      if (c && c.command_input && navigator.clipboard?.writeText) {
        navigator.clipboard.writeText(c.command_input).catch(() => {});
        state.feedback = { type: "ok", text: "Copied redacted command text for manual execution." };
        render();
      }
      return;
    }

    const previewBtn = e.target.closest("[data-rc-preview]");
    if (previewBtn) {
      const caseId = Number(previewBtn.dataset.rcPreview);
      if (state.exportPreview && Number(state.exportPreview.caseId) === caseId && state.exportPreview.open) {
        state.exportPreview = null;
        render();
        return;
      }
      try {
        const orgParam = state.data?.organization != null ? `&organization_id=${encodeURIComponent(state.data.organization)}` : "";
        const res = await fetch(`/api/v1/repro-cases/${caseId}/export?format=json${orgParam}`, {
          credentials: "same-origin",
          cache: "no-store",
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const text = await res.text();
        state.exportPreview = { caseId, open: true, text };
      } catch (err) {
        state.feedback = { type: "error", text: `Could not load export preview (${err.message || "error"}).` };
      }
      render();
    }
  });

  root.addEventListener("change", (e) => {
    if (e.target && e.target.id === "rc-run-select") {
      state.selectedRunNumber = Number(e.target.value);
      render();
    }
  });

  root.addEventListener("submit", async (e) => {
    if (e.target && e.target.id === "rc-convert-form") {
      e.preventDefault();
      if (!state.convertCandidate || state.busy) return;
      state.busy = true;
      state.feedback = null;
      const payload = {
        source_event_id: Number(state.convertCandidate.source_event_id),
        title: document.getElementById("rc-conv-title")?.value || "",
        revision: document.getElementById("rc-conv-revision")?.value || "",
        command_input: document.getElementById("rc-conv-cmd")?.value || "",
        expected_result: document.getElementById("rc-conv-expected")?.value || "",
        notes: document.getElementById("rc-conv-notes")?.value || "",
      };
      if (state.data?.organization != null) payload.organization_id = state.data.organization;
      try {
        const created = await apiJson("/api/v1/repro-cases", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        state.busy = false;
        state.convertCandidate = null;
        state.selectedCaseId = created.id;
        state.selectedRunNumber = null;
        state.feedback = { type: "ok", text: `Saved reproducible case #${created.id}.` };
        await load(true);
      } catch (err) {
        state.busy = false;
        state.feedback = { type: "error", text: err.message || "Could not create repro case." };
        render();
      }
      return;
    }

    if (e.target && e.target.id === "rc-run-form") {
      e.preventDefault();
      const c = currentCase();
      if (!c || state.busy) return;
      state.busy = true;
      state.feedback = null;
      const rawExit = (document.getElementById("rc-run-exit")?.value || "").trim();
      let exitCode = null;
      if (rawExit !== "") {
        const parsed = Number(rawExit);
        if (!Number.isInteger(parsed)) {
          state.busy = false;
          state.feedback = { type: "error", text: "Exit code must be a whole integer or left blank." };
          render();
          return;
        }
        exitCode = parsed;
      }
      const payload = {
        status: document.getElementById("rc-run-status")?.value || "failed",
        exit_code: exitCode,
        revision: document.getElementById("rc-run-revision")?.value || "",
        command_used: document.getElementById("rc-run-cmd")?.value || "",
        observed_output: document.getElementById("rc-run-output")?.value || "",
        notes: document.getElementById("rc-run-notes")?.value || "",
      };
      if (c.organization != null) payload.organization_id = c.organization;
      else if (state.data?.organization != null) payload.organization_id = state.data.organization;
      try {
        const res = await apiJson(`/api/v1/repro-cases/${c.id}/runs`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        state.busy = false;
        state.runFormOpen = false;
        state.selectedCaseId = c.id;
        state.selectedRunNumber = res.run?.run_number || null;
        state.feedback = {
          type: "ok",
          text: `Recorded run #${res.run?.run_number}: ${res.comparison?.verdict_label || res.run?.status}.`,
        };
        await load(true);
      } catch (err) {
        state.busy = false;
        state.feedback = { type: "error", text: err.message || "Could not record verification run." };
        render();
      }
    }
  });

  document.addEventListener("swarm-org-changed", () => {
    reset();
    load(true);
  });
  document.getElementById("refresh-btn")?.addEventListener("click", () => load(true));
  window.addEventListener("online", () => load(true));
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !signedOut()) load(false);
  });
  if (app) {
    new MutationObserver(() => {
      if (signedOut()) reset();
      else load(true);
    }).observe(app, { attributes: true, attributeFilter: ["class"] });
  }
  load(true);
  setInterval(() => load(false), 15000);
})();
