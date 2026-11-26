/* The report is loaded on demand. Opening a row uses Live's organization-bound evidence inspector. */
window.bindOutputCoverage = function ({api, activeOrg, openEvent}) {
  const byId = (id) => document.getElementById(id);
  const dialog = byId("output-coverage");
  const summary = byId("coverage-summary");
  const detail = byId("coverage-detail");
  const counts = byId("coverage-counts");
  const events = byId("coverage-events");
  const more = byId("coverage-more");
  const heading = byId("coverage-selection");
  const status = byId("coverage-status");
  const labels = {
    completed: "Completed", recorded_output: "Output recorded", missing_output: "Output missing",
    capture_disabled: "Capture disabled", outside_scope: "Outside authorized folders",
    protected: "Withheld for privacy", not_recorded: "Not recorded",
    empty_output: "Empty output", file_preview: "File preview", pending: "Pending",
    unconfirmed: "Completion unconfirmed",
  };
  const breakdown = ["capture_disabled", "outside_scope", "protected", "not_recorded", "empty_output",
                     "pending", "unconfirmed", "file_preview"];
  let organization, start, end, selection, previousButton, before;
  let generation = 0;

  function node(tag, text) {
    const element = document.createElement(tag);
    if (text != null) element.textContent = text;
    return element;
  }

  async function request(params, current) {
    const query = new URLSearchParams({organization_id: organization, from_ts: start, to_ts: end, ...params});
    const data = await api("/api/v1/output-coverage?" + query);
    if (current !== generation || !dialog.open || activeOrg()?.id !== organization) return null;
    if (String(data.organization) !== String(organization)) throw new Error("Active organization changed.");
    return data;
  }

  function showError(err, current) {
    if (current !== generation || !dialog.open) return;
    status.textContent = err.message || "Could not load output coverage.";
    if (err.status === 409 || err.status === 401 || err.status === 403) {
      counts.replaceChildren();
      events.replaceChildren();
      summary.hidden = detail.hidden = true;
    }
  }

  function countButton(row, bucket, withLabel) {
    const n = row.counts[bucket] || 0;
    if (!n) return document.createTextNode("0");
    const button = node("button", withLabel ? labels[bucket] + " · " + n : n);
    button.type = "button";
    button.className = "btn small";
    button.setAttribute("aria-label", (row.program || "All programs") + ", " + labels[bucket] + ", " + n);
    button.addEventListener("click", () => {
      selection = {bucket, version: row.version};
      if (row.program) selection.program = row.program;
      previousButton = button;
      before = null;
      more.hidden = true;
      events.replaceChildren();
      summary.hidden = true;
      detail.hidden = false;
      heading.textContent = (row.program || "All programs") + " · " + labels[bucket];
      heading.focus();
      loadEvents();
    });
    return button;
  }

  function addRow(row) {
    const tr = node("tr");
    const name = node("th", row.program || "All programs");
    name.scope = "row";
    tr.append(name);
    for (const bucket of ["completed", "recorded_output", "missing_output"]) {
      const td = node("td");
      td.append(countButton(row, bucket, false));
      tr.append(td);
    }
    const reasons = node("td");
    for (const bucket of breakdown) {
      if (row.counts[bucket]) reasons.append(countButton(row, bucket, true));
    }
    tr.append(reasons);
    counts.append(tr);
  }

  async function loadCounts(newWindow) {
    const current = ++generation;
    if (newWindow) {
      end = Math.floor(Date.now() / 1000) + 1;
      start = end - Number(byId("coverage-window").value);
    }
    byId("coverage-period").textContent = activeOrg().name + " · " +
      new Date(start * 1000).toLocaleString() + " – " + new Date(end * 1000).toLocaleString();
    summary.hidden = detail.hidden = true;
    counts.replaceChildren();
    events.replaceChildren();
    status.textContent = "Loading counts…";
    try {
      const data = await request({}, current);
      if (!data) return;
      if (!data.programs.length) {
        status.textContent = "No observed calls in this time window.";
        return;
      }
      addRow(data.total);
      data.programs.forEach(addRow);
      summary.hidden = false;
      status.textContent = "";
    } catch (err) { showError(err, current); }
  }

  async function loadEvents() {
    const current = ++generation;
    const params = {...selection};
    if (before) params.before = before;
    status.textContent = "Loading matching events…";
    more.disabled = true;
    try {
      const data = await request(params, current);
      if (!data) return;
      for (const event of data.events) {
        const li = node("li");
        const button = node("button", "Open event #" + event.id);
        button.type = "button";
        button.className = "btn small";
        button.addEventListener("click", () => openEvent(button, event.id, organization));
        const time = node("time", new Date(event.ts * 1000).toLocaleString());
        time.dateTime = new Date(event.ts * 1000).toISOString();
        li.append(button, node("code", event.program), node("span", event.host), time);
        events.append(li);
      }
      before = data.next_before;
      more.hidden = before == null;
      status.textContent = events.childElementCount + " of " + data.count + " matching events";
    } catch (err) { showError(err, current); }
    finally { if (current === generation) more.disabled = false; }
  }

  byId("open-output-coverage").addEventListener("click", () => {
    if (!activeOrg() || dialog.open) return;
    organization = activeOrg().id;
    dialog.showModal();
    loadCounts(true);
  });
  byId("coverage-refresh").addEventListener("click", () => loadCounts(false));
  byId("coverage-window").addEventListener("change", () => loadCounts(true));
  byId("coverage-back").addEventListener("click", () => {
    generation++;
    detail.hidden = true;
    summary.hidden = false;
    status.textContent = "";
    previousButton?.focus();
  });
  more.addEventListener("click", loadEvents);
  // Let the dialog handle its own keys, including native Escape, without firing feed shortcuts.
  dialog.addEventListener("keydown", (event) => event.stopPropagation());
  dialog.addEventListener("close", () => {
    if (dialog.open) return;
    generation++;
    counts.replaceChildren();
    events.replaceChildren();
    previousButton = selection = null;
  });
};
