"use strict";
const el = id => document.getElementById(id);
const node = (tag, value) => {
  const element = document.createElement(tag);
  element.textContent = value;
  return element;
};
let missions = [];
let organization;
let generation = 0;
const sourceEvent = (id, label) => {
  const link = node("a", label);
  link.href = "/live?" + new URLSearchParams({event: "event:" + id, organization: String(organization)});
  return link;
};

async function loadEvidence(details, task, version) {
  if (!details.open || details.dataset.loaded) return;
  details.dataset.loaded = "true";
  const body = node("p", "Checking linked actions…");
  details.append(body);
  try {
    const response = await fetch("/api/v1/missions?" + new URLSearchParams({task}), {cache: "no-store"});
    if (!response.ok) throw Error();
    const data = await response.json();
    if (version !== generation) return;
    if (data.organization !== organization) { await refresh(); return; }
    const link = data.link;
    body.textContent = link?.reason || "No matching action recorded for this task.";
    if (link?.last_step?.event_id) body.append(" · ", sourceEvent(link.last_step.event_id, "Latest action"));
    if (link?.confirmed_file_event_id) body.append(" · ", sourceEvent(link.confirmed_file_event_id, link.confirmed_file || "Confirmed file edit"));
  } catch {
    body.textContent = "Action lookup failed. Close and reopen to retry.";
    delete details.dataset.loaded;
  }
}

function render() {
  const mission = missions[el("mission").selectedIndex];
  if (!mission) return;
  el("objective").textContent = mission.title;
  const agents = new Set(mission.events.flatMap(event => [event.agent, event.to]).filter(Boolean));
  el("participants").textContent = [...agents].join(" · ");
  const nodes = mission.events.map(event => {
    const row = node("li", "");
    const stamp = new Date(event.time * 1000);
    const date = event.time ? stamp.toLocaleString() : "Time unavailable";
    row.append(node("strong", event.agent + (event.to ? " → " + event.to : "")));
    row.append(node("p", event.kind + " · " + date + " · " + mission.source));
    if (event.parent_text) row.append(node("blockquote", event.parent_text));
    row.append(node("p", event.text || "Content unavailable for this event."));
    if (event.reason) row.append(node("p", "Reported reason: " + event.reason));
    if (event.event_id) row.append(sourceEvent(event.event_id, "Open source event in Live"));
    if (event.task_id) {
      const details = document.createElement("details");
      details.className = "task-info";
      details.append(node("summary", "Task and linked actions"));
      details.append(node("p", [event.task || event.task_id, event.owner, event.state].filter(Boolean).join(" · ")));
      details.addEventListener("toggle", () => loadEvidence(details, event.task_id, generation));
      row.append(details);
    }
    return row;
  });
  el("events").replaceChildren(...nodes);
}

async function refresh() {
  const version = ++generation;
  const previous = el("mission").value || new URLSearchParams(location.search).get("mission");
  el("signin").hidden = true;
  try {
    const response = await fetch("/api/v1/missions", {cache:"no-store"});
    if (version !== generation) return;
    if (!response.ok) {
      if (response.status === 401) el("signin").hidden = false;
      throw Error();
    }
    const data = await response.json();
    if (version !== generation) return;
    organization = data.organization;
    missions = data.missions;
    el("mission").replaceChildren(...missions.map(m => new Option(m.title, m.source + "/" + m.id)));
    if (missions.some(m => m.source + "/" + m.id === previous)) el("mission").value = previous;
    el("view").hidden = !missions.length;
    el("status").textContent = (missions.length ? "Recent missions: " + missions.length : "No mission reports received.")
      + (data.shared_channel === "unavailable" ? " The shared channel could not be read." : "");
    render();
  } catch {
    if (version !== generation) return;
    missions = [];
    el("events").replaceChildren();
    el("view").hidden = true;
    el("status").textContent = el("signin").hidden ? "Could not load mission evidence. Refresh to retry." : "An operator session is required.";
  }
}
el("mission").addEventListener("change", render);
el("refresh").addEventListener("click", refresh);
window.addEventListener("pageshow", refresh);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
