"use strict";

const $ = (id) => document.getElementById(id);
const make = (tag, value = "", className = "") => {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
};
const dateTime = (value) =>
  new Date(value).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "medium",
  });
const number = (value) =>
  value == null ? "Unavailable" : Number(value).toLocaleString();
const pages = {
  overview: ["Overview", "A clear view of activity across your organization."],
  alerts: [
    "Security incidents",
    "Move from suspicious activity to the evidence behind it.",
  ],
  events: [
    "Event explorer",
    "Find the records you need without losing your place.",
  ],
  delivery: [
    "Sources & delivery",
    "Check connected computers and follow each delivery stage.",
  ],
  settings: [
    "Workspace settings",
    "Manage your account, team access, and connected computers.",
  ],
};
let snapshot = null;
let query = "";
let appliedQuery = "";
let staleData = false;
let paused = false;
let busy = false;
let rerun = false;
let epoch = 0;
let requestController = null;
let adminLoaded = false;
let detailRecord = null;
let toastTimer;
let adminBusy = false;

async function api(path, options = {}) {
  const response = await fetch("/api/v1/dashboard/" + path, {
    ...options,
    signal: options.signal || AbortSignal.timeout(15000),
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const error = new Error(
      typeof data.detail === "string"
        ? data.detail
        : `Request failed (${response.status}). Try again.`,
    );
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function message(id, value) {
  $(id).textContent = value;
  $(id).hidden = !value;
}
function toast(value) {
  clearTimeout(toastTimer);
  message("toast", value);
  toastTimer = setTimeout(() => message("toast", ""), 4500);
}
function pill(value, kind = "neutral") {
  return make("span", value, "pill " + kind);
}
function empty(title, description) {
  const node = make("div", "", "empty");
  node.append(make("strong", title), make("p", description));
  return node;
}
function button(label, action, className = "quiet", focusKey = "") {
  const node = make("button", label, className);
  node.type = "button";
  if (focusKey) node.dataset.focusKey = focusKey;
  node.addEventListener("click", action);
  return node;
}
function replaceRows(id, items, render, title, description) {
  const root = $(id);
  const focusKey = root.contains(document.activeElement)
    ? document.activeElement.dataset.focusKey
    : null;
  root.replaceChildren(...items.map(render));
  if (!items.length) root.append(empty(title, description));
  if (focusKey) {
    [...root.querySelectorAll("[data-focus-key]")]
      .find((node) => node.dataset.focusKey === focusKey)
      ?.focus({ preventScroll: true });
  }
}
function go(view) {
  const selected = Object.hasOwn(pages, view) ? view : "overview";
  if (location.hash !== "#" + selected)
    history.pushState(null, "", "#" + selected);
  showView();
  window.scrollTo({ top: 0, behavior: "instant" });
}
function showView() {
  const selected = Object.hasOwn(pages, location.hash.slice(1))
    ? location.hash.slice(1)
    : "overview";
  for (const panel of document.querySelectorAll("[data-panel]"))
    panel.hidden = panel.dataset.panel !== selected;
  for (const link of document.querySelectorAll("[data-view]")) {
    if (link.dataset.view === selected)
      link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  $("page-title").textContent = pages[selected][0];
  $("page-description").textContent = pages[selected][1];
  $("crumb").textContent = pages[selected][0];
  document.title = pages[selected][0] + " · SIEM";
  if (
    selected === "settings" &&
    snapshot?.user.role === "admin" &&
    !adminLoaded
  )
    loadAdmin();
}
function signedOut() {
  epoch++;
  requestController?.abort();
  rerun = false;
  snapshot = null;
  adminLoaded = false;
  detailRecord = null;
  for (const dialog of document.querySelectorAll("dialog[open]"))
    dialog.close();
  $("console").hidden = true;
  $("logout").hidden = true;
  $("login").hidden = false;
  $("account").textContent = "";
  $("admin").hidden = true;
  for (const field of document.querySelectorAll('input[type="password"]'))
    field.value = "";
  message("notice", "");
  message("admin-error", "");
  message("toast", "");
}
function setLiveState(stale = staleData) {
  staleData = stale;
  const node = $("live-state");
  node.textContent = stale
    ? "Data stale"
    : paused
      ? "Live paused"
      : "Live · 5s";
  node.className = "pill " + (stale ? "warn" : paused ? "neutral" : "good");
  $("pause").textContent = paused ? "Resume live" : "Pause live";
  $("pause").setAttribute("aria-pressed", String(paused));
}
function details(kind, record) {
  detailRecord = record;
  $("detail-kind").textContent =
    kind === "incident" ? "SECURITY INCIDENT" : "EVENT RECORD";
  $("detail-title").textContent =
    kind === "incident"
      ? record.title
      : record.event?.action || "Event details";
  $("detail-json").textContent = JSON.stringify(record, null, 2);
  $("detail-feedback").textContent = "";
  const grid = make("div", "", "detail-grid");
  const pairs =
    kind === "incident"
      ? [
          ["Severity", record.severity],
          ["Detected", dateTime(record["@timestamp"])],
          ["Rule", record.rule_id || "—"],
          [
            "Evidence records",
            record.evidence_count ?? record.evidence?.length ?? 0,
          ],
          ["Source", record.affected_asset?.["source.ip"] || "—"],
          ["User", record.affected_asset?.["user.name"] || "—"],
        ]
      : [
          ["Time", dateTime(record["@timestamp"])],
          ["Host", record.host?.name || "—"],
          ["Dataset", record.event?.dataset || "—"],
          ["Outcome", record.event?.outcome || "unknown"],
          ["User", record.user?.name || "—"],
          ["Source IP", record.source?.ip || "—"],
        ];
  for (const [label, value] of pairs) {
    const field = make("div");
    field.append(make("small", label), make("strong", String(value)));
    grid.append(field);
  }
  $("detail-summary").replaceChildren(
    grid,
    make("p", kind === "incident" ? record.description : record.message),
  );
  $("detail-dialog").showModal();
}
function incidentRow(record) {
  const row = make("div", "", "incident-row");
  const body = make("div", "", "incident-body");
  body.append(
    button(
      record.title,
      () => details("incident", record),
      "incident-title",
      record.id,
    ),
  );
  const asset = record.affected_asset || {};
  body.append(
    make(
      "p",
      [record.rule_id, asset["user.name"], asset["source.ip"]]
        .filter(Boolean)
        .join(" · ") || "Select to inspect evidence",
    ),
  );
  row.append(
    pill(record.severity, record.severity === "critical" ? "critical" : "high"),
    body,
    make("span", dateTime(record["@timestamp"]), "incident-time"),
  );
  return row;
}
function renderIncidents() {
  if (!snapshot) return;
  const incidents = snapshot.alerts.filter(
    (item) =>
      $("severity").value === "all" || item.severity === $("severity").value,
  );
  $("alert-summary").textContent =
    `${incidents.length} of ${snapshot.alerts.length} loaded incidents`;
  replaceRows(
    "alert-list",
    incidents,
    incidentRow,
    "No matching incidents",
    "Try another severity, or check back when a detection rule triggers.",
  );
  replaceRows(
    "recent-alerts",
    snapshot.alerts.slice(0, 4),
    incidentRow,
    "No recent incidents",
    "New alerts will appear here when a detection rule triggers.",
  );
}
function shownEvents() {
  if (!snapshot) return [];
  const filtered = snapshot.events.filter(
    (event) =>
      $("outcome").value === "all" ||
      event.event.outcome === $("outcome").value,
  );
  const direction = $("event-sort").value === "oldest" ? 1 : -1;
  return [...filtered].sort(
    (a, b) =>
      direction * (new Date(a["@timestamp"]) - new Date(b["@timestamp"])),
  );
}
function renderEvents() {
  if (!snapshot) return;
  const events = shownEvents();
  const root = $("event-list");
  const focusKey = root.contains(document.activeElement)
    ? document.activeElement.dataset.focusKey
    : null;
  root.replaceChildren();
  $("event-summary").textContent =
    `${events.length} shown / ${snapshot.events.length} loaded${appliedQuery ? " · Search: " + appliedQuery : ""}`;
  $("export-events").disabled = !events.length;
  for (const [index, event] of events.entries()) {
    const row = make("tr");
    const host = make("td", event.host?.name || "—");
    host.append(make("small", event.event.dataset));
    const who = make("td", event.user.name);
    who.append(make("small", event.source.ip));
    const outcome = make("td");
    outcome.append(
      pill(
        event.event.outcome,
        { failure: "bad", success: "good", unknown: "neutral" }[
          event.event.outcome
        ] || "neutral",
      ),
    );
    const description = make("td");
    const snippet = make("span", event.message, "message");
    snippet.title = event.message;
    description.append(snippet);
    const action = make("td");
    action.append(
      button(
        "Inspect ↗",
        () => details("event", event),
        "quiet",
        event.event.id || `${event["@timestamp"]}:${event.host?.name}:${index}`,
      ),
    );
    row.append(
      make("td", dateTime(event["@timestamp"])),
      host,
      make("td", event.event.action),
      outcome,
      who,
      description,
      action,
    );
    root.append(row);
  }
  if (!events.length) {
    const row = make("tr");
    const cell = make("td");
    cell.colSpan = 7;
    cell.append(
      empty(
        "No events to show",
        appliedQuery || $("outcome").value !== "all"
          ? "Clear your search or choose another outcome."
          : "Start a collector to receive new Windows or application events.",
      ),
    );
    row.append(cell);
    root.append(row);
  }
  if (focusKey)
    [...root.querySelectorAll("[data-focus-key]")]
      .find((node) => node.dataset.focusKey === focusKey)
      ?.focus({ preventScroll: true });
}
function operationalRow(title, subtitle, badge, kind = "neutral") {
  const row = make("div", "", "row");
  const copy = make("div", "", "row-copy");
  copy.append(make("strong", title), make("small", subtitle));
  row.append(copy, pill(badge, kind));
  return row;
}
function renderSnapshot(data, loadedQuery) {
  snapshot = data;
  appliedQuery = loadedQuery;
  $("console").hidden = false;
  $("logout").hidden = false;
  $("login").hidden = true;
  $("account").textContent = `${data.user.username} · ${data.user.role}`;
  $("admin").hidden = data.user.role !== "admin";
  $("updated").textContent = "Updated " + dateTime(data.updated_at);
  setLiveState(false);
  const warnings = [
    ...data.errors,
    ...(data.worker_healthy
      ? []
      : ["A delivery worker is unavailable. Check Sources & delivery."]),
  ];
  message("notice", warnings.join(" · "));
  const active = data.collectors.filter((item) => item.online).length;
  for (const [id, value] of [
    ["event-count", data.events_total],
    ["alert-count", data.alerts_total],
    ["failure-count", data.failures],
    ["collector-count", active],
  ])
    $(id).textContent = number(value);
  $("nav-alerts").textContent = number(data.alerts_total);
  $("metric-scope").textContent = appliedQuery
    ? "Filtered by event search"
    : "Last 24 hours";
  $("activity-scope").textContent = appliedQuery
    ? "Hourly volume · search: " + appliedQuery
    : "Hourly volume across the last 24 hours";
  $("chart").replaceChildren();
  const maximum = Math.max(1, ...data.timeline.map((item) => item.doc_count));
  for (const item of data.timeline) {
    const bar = make("div", "", "bar");
    bar.style.height = `${Math.max(2, (item.doc_count / maximum) * 130)}px`;
    bar.title = `${dateTime(item.key)} · ${number(item.doc_count)} events`;
    bar.setAttribute("aria-label", bar.title);
    bar.setAttribute("role", "img");
    $("chart").append(bar);
  }
  if (!data.timeline.length)
    $("chart").append(make("p", "No event volume to display.", "muted"));
  const queues = Object.entries(data.queues);
  const queued = queues.reduce((total, [, value]) => total + value.queued, 0);
  const dead = queues.reduce(
    (total, [, value]) => total + value.dead_letters,
    0,
  );
  const healthy = data.worker_healthy && !dead && !data.errors.length;
  $("health-state").textContent = healthy ? "Healthy" : "Needs attention";
  $("health-state").className = "pill " + (healthy ? "good" : "warn");
  $("health-summary").replaceChildren(
    operationalRow(
      "Delivery workers",
      "Background processing",
      data.worker_healthy ? "Running" : "Unavailable",
      data.worker_healthy ? "good" : "bad",
    ),
    operationalRow("Queued records", "Awaiting delivery", number(queued)),
    operationalRow(
      "Dead letters",
      "Require investigation",
      number(dead),
      dead ? "bad" : "good",
    ),
  );
  renderIncidents();
  renderEvents();
  replaceRows(
    "collectors",
    data.collectors,
    (item) =>
      operationalRow(
        item.host,
        `${number(item.sent)} sent · ${item.status} · ${dateTime(item.timestamp)}`,
        item.online ? "Online" : "Stale",
        item.online ? "good" : "warn",
      ),
    "No collector heartbeats",
    "Enroll a computer in Settings, then start its collector.",
  );
  replaceRows(
    "queues",
    queues,
    ([name, value]) =>
      operationalRow(
        name,
        `${number(value.queued)} queued`,
        `${number(value.dead_letters)} dead letters`,
        value.dead_letters ? "bad" : "neutral",
      ),
    "No queue data",
    "Refresh to retrieve the latest delivery state.",
  );
  const receipts = new Set(data.receipts.map((item) => item.id));
  replaceRows(
    "deliveries",
    data.deliveries,
    (item) =>
      operationalRow(
        item.id,
        dateTime(item.timestamp) + (item.reason ? " · " + item.reason : ""),
        receipts.has(item.id) && item.status === "http_2xx"
          ? "Signature verified"
          : item.status === "http_2xx"
            ? "HTTP 2xx"
            : item.status,
        item.status === "http_2xx" ? "good" : "bad",
      ),
    "No recorded deliveries",
    "A triggered incident sends a webhook. Run the pipeline check to verify the configured receiver.",
  );
  $("onboarding").hidden =
    data.collectors.length > 0 || data.user.role !== "admin";
  showView();
}
async function refresh() {
  if (busy) {
    rerun = true;
    return;
  }
  busy = true;
  $("refresh").disabled = true;
  const currentEpoch = epoch;
  requestController = new AbortController();
  const timeout = setTimeout(() => requestController?.abort(), 15000);
  try {
    const loadedQuery = query;
    const data = await api("snapshot?q=" + encodeURIComponent(loadedQuery), {
      signal: requestController.signal,
    });
    if (currentEpoch !== epoch) return;
    renderSnapshot(data, loadedQuery);
  } catch (error) {
    if (currentEpoch !== epoch) return;
    if (error.status === 401) signedOut();
    else {
      setLiveState(true);
      const value =
        error.name === "AbortError"
          ? "Refresh timed out. Try again."
          : error.message;
      if ($("console").hidden) message("login-error", value);
      else message("notice", `${value} Displayed records may be out of date.`);
    }
  } finally {
    clearTimeout(timeout);
    busy = false;
    $("refresh").disabled = false;
    if (rerun) {
      rerun = false;
      refresh();
    }
  }
}
async function submit(form, work, errorId) {
  const controls = [...form.querySelectorAll("button")];
  if (controls.some((node) => node.disabled)) return;
  form.setAttribute("aria-busy", "true");
  controls.forEach((node) => {
    node.disabled = true;
  });
  try {
    await work();
  } catch (error) {
    message(errorId, error.message || "Request failed. Please retry.");
  } finally {
    form.removeAttribute("aria-busy");
    controls.forEach((node) => {
      node.disabled = false;
    });
  }
}
function confirmChange(title, description, action) {
  const dialog = $("confirm-dialog");
  if (dialog.open) return Promise.resolve(false);
  $("confirm-title").textContent = title;
  $("confirm-message").textContent = description;
  $("confirm-accept").textContent = action;
  dialog.returnValue = "cancel";
  return new Promise((resolve) => {
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "accept"),
      { once: true },
    );
    dialog.showModal();
  });
}
async function loadAdmin() {
  if (adminBusy || snapshot?.user.role !== "admin") return;
  adminBusy = true;
  const currentEpoch = epoch;
  try {
    const data = await api("admin");
    if (currentEpoch !== epoch) return;
    const activeAdmins = data.users.filter(
      (user) => user.enabled && user.role === "admin",
    ).length;
    replaceRows(
      "users",
      data.users,
      (user) => {
        const row = operationalRow(
          user.username,
          user.role,
          user.enabled ? "Enabled" : "Disabled",
          user.enabled ? "good" : "neutral",
        );
        const control = button(
          user.enabled ? "Disable" : "Enable",
          async () => {
            if (
              user.enabled &&
              !(await confirmChange(
                `Disable ${user.username}?`,
                "Their active sessions will be revoked. You can enable the account again later.",
                "Disable account",
              ))
            )
              return;
            adminAction(
              () =>
                api("admin/users/" + encodeURIComponent(user.username), {
                  method: "PATCH",
                  body: JSON.stringify({ enabled: !user.enabled }),
                }),
              "Account updated.",
            );
          },
          user.enabled ? "quiet" : "secondary",
        );
        if (user.enabled && user.role === "admin" && activeAdmins === 1) {
          control.disabled = true;
          control.title = "The last active administrator cannot be disabled.";
        }
        row.append(control);
        return row;
      },
      "No users",
      "Create the first organization account.",
    );
    replaceRows(
      "registered-collectors",
      data.collectors,
      (collector) => {
        const row = operationalRow(
          collector.host,
          collector.id,
          collector.enabled ? "Active" : "Revoked",
          collector.enabled ? "good" : "neutral",
        );
        if (collector.enabled)
          row.append(
            button("Revoke", async () => {
              if (
                !(await confirmChange(
                  `Revoke ${collector.host}?`,
                  "This credential will stop accepting new logs. Reconnecting requires a new enrollment configuration.",
                  "Revoke credential",
                ))
              )
                return;
              adminAction(
                () =>
                  api("admin/collectors/" + encodeURIComponent(collector.id), {
                    method: "DELETE",
                  }),
                "Collector credential revoked.",
              );
            }),
          );
        return row;
      },
      "No enrolled computers",
      "Enroll a hostname to download its unique collector configuration.",
    );
    replaceRows(
      "audit",
      data.audit,
      (item) =>
        operationalRow(
          item.action.replaceAll("_", " "),
          `${item.actor} → ${item.target}`,
          dateTime(item.at),
        ),
      "No access changes",
      "Account and enrollment changes will appear here.",
    );
    adminLoaded = true;
  } catch (error) {
    if (currentEpoch !== epoch) return;
    if (error.status === 401) signedOut();
    else message("admin-error", error.message);
  } finally {
    adminBusy = false;
  }
}
async function adminAction(action, success) {
  try {
    await action();
    message("admin-error", "");
    toast(success);
    adminLoaded = false;
    await loadAdmin();
  } catch (error) {
    if (error.status === 401) signedOut();
    else message("admin-error", error.message);
  }
}
function downloadJson(value, filename) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

$("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submit(
    event.currentTarget,
    async () => {
      epoch++;
      requestController?.abort();
      await api("login", {
        method: "POST",
        body: JSON.stringify({
          username: $("username").value,
          password: $("key").value,
        }),
      });
      $("key").value = "";
      message("login-error", "");
      adminLoaded = false;
      await refresh();
    },
    "login-error",
  );
});
$("logout").addEventListener("click", async () => {
  $("logout").disabled = true;
  try {
    await api("logout", { method: "POST" });
    signedOut();
  } catch (error) {
    message("notice", "Sign out failed. " + error.message);
  } finally {
    $("logout").disabled = false;
  }
});
$("refresh").addEventListener("click", () => {
  refresh();
  if (location.hash === "#settings") {
    adminLoaded = false;
    loadAdmin();
  }
});
$("pause").addEventListener("click", () => {
  paused = !paused;
  setLiveState();
  if (!paused) refresh();
});
$("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  query = $("search").value.trim();
  refresh();
});
$("clear-search").addEventListener("click", () => {
  query = "";
  $("search").value = "";
  $("outcome").value = "all";
  refresh();
});
$("outcome").addEventListener("change", renderEvents);
$("event-sort").addEventListener("change", renderEvents);
$("severity").addEventListener("change", renderIncidents);
$("view-failures").addEventListener("click", () => {
  $("outcome").value = "failure";
  renderEvents();
  go("events");
});
$("export-events").addEventListener("click", () => {
  const events = shownEvents();
  if (!events.length) return;
  downloadJson(
    {
      exported_at: new Date().toISOString(),
      query: appliedQuery,
      outcome: $("outcome").value,
      scope: "Visible rows from the latest 100 loaded events",
      events,
    },
    "siem-events-" + new Date().toISOString().replaceAll(":", "-") + ".json",
  );
  toast(`${events.length} shown events exported.`);
});
$("close-detail").addEventListener("click", () => $("detail-dialog").close());
$("copy-detail").addEventListener("click", async () => {
  if (!detailRecord) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(detailRecord, null, 2));
    $("detail-feedback").textContent = "Record copied.";
  } catch {
    $("detail-feedback").textContent =
      "Clipboard unavailable. Select and copy the full record above.";
    $("detail-json").focus();
  }
});
$("confirm-cancel").addEventListener("click", () =>
  $("confirm-dialog").close("cancel"),
);
$("confirm-accept").addEventListener("click", () =>
  $("confirm-dialog").close("accept"),
);
$("create-user").addEventListener("submit", (event) => {
  event.preventDefault();
  submit(
    event.currentTarget,
    async () => {
      await api("admin/users", {
        method: "POST",
        body: JSON.stringify({
          username: $("new-user").value,
          password: $("new-password").value,
          role: $("new-role").value,
        }),
      });
      $("new-password").value = "";
      message("admin-error", "");
      toast("Account created. Share the initial password privately.");
      adminLoaded = false;
      await loadAdmin();
    },
    "admin-error",
  );
});
$("create-collector").addEventListener("submit", (event) => {
  event.preventDefault();
  submit(
    event.currentTarget,
    async () => {
      const config = await api("admin/collectors", {
        method: "POST",
        body: JSON.stringify({ host: $("new-host").value }),
      });
      downloadJson(config, "collector-" + config.host + ".json");
      message("admin-error", "");
      toast("Configuration downloaded. Keep this credential private.");
      adminLoaded = false;
      await loadAdmin();
    },
    "admin-error",
  );
});
$("change-password").addEventListener("submit", (event) => {
  event.preventDefault();
  submit(
    event.currentTarget,
    async () => {
      await api("password", {
        method: "POST",
        body: JSON.stringify({
          current_password: $("current-password").value,
          new_password: $("changed-password").value,
        }),
      });
      signedOut();
      message(
        "login-error",
        "Password changed. Sign in with your new password.",
      );
    },
    "password-result",
  );
});
for (const node of document.querySelectorAll("[data-go]"))
  node.addEventListener("click", () => go(node.dataset.go));
for (const node of document.querySelectorAll("[data-view]")) {
  node.addEventListener("click", (event) => {
    event.preventDefault();
    go(node.dataset.view);
  });
}
window.addEventListener("hashchange", showView);
window.addEventListener("popstate", showView);
document.addEventListener("keydown", (event) => {
  if (
    event.key !== "/" ||
    event.ctrlKey ||
    event.metaKey ||
    event.altKey ||
    $("console").hidden ||
    document.querySelector("dialog[open]")
  )
    return;
  if (
    ["INPUT", "TEXTAREA", "SELECT"].includes(event.target.tagName) ||
    event.target.isContentEditable
  )
    return;
  event.preventDefault();
  go("events");
  $("search").focus();
});
showView();
refresh();
setInterval(() => {
  if (!paused && !document.hidden && !$("console").hidden) refresh();
}, 5000);
