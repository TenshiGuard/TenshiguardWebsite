// -----------------------------------------------------------
//  TenshiGuard SOS Alerts & Preferences – Frontend Logic
//  Uses:
//    GET  /api/sos/latest  -> live events for SOS modal
//    GET  /api/sos/prefs   -> current preferences
//    POST /api/sos/prefs   -> update preferences
// -----------------------------------------------------------

const TG_SOS_API_ALERTS = "/api/sos/latest";
const TG_SOS_API_PREFS  = "/api/sos/prefs";

let tgSosLastSnapshotKey = null;   // to detect "new" alerts
let tgSosPollTimer = null;

// -----------------------------------------------------------
//  Toast Helpers (Bootstrap 5)
// -----------------------------------------------------------
function tgEnsureToastContainer() {
  let container = document.getElementById("tg-toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "tg-toast-container";
    container.className = "toast-container position-fixed top-0 end-0 p-3";
    document.body.appendChild(container);
  }
  return container;
}

function tgShowToast(message, variant = "info") {
  const container = tgEnsureToastContainer();
  const toastEl = document.createElement("div");
  toastEl.className = `toast align-items-center text-bg-${
    variant === "error" ? "danger" :
    variant === "success" ? "success" :
    variant === "warning" ? "warning" :
    "secondary"
  } border-0`;
  toastEl.setAttribute("role", "alert");
  toastEl.setAttribute("aria-live", "assertive");
  toastEl.setAttribute("aria-atomic", "true");

  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        ${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  `;

  container.appendChild(toastEl);
  const toast = new bootstrap.Toast(toastEl, { delay: 3500 });
  toast.show();

  toastEl.addEventListener("hidden.bs.toast", () => {
    toastEl.remove();
  });
}

// -----------------------------------------------------------
//  Severity helpers
// -----------------------------------------------------------
function tgSeverityBadge(sevRaw) {
  const sev = (sevRaw || "info").toLowerCase();
  let cls = "secondary";
  if (sev === "low") cls = "success";
  else if (sev === "medium") cls = "warning";
  else if (sev === "high") cls = "danger";
  else if (sev === "critical") cls = "danger";

  return `<span class="badge bg-${cls} text-uppercase">${sev}</span>`;
}

function tgComputeSnapshotKey(alerts) {
  // Build a simple hash-like string from severity + time + detail
  // to detect changes between poll cycles.
  if (!alerts || !alerts.length) return "empty";
  return alerts
    .map(a => `${a.time || ""}|${a.severity || ""}|${a.detail || ""}`)
    .join("::");
}

// -----------------------------------------------------------
//  Render SOS Modal Table
// -----------------------------------------------------------
function tgRenderSosTable(alerts) {
  const tbody = document.getElementById("sos-alerts-body");
  if (!tbody) return;

  tbody.innerHTML = "";

  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center text-muted py-3">
          <i class="fa-regular fa-circle-check me-2"></i>
          No recent SOS alerts in the last 24 hours.
        </td>
      </tr>
    `;
    return;
  }

  alerts.forEach((a) => {
    const when = a.time ? new Date(a.time) : null;
    const timeStr = when && !isNaN(when.valueOf())
      ? when.toLocaleString()
      : (a.time || "—");

    const row = document.createElement("tr");

    // highlight critical / high
    const sev = (a.severity || "").toLowerCase();
    if (sev === "high" || sev === "critical") {
      row.classList.add("table-danger");
    }

    row.innerHTML = `
      <td class="small">${timeStr}</td>
      <td>${tgSeverityBadge(a.severity)}</td>
      <td class="small text-capitalize">${a.category || "general"}</td>
      <td class="small">${a.action || ""}</td>
      <td class="small font-monospace">${a.mac || ""}</td>
      <td>
        <div class="fw-semibold small">${a.detail || "Security event"}</div>
        ${
          a.mitigation
            ? `<div class="text-muted small"><i class="fa-solid fa-lightbulb me-1"></i>${a.mitigation}</div>`
            : ""
        }
      </td>
    `;
    tbody.appendChild(row);
  });
}

// -----------------------------------------------------------
//  Fetch Latest Alerts
// -----------------------------------------------------------
async function tgFetchLatestAlerts(showErrors = false) {
  try {
    const res = await fetch(TG_SOS_API_ALERTS, {
      headers: { "Accept": "application/json" }
    });

    if (!res.ok) {
      if (showErrors) {
        tgShowToast(`SOS API error: ${res.status}`, "error");
      }
      return null;
    }

    const data = await res.json();
    if (data.status !== "ok") {
      if (showErrors) {
        tgShowToast(data.message || "Failed to load SOS alerts.", "error");
      }
      return null;
    }

    const alerts = data.alerts || [];
    const newKey = tgComputeSnapshotKey(alerts);

    // detect new items
    const isNew = tgSosLastSnapshotKey && newKey !== tgSosLastSnapshotKey;
    tgSosLastSnapshotKey = newKey;

    if (isNew) {
      // show toast only if there is at least one high/critical
      const hasHigh = alerts.some(a => {
        const s = (a.severity || "").toLowerCase();
        return s === "high" || s === "critical";
      });
      if (hasHigh) {
        tgShowToast("New high severity security alerts detected.", "warning");
      }
    }

    tgRenderSosTable(alerts);
    return alerts;

  } catch (err) {
    console.error("[SOS] fetch latest error:", err);
    if (showErrors) {
      tgShowToast("Unable to reach SOS alerts API.", "error");
    }
    return null;
  }
}

// -----------------------------------------------------------
//  Polling manager
// -----------------------------------------------------------
function tgStartSosPolling() {
  if (tgSosPollTimer) {
    clearInterval(tgSosPollTimer);
  }

  // initial load (quiet)
  tgFetchLatestAlerts(false);

  // poll every ~10s with a little jitter
  tgSosPollTimer = setInterval(() => {
    tgFetchLatestAlerts(false);
  }, 10000 + Math.floor(Math.random() * 2000));
}

// -----------------------------------------------------------
//  SOS Preferences (modal in base_dashboard, optional page)
// -----------------------------------------------------------
async function tgLoadSosPrefs() {
  try {
    const res = await fetch(TG_SOS_API_PREFS, {
      headers: { "Accept": "application/json" }
    });
    if (!res.ok) {
      tgShowToast(`Failed to load SOS preferences (${res.status})`, "error");
      return;
    }
    const data = await res.json();

    const minSev = document.getElementById("prefMinSeverity");
    const emailOn = document.getElementById("prefEmailEnabled");
    const smsOn = document.getElementById("prefSmsEnabled");

    if (minSev && data.min_severity) {
      minSev.value = data.min_severity;
    }
    if (emailOn) {
      emailOn.checked = !!data.email_enabled;
    }
    if (smsOn) {
      smsOn.checked = !!data.sms_enabled;
    }

  } catch (err) {
    console.error("[SOS] load prefs error:", err);
    tgShowToast("Error loading SOS preferences.", "error");
  }
}

async function tgSaveSosPrefs(ev) {
  if (ev) ev.preventDefault();

  const minSev = document.getElementById("prefMinSeverity");
  const emailOn = document.getElementById("prefEmailEnabled");
  const smsOn = document.getElementById("prefSmsEnabled");

  const payload = {
    min_severity: minSev ? minSev.value : "high",
    email_enabled: emailOn ? emailOn.checked : true,
    sms_enabled: smsOn ? smsOn.checked : false
  };

  try {
    const res = await fetch(TG_SOS_API_PREFS, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      tgShowToast(`Failed to save SOS preferences (${res.status})`, "error");
      return;
    }
    tgShowToast("SOS preferences updated.", "success");

  } catch (err) {
    console.error("[SOS] save prefs error:", err);
    tgShowToast("Error saving SOS preferences.", "error");
  }
}

// -----------------------------------------------------------
//  Auto-wire on DOM ready
// -----------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const modal = document.getElementById("modalSOS");
  const refreshBtn = document.getElementById("refresh-alerts-btn");
  const prefsModal = document.getElementById("modalSOSPrefs");
  const prefsForm = document.getElementById("sosPrefsForm");

  // If SOS modal not present, nothing to do (e.g. basic plan / user view)
  if (!modal) return;

  // Start polling as soon as user is on any dashboard page with SOS available
  tgStartSosPolling();

  // When modal is opened → refresh immediately (and show errors if any)
  modal.addEventListener("shown.bs.modal", () => {
    tgFetchLatestAlerts(true);
  });

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      tgFetchLatestAlerts(true);
    });
  }

  if (prefsModal) {
    prefsModal.addEventListener("shown.bs.modal", () => {
      tgLoadSosPrefs();
    });
  }

  if (prefsForm) {
    prefsForm.addEventListener("submit", tgSaveSosPrefs);
  }
});
