// app/static/js/ai_dashboard.js
// ======================================================
// TenshiGuard — AI Dashboard Front-End (Phase 2.5)
// Talks to: GET /api/dashboard/ai/latest
// Expects JSON: { ok: true, items: [ ... ] }
// Each item will later follow a unified shape, but for now
// we handle it defensively.
// ======================================================

async function tgFetchAiLatest() {
  const loadingEl = document.getElementById("ai-loading");
  const emptyEl = document.getElementById("ai-empty");
  const errorEl = document.getElementById("ai-error");
  const tableWrapperEl = document.getElementById("ai-table-wrapper");
  const tableBodyEl = document.getElementById("ai-table-body");
  const summaryRowEl = document.getElementById("ai-summary-row");

  if (!loadingEl || !tableBodyEl) {
    // AI panel not on this page
    return;
  }

  // Reset states
  loadingEl.style.display = "block";
  emptyEl.style.display = "none";
  errorEl.style.display = "none";
  tableWrapperEl.style.display = "none";
  summaryRowEl.style.display = "none";
  tableBodyEl.innerHTML = "";

  try {
    const resp = await fetch("/api/dashboard/ai/latest", {
      headers: {
        "Accept": "application/json"
        // NOTE: when called from browser while logged-in,
        // cookies provide auth. No API key needed here.
      }
    });

    if (!resp.ok) {
      throw new Error("HTTP " + resp.status);
    }

    const data = await resp.json();

    // We currently expect: { ok: true, items: [...] }
    const ok = data.ok === true;
    const items = Array.isArray(data.items) ? data.items : [];

    if (!ok) {
      throw new Error("Backend responded with ok = false");
    }

    if (items.length === 0) {
      loadingEl.style.display = "none";
      emptyEl.style.display = "block";
      return;
    }

    // Compute simple counts by severity
    let total = items.length;
    let highCount = 0;
    let medLowCount = 0;

    items.forEach((item) => {
      const sev = (item.severity || "").toLowerCase();
      if (sev === "high" || sev === "critical") {
        highCount++;
      } else {
        medLowCount++;
      }
    });

    // Update summary widgets
    const totalEl = document.getElementById("ai-total-count");
    const highEl = document.getElementById("ai-high-count");
    const medLowEl = document.getElementById("ai-medlow-count");
    const lastUpdatedEl = document.getElementById("ai-last-updated");

    if (totalEl) totalEl.textContent = total;
    if (highEl) highEl.textContent = highCount;
    if (medLowEl) medLowEl.textContent = medLowCount;
    if (lastUpdatedEl) {
      const now = new Date();
      lastUpdatedEl.textContent = now.toISOString();
    }

    summaryRowEl.style.display = "flex";

    // Fill the table
    items.forEach((item) => {
      // We design a future-proof "contract" of item fields:
      // - kind: "file" | "process" | "network" | "behavior"
      // - severity: "low" | "medium" | "high" | "critical"
      // - score: 0–100
      // - device_name (optional)
      // - summary (optional string)
      // - created_at (ISO string)
      //
      // But to avoid breakage today, we fall back if fields are missing.

      const kind = item.category || "n/a";
      const severity = item.severity || "unknown";
      const score = item.risk_score || 0;
      const deviceName = item.device_name || "–";

      // Combine rule name and detail for summary
      let summary = item.rule_name || "";
      if (item.detail) {
        summary += ` — ${item.detail}`;
      }
      if (!summary) summary = "No details provided";

      const createdAt = item.ts || "–";

      const tr = document.createElement("tr");

      tr.innerHTML = `
        <td class="text-nowrap">${kind}</td>
        <td class="text-nowrap">
          <span class="badge bg-${severityToBootstrap(severity)}">
            ${severity}
          </span>
        </td>
        <td>${score}</td>
        <td class="text-nowrap">${deviceName}</td>
        <td>${escapeHtml(summary)}</td>
        <td class="text-nowrap small">${createdAt}</td>
      `;

      tableBodyEl.appendChild(tr);
    });

    loadingEl.style.display = "none";
    tableWrapperEl.style.display = "block";
  } catch (err) {
    console.error("[AI Dashboard] Failed to load latest:", err);
    loadingEl.style.display = "none";
    errorEl.style.display = "block";
  }
}

// ------------------------------------------------------
// Small helpers: severity -> bootstrap badge class, HTML escape
// ------------------------------------------------------
function severityToBootstrap(sev) {
  sev = (sev || "").toLowerCase();
  if (sev === "critical" || sev === "high") return "danger";
  if (sev === "medium") return "warning";
  if (sev === "low") return "info";
  return "secondary";
}

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ------------------------------------------------------
// Wire up on page load
// ------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const refreshBtn = document.getElementById("ai-refresh-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      tgFetchAiLatest();
    });
  }

  // Auto-load once when admin dashboard is opened
  tgFetchAiLatest();
});
