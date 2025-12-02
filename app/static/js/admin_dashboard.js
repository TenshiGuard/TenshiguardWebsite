admin_dashboard.js// static/js/admin_dashboard.js

document.addEventListener("DOMContentLoaded", () => {
  const kpiTotal = document.getElementById("kpi_total_devices");
  const kpiOnline = document.getElementById("kpi_online_devices");
  const kpiOffline = document.getElementById("kpi_offline_devices");
  const kpiEvents24 = document.getElementById("kpi_events_24h");
  const kpiFailed24 = document.getElementById("kpi_failed_24h");

  const historyTbody = document.getElementById("history_tbody");
  const topDevicesTbody = document.getElementById("top_devices_tbody");

  const failedEmpty = document.getElementById("failed_logins_empty");
  const severityEmpty = document.getElementById("severity_empty");
  const osEmpty = document.getElementById("os_empty");

  let chartFailedLogins = null;
  let chartSeverity = null;
  let chartOS = null;

  // ---------- Helpers ----------
  function safeBadge(sev) {
    const s = (sev || "info").toLowerCase();
    const map = {
      critical: "danger",
      high: "danger",
      medium: "warning",
      low: "success",
      info: "secondary",
    };
    return map[s] || "secondary";
  }

  function formatTs(ts) {
    if (!ts) return "-";
    try {
      const d = new Date(ts);
      if (isNaN(d.getTime())) return ts;
      return d.toISOString().replace("T", " ").substring(0, 19);
    } catch {
      return ts;
    }
  }

  function shortDetail(text, max = 80) {
    if (!text) return "";
    if (text.length <= max) return text;
    return text.substring(0, max) + "…";
  }

  // ---------- Fetch: Summary ----------
  async function loadSummary() {
    try {
      const res = await fetch("/api/dashboard/summary");
      if (!res.ok) {
        throw new Error("HTTP " + res.status);
      }
      const data = await res.json();
      if (data.status !== "ok") {
        throw new Error(data.message || "API error");
      }

      const devices = data.devices || {};
      const events = data.events || {};
      const bySev = events.by_severity || {};

      kpiTotal.textContent = devices.total ?? "0";
      kpiOnline.textContent = devices.online ?? "0";
      kpiOffline.textContent = devices.offline ?? "0";
      kpiEvents24.textContent = events.last_24h ?? "0";
      kpiFailed24.textContent = events.failed_logins_24h ?? "0";

      // Build severity chart
      const sevLabels = ["critical", "high", "medium", "low", "info"];
      const sevCounts = sevLabels.map((s) => bySev[s] || 0);

      const hasAny = sevCounts.some((v) => v > 0);
      if (!hasAny) {
        severityEmpty.classList.remove("d-none");
        if (chartSeverity) chartSeverity.destroy();
      } else {
        severityEmpty.classList.add("d-none");

        const ctx = document.getElementById("chart_severity").getContext("2d");
        if (chartSeverity) chartSeverity.destroy();
        chartSeverity = new Chart(ctx, {
          type: "bar",
          data: {
            labels: sevLabels.map((s) => s.toUpperCase()),
            datasets: [
              {
                label: "Events",
                data: sevCounts,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                beginAtZero: true,
                ticks: { precision: 0 },
              },
            },
          },
        });
      }
    } catch (err) {
      console.error("[AdminDashboard] Summary error:", err);
      kpiTotal.textContent = "–";
      kpiOnline.textContent = "–";
      kpiOffline.textContent = "–";
      kpiEvents24.textContent = "–";
      kpiFailed24.textContent = "–";
      severityEmpty.classList.remove("d-none");
    }
  }

  // ---------- Fetch: History ----------
  async function loadHistory() {
    try {
      const res = await fetch("/api/dashboard/history?per_page=10");
      if (!res.ok) {
        throw new Error("HTTP " + res.status);
      }
      const data = await res.json();
      if (data.status !== "ok") {
        throw new Error(data.message || "API error");
      }

      const items = data.items || [];
      historyTbody.innerHTML = "";

      if (!items.length) {
        historyTbody.innerHTML =
          '<tr><td colspan="4" class="text-muted small">No events in the last 24 hours.</td></tr>';
        return;
      }

      items.forEach((ev) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="small text-muted">${formatTs(ev.ts)}</td>
          <td class="small">
            <span class="badge bg-${safeBadge(ev.severity)}">
              ${(ev.severity || "info").toUpperCase()}
            </span>
          </td>
          <td class="small text-capitalize">${ev.category || "-"}</td>
          <td class="small">${shortDetail(ev.detail || "")}</td>
        `;
        historyTbody.appendChild(tr);
      });
    } catch (err) {
      console.error("[AdminDashboard] History error:", err);
      historyTbody.innerHTML =
        '<tr><td colspan="4" class="text-danger small">Failed to load events.</td></tr>';
    }
  }

  // ---------- Fetch: Failed Logins Trend ----------
  async function loadFailedLoginsTrend() {
    try {
      const res = await fetch("/api/dashboard/failed-logins-trend");
      if (!res.ok) {
        throw new Error("HTTP " + res.status);
      }
      const data = await res.json();
      if (data.status !== "ok") {
        throw new Error(data.message || "API error");
      }

      const points = data.points || [];
      const hasAny = points.some((p) => (p.count || 0) > 0);
      const ctx = document.getElementById("chart_failed_logins").getContext("2d");

      if (!hasAny) {
        failedEmpty.classList.remove("d-none");
        if (chartFailedLogins) chartFailedLogins.destroy();
        return;
      }

      failedEmpty.classList.add("d-none");

      const labels = points.map((p) => p.bucket || "");
      const values = points.map((p) => p.count || 0);

      if (chartFailedLogins) chartFailedLogins.destroy();
      chartFailedLogins = new Chart(ctx, {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "Failed logins",
              data: values,
              tension: 0.3,
              fill: true,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              ticks: { precision: 0 },
            },
          },
        },
      });
    } catch (err) {
      console.error("[AdminDashboard] Failed-logins trend error:", err);
      failedEmpty.classList.remove("d-none");
    }
  }

  // ---------- Fetch: Top Devices ----------
  async function loadTopDevicesAndOS() {
    try {
      const res = await fetch("/api/dashboard/top-devices");
      if (!res.ok) {
        throw new Error("HTTP " + res.status);
      }
      const data = await res.json();
      if (data.status !== "ok") {
        throw new Error(data.message || "API error");
      }

      const items = data.items || [];
      topDevicesTbody.innerHTML = "";

      if (!items.length) {
        topDevicesTbody.innerHTML =
          '<tr><td colspan="4" class="text-muted small">No device activity yet.</td></tr>';
        osEmpty.classList.remove("d-none");
        if (chartOS) chartOS.destroy();
        return;
      }

      // Fill table
      items.forEach((d) => {
        const name = d.device_name || d.mac || "Unknown";
        const os = d.os || "Unknown";
        const status = (d.status || "unknown").toLowerCase();
        let badgeClass = "secondary";
        if (status === "online") badgeClass = "success";
        else if (status === "offline") badgeClass = "warning";

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="small">${name}</td>
          <td class="small">${os}</td>
          <td class="small">
            <span class="badge bg-${badgeClass}">${status.toUpperCase()}</span>
          </td>
          <td class="small fw-bold">${d.events ?? 0}</td>
        `;
        topDevicesTbody.appendChild(tr);
      });

      // Build OS distribution from top devices
      const osCounts = {};
      items.forEach((d) => {
        const os = (d.os || "Unknown").toLowerCase();
        osCounts[os] = (osCounts[os] || 0) + 1;
      });

      const osLabels = Object.keys(osCounts);
      const osValues = osLabels.map((k) => osCounts[k]);

      const hasAnyOS = osValues.some((v) => v > 0);
      if (!hasAnyOS) {
        osEmpty.classList.remove("d-none");
        if (chartOS) chartOS.destroy();
        return;
      }

      osEmpty.classList.add("d-none");
      const ctxOS = document.getElementById("chart_os").getContext("2d");
      if (chartOS) chartOS.destroy();
      chartOS = new Chart(ctxOS, {
        type: "doughnut",
        data: {
          labels: osLabels.map((s) => s.toUpperCase()),
          datasets: [
            {
              data: osValues,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
            },
          },
        },
      });
    } catch (err) {
      console.error("[AdminDashboard] Top devices error:", err);
      topDevicesTbody.innerHTML =
        '<tr><td colspan="4" class="text-danger small">Failed to load devices.</td></tr>';
      osEmpty.classList.remove("d-none");
    }
  }

  // ---------- Init ----------
  loadSummary();
  loadHistory();
  loadFailedLoginsTrend();
  loadTopDevicesAndOS();

  // Optional small auto-refresh (every 60s)
  setInterval(() => {
    loadSummary();
    loadFailedLoginsTrend();
    loadTopDevicesAndOS();
  }, 60000);
});
