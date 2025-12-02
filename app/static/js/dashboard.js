// app/static/js/dashboard.js

document.addEventListener("DOMContentLoaded", () => {
  const charts = {
    failedLogins: null,
    severity: null,
    os: null,
  };

  // -------------------------- helpers --------------------------

  function setText(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function getCanvasContext(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    return el.getContext && el.getContext("2d");
  }

  function hasChartJs() {
    if (!window.Chart) {
      console.warn("Chart.js not found. Charts will not render.");
      return false;
    }
    return true;
  }

  function getCssVar(name) {
    const v = getComputedStyle(document.documentElement)
      .getPropertyValue(name)
      .trim();
    return v || null;
  }

  function getThemeColors() {
    const root = document.documentElement;
    const isLight = root.getAttribute("data-theme") === "light";

    const text = getCssVar("--text-main") || (isLight ? "#142033" : "#dee4f0");
    const grid =
      getCssVar("--grid-line") ||
      (isLight ? "rgba(0,0,0,0.12)" : "rgba(255,255,255,0.09)");
    const accent =
      getCssVar("--text-accent") || (isLight ? "#005fed" : "#00d0ff");

    const c1 = getCssVar("--chart-1") || accent;
    const c2 = getCssVar("--chart-2") || "#00e6b8";
    const c3 = getCssVar("--chart-3") || "#ff4b6e";
    const c4 = getCssVar("--chart-4") || "#ffb600";
    const c5 = getCssVar("--chart-5") || "#8892ff";

    return {
      text,
      grid,
      accent,
      doughnut: [c1, c2, c3, c4, c5],
      bar: c1,
      line: accent,
    };
  }

  function destroyCharts() {
    Object.keys(charts).forEach((k) => {
      if (charts[k]) {
        charts[k].destroy();
        charts[k] = null;
      }
    });
  }

  // ----------------- 1) summary + severity chart ---------------

  async function loadSummaryAndSeverity() {
    try {
      const res = await fetch("/api/dashboard/summary");
      if (!res.ok) throw new Error("HTTP " + res.status);

      const data = await res.json();
      if (data.status !== "ok") throw new Error(data.message || "API error");

      const dev = data.devices || {};
      const ev = data.events || {};
      const bySev = ev.by_severity || {};

      // metric cards
      setText("metric-total-devices", dev.total ?? 0);
      setText("metric-online-devices", dev.online ?? 0);
      setText("metric-offline-devices", dev.offline ?? 0);
      setText("metric-last24-events", ev.last_24h ?? 0);
      setText("metric-failed-logins", ev.failed_logins_24h ?? 0);

      // severity chart
      if (hasChartJs()) {
        const ctx = getCanvasContext("chart-severity");
        if (ctx) {
          const labels = ["critical", "high", "medium", "low", "info"];
          const counts = labels.map((s) => bySev[s] || 0);
          const nonZero = counts.some((c) => c > 0);
          if (!nonZero) {
            renderEmptySeverityChart(ctx);
          } else {
            renderSeverityChart(ctx, labels, counts);
          }
        }
      }
    } catch (err) {
      console.error("Summary load error:", err);
      setText("metric-total-devices", "—");
      setText("metric-online-devices", "—");
      setText("metric-offline-devices", "—");
      setText("metric-last24-events", "—");
      setText("metric-failed-logins", "—");
    }
  }

  // ------------- 2) failed login trend + badge -----------------

  async function loadTrendAndChart() {
    const badge = document.getElementById("trend-badge");

    try {
      const res = await fetch("/api/dashboard/failed-logins-trend");
      if (!res.ok) throw new Error("HTTP " + res.status);

      const data = await res.json();
      if (data.status !== "ok") throw new Error(data.message || "API error");

      const points = data.points || [];

      if (badge) {
        if (!points.length) {
          badge.className = "trend-badge badge bg-secondary";
          badge.textContent = "No activity";
        } else {
          const values = points.map((p) => p.count || 0);
          const spark = values.join(" → ");
          const first = values[0];
          const last = values[values.length - 1];

          let trendText = "";
          let color = "secondary";

          if (last > first) {
            trendText = "↑ increasing";
            color = "danger";
          } else if (last < first) {
            trendText = "↓ decreasing";
            color = "success";
          } else {
            trendText = "— stable";
            color = "info";
          }

          badge.className = "trend-badge badge bg-" + color;
          badge.textContent = `${spark} (${trendText})`;
        }
      }

      if (hasChartJs()) {
        const ctx = getCanvasContext("chart-failed-logins");
        if (ctx) {
          renderFailedLoginsChart(ctx, points || []);
        }
      }
    } catch (err) {
      console.error("Trend load error:", err);
      if (badge) {
        badge.className = "trend-badge badge bg-secondary";
        badge.textContent = "Error";
      }
    }
  }

  // ----------------- 3) top devices + OS chart -----------------

  async function loadTopDevices() {
    const body = document.getElementById("top-devices-body");
    if (!body) return;

    try {
      const res = await fetch("/api/dashboard/top-devices");
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      if (data.status !== "ok") throw new Error(data.message || "API error");

      const items = data.items || [];
      body.innerHTML = "";

      if (!items.length) {
        body.innerHTML = `
          <tr>
            <td colspan="4" class="text-center text-muted small py-3">
              No active devices yet.
            </td>
          </tr>`;
        return;
      }

      items.forEach((d) => {
        const tr = document.createElement("tr");

        const status = (d.status || "unknown").toLowerCase();
        let statusBadge = `<span class="badge bg-secondary">Unknown</span>`;
        if (status === "online") {
          statusBadge = `<span class="badge bg-success">Online</span>`;
        } else if (status === "offline") {
          statusBadge = `<span class="badge bg-danger">Offline</span>`;
        }

        tr.innerHTML = `
          <td class="small">
            ${escapeHtml(d.device_name || d.mac || "Unnamed")}
          </td>
          <td class="small">
            <span class="badge bg-info text-dark">${d.events ?? 0}</span>
          </td>
          <td class="small text-capitalize">
            ${escapeHtml(d.os || "-")}
          </td>
          <td class="small">
            ${statusBadge}
          </td>
        `;
        body.appendChild(tr);
      });
    } catch (err) {
      console.error("Top devices load error:", err);
      body.innerHTML = `
        <tr>
          <td colspan="4" class="text-center text-danger small py-3">
            Error loading devices: ${escapeHtml(String(err))}
          </td>
        </tr>`;
    }

    // OS chart uses same data
    if (hasChartJs()) {
      const ctx = getCanvasContext("chart-os");
      if (ctx) {
        try {
          const res = await fetch("/api/dashboard/top-devices");
          if (!res.ok) throw new Error("HTTP " + res.status);
          const data = await res.json();
          if (data.status !== "ok") throw new Error(data.message || "API error");
          const items = data.items || [];
          renderOsChart(ctx, items);
        } catch (err) {
          console.error("OS chart load error:", err);
        }
      }
    }
  }

  // ----------------- 4) latest events table --------------------

  async function loadLatestEvents() {
    const body = document.getElementById("latest-events-body");
    if (!body) return;

    try {
      const res = await fetch("/api/dashboard/history?per_page=10");
      if (!res.ok) throw new Error("HTTP " + res.status);
      const data = await res.json();
      if (data.status !== "ok") throw new Error(data.message || "API error");

      const items = data.items || [];
      body.innerHTML = "";

      if (!items.length) {
        body.innerHTML = `
          <tr>
            <td colspan="4" class="text-center text-muted small py-3">
              No recent events.
            </td>
          </tr>`;
        return;
      }

      items.forEach((ev) => {
        const tr = document.createElement("tr");

        const sev = (ev.severity || "info").toLowerCase();
        const sevColor =
          {
            critical: "danger",
            high: "warning",
            medium: "info",
            low: "success",
            info: "secondary",
          }[sev] || "secondary";

        tr.innerHTML = `
          <td class="small text-muted">
            ${escapeHtml(ev.ts || "-")}
          </td>
          <td class="small">
            <span class="badge bg-${sevColor} text-uppercase">
              ${escapeHtml((ev.severity || "INFO").toString())}
            </span>
          </td>
          <td class="small text-capitalize">
            ${escapeHtml(ev.category || "-")}
          </td>
          <td class="small">
            ${escapeHtml(ev.detail || "")}
          </td>
        `;
        body.appendChild(tr);
      });
    } catch (err) {
      console.error("Latest events load error:", err);
      body.innerHTML = `
        <tr>
          <td colspan="4" class="text-center text-danger small py-3">
            Error loading events: ${escapeHtml(String(err))}
          </td>
        </tr>`;
    }
  }

  // ===================== chart renderers =======================

  function renderFailedLoginsChart(ctx, points) {
    if (!hasChartJs()) return;

    const labels = points.map((p) => p.bucket || "");
    const values = points.map((p) => p.count || 0);
    const theme = getThemeColors();

    if (charts.failedLogins) {
      charts.failedLogins.data.labels = labels;
      charts.failedLogins.data.datasets[0].data = values;
      charts.failedLogins.data.datasets[0].borderColor = theme.line;
      charts.failedLogins.update();
      return;
    }

    charts.failedLogins = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Failed Logins",
            data: values,
            tension: 0.3,
            borderWidth: 2,
            borderColor: theme.line,
            pointBackgroundColor: theme.line,
            fill: false,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: theme.text },
            grid: { color: theme.grid },
          },
          y: {
            beginAtZero: true,
            ticks: { color: theme.text },
            grid: { color: theme.grid },
          },
        },
        plugins: {
          legend: {
            labels: { color: theme.text },
          },
        },
      },
    });
  }

  function renderSeverityChart(ctx, labels, counts) {
    if (!hasChartJs()) return;

    const theme = getThemeColors();

    if (charts.severity) {
      charts.severity.data.labels = labels;
      charts.severity.data.datasets[0].data = counts;
      charts.severity.data.datasets[0].backgroundColor = theme.doughnut;
      charts.severity.update();
      return;
    }

    charts.severity = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [
          {
            data: counts,
            backgroundColor: theme.doughnut,
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: theme.text },
          },
        },
      },
    });
  }

  function renderEmptySeverityChart(ctx) {
    renderSeverityChart(ctx, ["No data"], [1]);
  }

  function renderOsChart(ctx, devices) {
    if (!hasChartJs()) return;

    const osCounts = {};
    devices.forEach((d) => {
      const osName = (d.os || "unknown").toLowerCase();
      osCounts[osName] = (osCounts[osName] || 0) + 1;
    });

    const labels = Object.keys(osCounts);
    const values = labels.map((k) => osCounts[k]);
    const theme = getThemeColors();

    if (charts.os) {
      charts.os.data.labels = labels;
      charts.os.data.datasets[0].data = values;
      charts.os.data.datasets[0].backgroundColor = theme.bar;
      charts.os.update();
      return;
    }

    charts.os = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [
          {
            label: "Devices",
            data: values,
            backgroundColor: theme.bar,
            borderColor: theme.bar,
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: theme.text },
            grid: { color: theme.grid },
          },
          y: {
            beginAtZero: true,
            ticks: { color: theme.text },
            grid: { color: theme.grid },
          },
        },
        plugins: {
          legend: {
            labels: { color: theme.text },
          },
        },
      },
    });
  }

  // ==================== bootstrapping ==========================

  function refreshAll() {
    loadSummaryAndSeverity();
    loadTrendAndChart();
    loadTopDevices();
    loadLatestEvents();
  }

  refreshAll();

  setInterval(loadSummaryAndSeverity, 60000);
  setInterval(loadTrendAndChart, 60000);
  setInterval(loadTopDevices, 60000);
  setInterval(loadLatestEvents, 60000);

  // When user clicks the theme toggle, wait a tick then
  // destroy + rebuild charts so they pick the new colors.
  const themeToggleBtn = document.getElementById("themeToggle");
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", () => {
      setTimeout(() => {
        destroyCharts();
        refreshAll();
      }, 80);
    });
  }
});
