/* ============================================================
   📊 TenshiGuard Dashboard Live Feed (v3.1)
   Fetches KPI, charts & risk data every 10 seconds
============================================================ */

const API_DASHBOARD = "/api/dashboard/live";
const API_ATRISK = "/api/dashboard/at_risk";
let refreshInterval = 10000; // 10s auto-refresh

document.addEventListener("DOMContentLoaded", () => {
  loadDashboardData();
  setInterval(loadDashboardData, refreshInterval);
});

async function loadDashboardData() {
  try {
    const res = await fetch(API_DASHBOARD);
    const json = await res.json();
    if (json.status !== "ok") throw new Error("Invalid dashboard data");

    updateKPI(json.data.stats);
    renderCharts(json.data.chart_data);
  } catch (err) {
    console.error("Dashboard fetch failed:", err);
  }
}

/* ---------------------------
   📌 Update KPI Cards
--------------------------- */
function updateKPI(stats) {
  const elTotal = document.getElementById("totalDevices");
  const elOnline = document.getElementById("onlineDevices");
  const elOffline = document.getElementById("offlineDevices");
  const elUptime = document.getElementById("uptimePercent");
  const elAtRisk = document.getElementById("atRiskDevices");

  if (!stats) return;

  if (elTotal) elTotal.textContent = stats.total;
  if (elOnline) elOnline.textContent = stats.online;
  if (elOffline) elOffline.textContent = stats.offline;
  if (elUptime) elUptime.textContent = `${stats.uptime_pct}%`;
  if (elAtRisk) {
    elAtRisk.textContent = stats.at_risk;
    elAtRisk.classList.toggle("text-danger", stats.at_risk > 0);
  }
}

/* ---------------------------
   📈 Charts: CPU/MEM + Threats
--------------------------- */
let sysChart, threatChart;

function renderCharts(chartData) {
  if (!chartData) return;
  const ctxSys = document.getElementById("sysChart");
  const ctxThreat = document.getElementById("threatChart");

  const cpu = chartData.cpu || [];
  const mem = chartData.mem || [];
  const timestamps = chartData.timestamps || [];

  const threatLabels = chartData.threatTrend.map(e => e.t);
  const threatValues = chartData.threatTrend.map(e => e.v);

  if (sysChart) sysChart.destroy();
  if (threatChart) threatChart.destroy();

  // System Load Chart
  sysChart = new Chart(ctxSys, {
    type: "line",
    data: {
      labels: timestamps,
      datasets: [
        {
          label: "CPU %",
          data: cpu,
          borderColor: "#00C8FF",
          fill: false,
          tension: 0.3,
        },
        {
          label: "Memory %",
          data: mem,
          borderColor: "#2EA043",
          fill: false,
          tension: 0.3,
        },
      ],
    },
    options: {
      plugins: { legend: { labels: { color: "#E4E8EC" } } },
      scales: {
        x: { ticks: { color: "#9CA3AF" }, grid: { color: "#1E2630" } },
        y: { ticks: { color: "#9CA3AF" }, grid: { color: "#1E2630" } },
      },
    },
  });

  // Threat Trend Chart
  threatChart = new Chart(ctxThreat, {
    type: "bar",
    data: {
      labels: threatLabels,
      datasets: [
        {
          label: "Threat Events",
          data: threatValues,
          backgroundColor: "rgba(248,81,73,0.8)",
          borderRadius: 6,
        },
      ],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9CA3AF" }, grid: { color: "#141A22" } },
        y: { ticks: { color: "#9CA3AF" }, grid: { color: "#1E2630" } },
      },
    },
  });
}
