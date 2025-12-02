// === CPU & Memory Line Charts ===
export function initSystemMetrics(cpuCtx, memCtx) {
  const cpuChart = new Chart(cpuCtx, {
    type: "line",
    data: { labels: [], datasets: [{
      label: "CPU Usage (%)",
      borderColor: "#00bcd4",
      backgroundColor: "rgba(0,188,212,0.2)",
      data: [],
      tension: 0.4,
    }]},
    options: { scales: { y: { beginAtZero: true, max: 100 } } }
  });

  const memChart = new Chart(memCtx, {
    type: "line",
    data: { labels: [], datasets: [{
      label: "Memory Usage (%)",
      borderColor: "#8e44ad",
      backgroundColor: "rgba(142,68,173,0.2)",
      data: [],
      tension: 0.4,
    }]},
    options: { scales: { y: { beginAtZero: true, max: 100 } } }
  });

  return { cpuChart, memChart };
}
