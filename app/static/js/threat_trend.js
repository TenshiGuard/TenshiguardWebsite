// === Threat Activity Line Chart ===
export function initThreatTrend(ctx) {
  return new Chart(ctx, {
    type: "line",
    data: { labels: [], datasets: [{
      label: "Threat Activity Level",
      borderColor: "#f39c12",
      backgroundColor: "rgba(243,156,18,0.3)",
      data: [],
      tension: 0.4
    }]},
    options: { scales: { y: { beginAtZero: true, max: 5 } } }
  });
}
