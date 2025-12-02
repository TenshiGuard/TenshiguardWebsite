// === Online vs Offline Doughnut Chart ===
export function initDeviceStatus(ctx) {
  return new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Online", "Offline"],
      datasets: [{
        data: [0, 0],
        backgroundColor: ["#2ecc71", "#e74c3c"],
        borderWidth: 2
      }]
    },
    options: { plugins: { legend: { position: "bottom" } } }
  });
}
