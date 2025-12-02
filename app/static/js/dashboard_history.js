/*
  🕒 TenshiGuard Device History Viewer
  Triggered when "View History" modal is opened.
*/

document.addEventListener("DOMContentLoaded", () => {
  const modal = document.getElementById("historyModal");
  const canvas = document.getElementById("historyChart");
  let historyChart = null;

  // Helper to format timestamps nicely
  function formatTime(ts) {
    const date = new Date(ts);
    return `${date.getHours()}:${String(date.getMinutes()).padStart(2, "0")}`;
  }

  // Fetch and render device history data
  async function loadHistory() {
    try {
      const res = await fetch("/api/dashboard/history");
      const j = await res.json();
      if (j.status !== "ok") {
        console.warn("No history data available");
        return;
      }

      const d = j.data;
      const labels = d.timestamps.map(formatTime);

      if (historyChart) historyChart.destroy();

      historyChart = new Chart(canvas, {
        type: "line",
        data: {
          labels,
          datasets: [
            {
              label: "CPU Usage (%)",
              data: d.cpu,
              borderColor: "#00bcd4",
              backgroundColor: "rgba(0,188,212,0.2)",
              borderWidth: 2,
              tension: 0.3,
            },
            {
              label: "Memory Usage (%)",
              data: d.mem,
              borderColor: "#9b59b6",
              backgroundColor: "rgba(155,89,182,0.2)",
              borderWidth: 2,
              tension: 0.3,
            },
          ],
        },
        options: {
          responsive: true,
          animation: { duration: 800 },
          scales: {
            y: {
              beginAtZero: true,
              max: 100,
              ticks: { color: "#fff" },
              grid: { color: "rgba(255,255,255,0.1)" },
            },
            x: {
              ticks: { color: "#fff" },
              grid: { color: "rgba(255,255,255,0.05)" },
            },
          },
          plugins: {
            legend: { labels: { color: "#fff" } },
          },
        },
      });
    } catch (err) {
      console.error("⚠️ Failed to load history:", err);
    }
  }

  // When the modal is shown, load data
  modal.addEventListener("shown.bs.modal", () => {
    loadHistory();
  });
});
