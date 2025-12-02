// app/static/js/ai/ai_insights.js

document.addEventListener("DOMContentLoaded", () => {
  loadAISummary();
  loadAILatest();

  const btn = document.getElementById("ai-refresh-btn");
  if (btn) {
    btn.addEventListener("click", () => {
      loadAISummary();
      loadAILatest();
    });
  }
});

function loadAISummary() {
  fetch("/api/dashboard/ai/summary")
    .then((r) => r.json())
    .then((data) => {
      if (!data.ok) return;
      const d = data.data || {};

      setText("ai-total-signals", d.total ?? "0");
      setText("ai-high-24h", d.high24 ?? "0");
      setText("ai-risk-max", d.max_risk ?? "0");
      setText("ai-risk-avg", d.avg_risk ?? "0");
    })
    .catch((err) => {
      console.error("AI summary error:", err);
    });
}

function loadAILatest() {
  fetch("/api/dashboard/ai/latest")
    .then((r) => r.json())
    .then((data) => {
      const tbody = document.getElementById("ai-latest-body");
      const meta = document.getElementById("ai-latest-meta");
      if (!tbody) return;

      tbody.innerHTML = "";

      if (!data.ok || !data.items || data.items.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="5" class="text-center text-muted py-3">
              No AI signals yet. Seed or wait for agent data.
            </td>
          </tr>`;
        if (meta) {
          meta.textContent = "No AI events returned";
        }
        return;
      }

      data.items.forEach((item) => {
        const tr = document.createElement("tr");

        const sevClass = severityClass(item.severity);

        tr.innerHTML = `
          <td>${escapeHtml(item.ts || "-")}</td>
          <td>${escapeHtml(item.category || "-")}</td>
          <td><span class="badge ${sevClass}">${escapeHtml(
          (item.severity || "").toUpperCase()
        )}</span></td>
          <td>${escapeHtml(item.rule || "-")}</td>
          <td>${escapeHtml(item.detail || "-")}</td>
        `;

        tbody.appendChild(tr);
      });

      if (meta) {
        meta.textContent = `${data.items.length} latest AI events`;
      }
    })
    .catch((err) => {
      console.error("AI latest error:", err);
    });
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function severityClass(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical") return "bg-danger";
  if (s === "high") return "bg-warning text-dark";
  if (s === "medium") return "bg-info text-dark";
  if (s === "low") return "bg-secondary";
  return "bg-dark";
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
