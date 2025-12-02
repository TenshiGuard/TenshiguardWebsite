document.addEventListener("DOMContentLoaded", () => {
  const tbody = document.getElementById("recent-events");
  if (!tbody) return;
  async function loadEvents() {
    const res = await fetch("/api/events/live?limit=50");
    const j = await res.json();
    if (j.status !== "ok") return;
    tbody.innerHTML = j.events.map(ev => `
      <tr>
        <td>${new Date(ev.ts).toLocaleString()}</td>
        <td>${ev.category}</td>
        <td>${ev.action}</td>
        <td><span class="badge ${sevBadge(ev.severity)}">${ev.severity}</span></td>
        <td>
          <div class="fw-semibold">${ev.title}</div>
          <div class="small text-muted">${ev.detail}</div>
          <div class="small text-warning mt-1">Mitigation: ${ev.mitigation}</div>
        </td>
      </tr>
    `).join("");
  }
  function sevBadge(s){
    s=(s||"").toLowerCase();
    return s=="critical"?"bg-danger":s=="high"?"bg-warning text-dark":s=="medium"?"bg-info text-dark":"bg-secondary";
  }
  loadEvents(); setInterval(loadEvents, 10000);
});
