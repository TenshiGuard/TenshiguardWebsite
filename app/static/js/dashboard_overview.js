/* -------------------------------------------------------------
   TenshiGuard Dashboard — Overview Page JS
   Fully cleaned & optimized
--------------------------------------------------------------*/

// -------------------------------------------------------------
//  1)  LOAD SUMMARY  (/api/dashboard/summary)
// -------------------------------------------------------------
async function loadSummary() {
    try {
        const res = await fetch("/api/dashboard/summary");
        if (!res.ok) throw new Error("HTTP " + res.status);

        const data = await res.json();
        if (data.status !== "ok") throw new Error(data.message);

        // Device stats
        setText("total-devices", data.devices.total ?? "-");
        setText("online-devices", data.devices.online ?? "-");
        setText("offline-devices", data.devices.offline ?? "-");

        // Event stats
        setText("events-24h", data.events.last_24h ?? "-");
        setText("failed-24h", data.events.failed_logins_24h ?? "-");

    } catch (err) {
        console.error("Summary load error:", err);
        setText("total-devices", "-");
        setText("online-devices", "-");
        setText("offline-devices", "-");
        setText("events-24h", "-");
        setText("failed-24h", "-");
    }
}



// -------------------------------------------------------------
//  2)  LOAD RECENT EVENTS (/api/dashboard/history)
// -------------------------------------------------------------
async function loadRecentEvents() {
    const body = document.getElementById("recent-events-body");
    if (!body) return;

    try {
        const res = await fetch("/api/dashboard/history?per_page=10");
        if (!res.ok) throw new Error("HTTP " + res.status);

        const data = await res.json();
        if (data.status !== "ok") throw new Error(data.message);

        const items = data.items || [];
        body.innerHTML = "";

        if (!items.length) {
            body.innerHTML = `
                <tr>
                    <td colspan="4" class="text-center text-muted small py-3">
                        No events found.
                    </td>
                </tr>`;
            return;
        }

        items.forEach(ev => {
            const tr = document.createElement("tr");

            tr.innerHTML = `
                <td class="small">${escapeHtml(ev.ts)}</td>
                <td><span class="badge bg-info">${escapeHtml(ev.severity || "")}</span></td>
                <td class="small text-capitalize">${escapeHtml(ev.category || "")}</td>
                <td class="small">${escapeHtml(ev.detail || "")}</td>
            `;

            body.appendChild(tr);
        });

    } catch (err) {
        console.error("Recent events error:", err);
        body.innerHTML = `
            <tr>
                <td colspan="4" class="text-center text-danger small py-3">
                    Error loading events.
                </td>
            </tr>`;
    }
}



// -------------------------------------------------------------
//  3)  LOAD TOP DEVICES  (/api/dashboard/top-devices)
// -------------------------------------------------------------
async function loadTopDevices() {
    const body = document.getElementById("top-devices-body");
    if (!body) return;

    try {
        const res = await fetch("/api/dashboard/top-devices");
        if (!res.ok) throw new Error("HTTP " + res.status);

        const data = await res.json();
        if (data.status !== "ok") throw new Error(data.message);

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

        items.forEach(d => {
            const status = (d.status || "unknown").toLowerCase();
            let badge = `<span class="badge bg-secondary">Unknown</span>`;
            if (status === "online") badge = `<span class="badge bg-success">Online</span>`;
            else if (status === "offline") badge = `<span class="badge bg-danger">Offline</span>`;

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td class="small">${escapeHtml(d.device_name || d.mac || "Unnamed")}</td>
                <td class="small">
                    <span class="badge bg-info text-dark">${d.events ?? 0}</span>
                </td>
                <td class="small text-capitalize">${escapeHtml(d.os || "-")}</td>
                <td class="small">${badge}</td>
            `;
            body.appendChild(tr);
        });

    } catch (err) {
        console.error("Top devices error:", err);
        body.innerHTML = `
            <tr>
                <td colspan="4" class="text-center text-danger small py-3">
                    Error loading devices.
                </td>
            </tr>`;
    }
}



// -------------------------------------------------------------
//  4)  FAILED LOGIN SPARKLINE BADGE
//      (/api/dashboard/failed-logins-trend)
// -------------------------------------------------------------
async function loadTrend() {
    const badge = document.getElementById("trend-badge");
    if (!badge) return;

    try {
        const res = await fetch("/api/dashboard/failed-logins-trend");
        if (!res.ok) throw new Error("HTTP " + res.status);

        const data = await res.json();
        if (data.status !== "ok") throw new Error(data.message);

        const points = data.points || [];
        if (!points.length) {
            badge.className = "badge bg-secondary";
            badge.textContent = "No activity";
            return;
        }

        const values = points.map(p => p.count);
        const spark = values.join(" → ");

        const first = values[0];
        const last = values[values.length - 1];
        let trend = "";
        let color = "secondary";

        if (last > first) {
            trend = "↑ increasing";
            color = "danger";
        } else if (last < first) {
            trend = "↓ decreasing";
            color = "success";
        } else {
            trend = "— stable";
            color = "info";
        }

        badge.className = "badge bg-" + color;
        badge.textContent = `${spark} (${trend})`;

    } catch (err) {
        console.error("Trend load error:", err);
        badge.className = "badge bg-secondary";
        badge.textContent = "Error";
    }
}



// -------------------------------------------------------------
//  5)  REFRESH EVERYTHING
// -------------------------------------------------------------
async function refreshAll() {
    await Promise.all([
        loadSummary(),
        loadRecentEvents(),
        loadTopDevices(),
        loadTrend(),
    ]);
}


// Auto-refresh every 15 seconds
setInterval(refreshAll, 15000);

// Initial load
refreshAll();



// -------------------------------------------------------------
//  Helpers
// -------------------------------------------------------------
function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
