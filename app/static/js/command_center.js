document.addEventListener("DOMContentLoaded", function () {
    console.log("🚀 Command Center Initialized");

    const feedBody = document.getElementById("live-feed-body");
    const kpiThreats = document.getElementById("kpi-threats");
    const kpiSuspicious = document.getElementById("kpi-suspicious");
    const kpiSignals = document.getElementById("kpi-signals");
    const kpiDevices = document.getElementById("kpi-devices");

    // AI Panel Elements
    const aiPanelEmpty = document.getElementById("ai-panel-empty");
    const aiPanelContent = document.getElementById("ai-panel-content");
    const aiSeverity = document.getElementById("ai-severity");
    const aiTitle = document.getElementById("ai-title");
    const aiTime = document.getElementById("ai-time");
    const aiAnalysis = document.getElementById("ai-analysis");
    const aiMitigation = document.getElementById("ai-mitigation");
    const btnAskAi = document.getElementById("btn-ask-ai");

    let selectedSignal = null;

    // ---------------------------------------------------------
    // 1. Fetch Live Data
    // ---------------------------------------------------------
    function fetchLiveData() {
        fetch("/api/dashboard/ai/latest")
            .then(res => res.json())
            .then(data => {
                if (data.ok) {
                    updateFeed(data.items);
                    updateKPIs(data.items);
                }
            })
            .catch(err => console.error("Error fetching AI data:", err));
    }

    // ---------------------------------------------------------
    // 2. Update Feed Table
    // ---------------------------------------------------------
    function updateFeed(items) {
        if (!items || items.length === 0) {
            feedBody.innerHTML = `<tr><td colspan="5" class="text-center py-3 text-muted">No active threats detected.</td></tr>`;
            return;
        }

        feedBody.innerHTML = "";
        items.forEach((item, index) => {
            const row = document.createElement("tr");
            row.style.cursor = "pointer";
            row.onclick = () => selectSignal(item);

            // Severity Badge
            let badgeClass = "bg-secondary";
            if (item.severity === "critical") badgeClass = "bg-danger";
            else if (item.severity === "high") badgeClass = "bg-warning text-dark";
            else if (item.severity === "medium") badgeClass = "bg-info text-dark";

            row.innerHTML = `
                <td class="ps-3 text-muted small">${item.ts.split(" ")[1]}</td>
                <td><span class="badge ${badgeClass}">${item.severity.toUpperCase()}</span></td>
                <td><span class="text-light">${item.category}</span></td>
                <td class="text-truncate" style="max-width: 250px;">${item.rule}</td>
                <td><button class="btn btn-sm btn-outline-light"><i class="fa-solid fa-chevron-right"></i></button></td>
            `;
            feedBody.appendChild(row);
        });
    }

    // ---------------------------------------------------------
    // 3. Update KPIs (Simple client-side calc for demo)
    // ---------------------------------------------------------
    function updateKPIs(items) {
        const threats = items.filter(i => i.severity === "critical" || i.severity === "high").length;
        const suspicious = items.filter(i => i.severity === "medium").length;

        kpiThreats.innerText = threats;
        kpiSuspicious.innerText = suspicious;
        kpiSignals.innerText = items.length;
        // kpiDevices is fetched from another API usually, leaving static for now or fetch separately
    }

    // ---------------------------------------------------------
    // 4. Select Signal & Show AI Panel
    // ---------------------------------------------------------
    function selectSignal(item) {
        selectedSignal = item;
        aiPanelEmpty.classList.add("d-none");
        aiPanelContent.classList.remove("d-none");

        aiTitle.innerText = item.rule;
        aiTime.innerText = item.ts;
        aiSeverity.innerText = item.severity.toUpperCase();

        // Update badge color
        aiSeverity.className = "badge mb-2";
        if (item.severity === "critical") aiSeverity.classList.add("bg-danger");
        else if (item.severity === "high") aiSeverity.classList.add("bg-warning", "text-dark");
        else aiSeverity.classList.add("bg-info", "text-dark");

        aiAnalysis.innerText = item.detail || "No details available.";

        // Mitigation (mock or from item)
        aiMitigation.innerHTML = `<li>Review logs for ${item.category} activity.</li><li>Isolate affected device if needed.</li>`;
    }

    // ---------------------------------------------------------
    // 5. Ask AI Button
    // ---------------------------------------------------------
    btnAskAi.addEventListener("click", function () {
        if (!selectedSignal) return;

        const originalText = btnAskAi.innerHTML;
        btnAskAi.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...`;
        btnAskAi.disabled = true;

        fetch("/api/dashboard/ai/ask", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                prompt: `Analyze this security event and provide a detailed mitigation plan: ${JSON.stringify(selectedSignal)}`
            })
        })
            .then(res => res.json())
            .then(data => {
                if (data.ok) {
                    aiAnalysis.innerText = data.response;
                } else {
                    aiAnalysis.innerText = "Error: " + data.message;
                }
            })
            .catch(err => {
                aiAnalysis.innerText = "Failed to contact AI service.";
            })
            .finally(() => {
                btnAskAi.innerHTML = originalText;
                btnAskAi.disabled = false;
            });
    });

    // Initial Load & Poll
    fetchLiveData();
    setInterval(fetchLiveData, 5000); // Poll every 5s
});
