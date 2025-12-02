# The Core Idea Behind the SOS Feature

Modern security dashboards generate thousands of events — file creations, process executions, network connections, logins, and AI detections. Most of these events are noise. Admins don’t have time to manually filter them.

The purpose of the SOS system is to solve this exact problem:

**SOS identifies the few events out of thousands that truly matter — the ones that indicate a real attack — and immediately alerts the administrator.**

SOS is the human-facing final layer of the entire TenshiGuard detection pipeline.

---

## 1. It Extracts the “Critical Few” From the “Trivial Many”

Every agent generates:
*   Normal file operations
*   Normal processes
*   Clean outbound connections
*   Regular auth activity
*   Routine system behavior

These SHOULD NOT overwhelm the admin.

SOS fires only for real threats, such as:
*   Brute-force patterns
*   Malware execution
*   Credential dumping
*   Ransomware behavior
*   High-risk outbound connections
*   Multi-step correlated attacks
*   Incident escalation

**Philosophy:** Turn 10,000 raw events into 5 meaningful alerts.

---

## 2. It Converts Technical Detections Into Human Understanding

Agents and AI produce signals like:
*   `psexec.exe executed with parent winlogon`
*   `Outbound connection to suspicious IP: 185.199.111.153:4444`
*   `entropy spike in file system`

These are technical. SOS turns them into simple, digestible messages:
*   **“Potential lateral movement detected.”**
*   **“Endpoint connected to a high-risk IP.”**
*   **“Ransomware-like encryption patterns observed.”**

This bridges the gap between machine output and human decision-making.

---

## 3. SOS Provides a Single, Central Pane of Glass for Urgent Issues

Security admins are human — they don’t have time to scroll through logs, trends, AI feeds, or correlation data every second.

SOS gives them one place to check:
*   **If something is here, it’s serious.**
*   **If it’s not here, you’re safe.**

This is why the `/dashboard/alerts` page exists — it is the single truth source for urgent activity.

---

## 4. It Ensures No Critical Event Is Lost in the Noise

Even if AI detects something, or correlation identifies a pattern, the admin might miss it in the large dashboards.

SOS ensures: **Every high-risk event triggers a real-time alert that cannot be ignored.**

This prevents:
*   Silent compromise
*   Undetected lateral movement
*   Ransomware dwell time
*   Privileged account abuse
*   Missed early indicators

---

## 5. It Creates Accountability and Response Readiness

SOS is not just “alerting.” It is part of the Incident Response workflow.

When SOS fires:
1.  Threat is logged
2.  Administrator becomes aware
3.  Response begins
4.  Evidence is preserved
5.  Incidents are linked

SOS is the bridge between “detection” and “response.”

---

## 6. It Allows Future Multi-Channel Escalations (Phase 4+)

The long-term vision behind SOS includes:
*   Email alerts (Implemented)
*   SMS alerts (Implemented)
*   Global notifications
*   Sector-level broadcast alerts
*   Integration with IR playbooks

This elevates TenshiGuard from a tool to a full alerting & response system.

---

## 7. It Builds Trust and Transparency

A customer wants to know:
*   “If something bad happens, will I be notified immediately?”
*   “Will I ever miss a critical event?”
*   “Will the system catch real attacks?”

SOS answers those questions confidently.

---

# Business Justification for Investors

**Problem:**
Security teams are drowning in "Alert Fatigue." The average SOC analyst sees 1,000+ alerts per day, leading to burnout and missed threats (e.g., the Target breach was detected but ignored).

**Solution:**
TenshiGuard SOS is an intelligent filtration layer that reduces alert volume by 99% while increasing signal fidelity. It doesn't just show data; it demands attention only when necessary.

**ROI:**
*   **Reduced Dwell Time:** Detects attacks in minutes, not months.
*   **Lower Operational Costs:** Admins spend less time triaging false positives.
*   **Compliance:** Meets "timely notification" requirements for GDPR, HIPAA, and NIST.

---

# Marketing Explanation for Customers

**"Sleep Soundly. We'll Wake You When It Matters."**

You don't need another dashboard that blinks red every time a user logs in. You need a silent guardian that only speaks when there's a real danger.

TenshiGuard SOS is your 24/7 watchtower. It analyzes millions of system events so you don't have to. When you get an SOS alert, it's not a false alarm—it's a call to action.

*   **Zero Noise:** We filter out the routine.
*   **Instant Clarity:** No cryptic codes, just clear warnings.
*   **Total Peace of Mind:** If SOS is quiet, your network is safe.
