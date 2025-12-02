# app/utils/mitigation.py
def classify(event):
    cat = (getattr(event, "category", "") or event.get("category", "")).lower()
    act = (getattr(event, "action", "") or event.get("action", "")).lower()
    detail = (getattr(event, "detail", "") or event.get("detail", "")).lower()
    title = "Security Event"
    mitigation = "Review the event details."
    score = 10

    if cat == "auth" and act == "failed_login":
        title = "Failed Login Attempt"
        mitigation = "Check SSH logs, block offending IPs, enable Fail2Ban, and enforce key-based auth."
        score = 50
    elif "brute" in detail:
        title = "Possible Brute Force Attack"
        mitigation = "Temporarily block the IP; audit user lockout policies."
        score = 70
    elif cat == "malware":
        title = "Malware Suspicion"
        mitigation = "Isolate host, run malware scan, and restore from clean state."
        score = 80

    return title, mitigation, score
