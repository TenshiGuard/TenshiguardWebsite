# app/utils/sector_features.py

def get_sector_features(sector: str):
    sector = sector.lower()

    # Common baseline across all
    base = [
        "Real-time Endpoint Monitoring",
        "Threat Detection Dashboard",
        "Device Status & Compliance Overview",
    ]

    data = {
        "academic": {
            "name": "Academic / Education",
            "basic": base + [
                "Student Device Monitoring (Limited)",
                "Manual Security Alerts",
            ],
            "professional": base + [
                "Automated Patch Management",
                "Centralized Student Network Log Analysis",
                "Classroom Policy Enforcement (Local Rules)",
                "Weekly Security Summary Reports",
            ],
            "enterprise": base + [
                "AI-driven Threat Analysis",
                "Cloud Integration (Google Workspace, Microsoft 365)",
                "Multi-campus Management Console",
                "24/7 Automated Incident Response",
            ],
        },
        "healthcare": {
            "name": "Healthcare / Clinics / Hospitals",
            "basic": base + [
                "Local Threat Alerts",
                "System Health Monitoring",
            ],
            "professional": base + [
                "HIPAA Compliance Logging",
                "Patient Data Integrity Checks",
                "Automatic Policy Updates",
                "Advanced Endpoint Correlation",
            ],
            "enterprise": base + [
                "Anomaly Detection via Machine Learning",
                "24/7 Real-time Alert Response",
                "Multi-clinic Data Visualization",
                "SOC 2 & HIPAA Automated Compliance Reports",
            ],
        },
        "hospitality": {
            "name": "Hospitality / Restaurants / Hotels",
            "basic": base + [
                "POS Endpoint Monitoring",
                "Manual Breach Alerts",
            ],
            "professional": base + [
                "Centralized Staff Device Management",
                "Ransomware Prevention Policies",
                "Daily Security Health Reports",
                "Guest Network Risk Analysis",
            ],
            "enterprise": base + [
                "Smart IoT Device Monitoring",
                "Chain-level Threat Correlation",
                "Cloud Backup & Restore Automation",
                "AI-based Fraud Detection & Auto Alerts",
            ],
        },
    }

    return data.get(sector, data["academic"])
