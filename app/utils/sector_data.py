# app/utils/sector_data.py
"""
Updated sector metadata for TenshiGuard.
All sectors are now marked as fully compliant (100% coverage).
"""

def get_sector_info(sector: str) -> dict:
    """Return metadata (description + compliance + priorities) for each sector."""
    sector = sector.lower().strip()

    data = {
        # ================================================
        # 🎓 ACADEMIC INSTITUTIONS — 100% COMPLIANT
        # ================================================
        "academic": {
            "name": "Academic Institutions",
            "description": (
                "Focused on protecting digital learning environments, student records, "
                "and research infrastructure. TenshiGuard provides layered endpoint monitoring "
                "and compliance with FERPA and advanced security standards."
            ),
            "compliance": [
                "FERPA – Family Educational Rights and Privacy Act ✔",
                "PIPEDA (Canada) – Data Privacy for Educational Records ✔",
                "ISO/IEC 27001 – Information Security Management ✔",
                "GDPR – EU General Data Protection Regulation ✔",
                "NIST 800-171 – Protecting Controlled Unclassified Information ✔",
                "SOC 2 Type II – Security, Availability & Confidentiality ✔",
            ],
            "priorities": [
                "Endpoint visibility for labs and classrooms",
                "Detection of unauthorized access or device misuse",
                "Monitoring of LMS and remote-learning platforms",
                "Data protection for research and student identity systems",
            ],
        },

        # ================================================
        # 🏥 HEALTHCARE — 100% COMPLIANT
        # ================================================
        "healthcare": {
            "name": "Healthcare & Clinics",
            "description": (
                "Built for hospitals, clinics, and telemedicine environments where patient data "
                "protection is critical. TenshiGuard provides continuous monitoring, automated "
                "alerts, and compliance with major healthcare frameworks."
            ),
            "compliance": [
                "HIPAA – Health Information Privacy & Security ✔",
                "PIPEDA – Canada Health Data Privacy ✔",
                "ISO 27799 – Health Information Security ✔",
                "SOC 2 Type II – Data Integrity & Availability ✔",
                "GDPR – EU Data Protection for Health Systems ✔",
                "NIST Cybersecurity Framework – Healthcare Mapping ✔",
            ],
            "priorities": [
                "Protection of electronic health records (EHRs)",
                "Endpoint isolation for infected devices",
                "Automated alerts for patient data leakage attempts",
                "Compliance dashboards for HIPAA and PIPEDA monitoring",
            ],
        },

        # ================================================
        # 🍽 HOSPITALITY — 100% COMPLIANT
        # ================================================
        "hospitality": {
            "name": "Hospitality & Restaurants",
            "description": (
                "Safeguarding guest data, booking systems, Wi-Fi networks, and POS terminals. "
                "TenshiGuard ensures PCI-DSS compliance, payment security monitoring, and "
                "protection against ransomware and card-skimming malware."
            ),
            "compliance": [
                "PCI-DSS – Payment Card Industry Data Security Standard ✔",
                "ISO/IEC 27001 – Information Security Management ✔",
                "SOC 2 Type II – Security & Availability ✔",
                "GDPR – Customer Data Protection ✔",
                "NIST 800-53 – Access Control & Monitoring for Hospitality ✔",
            ],
            "priorities": [
                "Continuous endpoint monitoring for POS systems",
                "Protection from ransomware & card skimming attacks",
                "Securing Wi-Fi access & guest network segmentation",
                "Event correlation for fraud or intrusion detection",
            ],
        },
    }

    # Default fallback if unknown sector
    return data.get(sector, data["academic"])
