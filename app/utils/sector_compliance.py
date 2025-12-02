# app/utils/sector_compliance.py

def get_sector_compliance(sector: str):
    """Return list of compliance frameworks per sector."""
    sector = sector.lower()

    data = {
        "academic": [
            "FERPA – Family Educational Rights and Privacy Act",
            "ISO 27001 – Information Security Management",
            "SOC 2 Type II – Data Integrity & Audit Controls",
        ],
        "healthcare": [
            "HIPAA – Health Insurance Portability & Accountability Act",
            "PIPEDA – Canada Privacy Act for Health Data",
            "ISO 27799 – Information Security in Health",
            "SOC 2 Type II – Data Integrity & Audit Controls",
            "GDPR – EU General Data Protection Regulation",
        ],
        "hospitality": [
            "PCI DSS – Payment Card Industry Data Security Standard",
            "ISO 27001 – Information Security Management",
            "SOC 2 Type II – Service Organization Controls",
            "GDPR – EU General Data Protection Regulation",
        ],
    }

    return data.get(sector, data["academic"])
