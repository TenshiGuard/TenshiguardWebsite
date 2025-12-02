TenshiGuard – Endpoint Security Monitoring Platform

<img width="112" height="136" alt="TenshiGuardlogo" src="https://github.com/user-attachments/assets/67070b55-5656-4614-bec6-f8c5b9a3028b" />

TenshiGuard is a multi-tenant endpoint security monitoring platform designed to bring enterprise-grade protection to small and medium organizations.
TenshiGuard provides real-time threat detection, AI-powered insights, device health monitoring, and sector-specific dashboards for Academic, Healthcare, and Hospitality environments.
TenshiGuard’s goal is simple:
make modern cybersecurity accessible, affordable, and easy to use — without sacrificing depth or intelligence.

Key Features
• Multi-Tenant Architecture
Each organization operates in its own isolated environment with independent dashboards, alerts, and configurations.

• Sector-Specific Dashboards
Customized themes and monitoring profiles for:

Academic 

Healthcare 

Hospitality 

• Real-Time Endpoint Monitoring
Centralized visibility of:
CPU, RAM, and resource usage
Suspicious processes
Login attempts & authentication failures
File activity & integrity changes
Network behavior patterns

• Advanced Threat Analysis
Combines Wazuh rules, behavioral analytics, and AI insights to identify:
Malware activity
Brute-force attacks
Insider threats
Persistence mechanisms
Zero-day-like behaviors

• AI-Powered Insights
Threats explained in simple language with:
Severity scores
Root-cause context
Recommended actions

• Subscription Management

Built-in subscription tiers:
Includes automated billing logic and renewal reminders (payment gateway integration coming soon).

• Seamless Integration
One-command agent deployment with:
Native Wazuh manager integration
Event streaming to backend API
Automatic device registration
Immediate dashboard visibility

• Modern UI/UX
Clean, responsive interface
Sector-based themes
Real-time charts and visualizations


Tech Stack
Backend: Flask (Python), SQLAlchemy, JWT Authentication
Security Engine: Wazuh Manager & Agents
Frontend: HTML + Bootstrap (sector-based themes)
Database: SQLite (dev), PostgreSQL (prod planned)
Environment: Ubuntu on Windows (WSL2)
