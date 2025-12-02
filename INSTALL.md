# TenshiGuard AI - Installation & Deployment Guide

## Overview
TenshiGuard AI is a lightweight, agent-based security monitoring system. This guide covers how to deploy the **Server** (Dashboard) and how to install **Agents** on Windows, Linux, and macOS endpoints.

---

## 1. Server Deployment (Dashboard)

### Prerequisites
- Python 3.9+
- pip (Python Package Manager)
- Git

### Installation Steps
1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-repo/tenshiguard_ai.git
   cd tenshiguard_ai
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configuration**
   Create a `.env` file in the root directory (or rename `.env.example`):
   ```ini
   SECRET_KEY=your-super-secret-key-change-this
   DATABASE_URL=sqlite:///tenshiguard.db
   # Optional: For AI Features
   OPENAI_API_KEY=sk-...
   # Optional: For SMS Alerts
   TWILIO_ACCOUNT_SID=...
   TWILIO_AUTH_TOKEN=...
   TWILIO_PHONE_NUMBER=...
   ```

4. **Initialize Database**
   ```bash
   flask db upgrade
   # Or if using the provided setup script:
   python run.py --setup
   ```

5. **Run the Server**
   ```bash
   python run.py
   ```
   The dashboard will be available at `http://localhost:5000`.

---

## 2. Agent Installation

Agents are installed on endpoints to collect telemetry and security events. You need your **Organization Token** from the Admin Dashboard (`Setup Agent` page).

### 🐧 Linux (Ubuntu, Debian, CentOS, RHEL)
**One-Line Installer:**
Replace `YOUR_ORG_TOKEN` and `SERVER_URL` (e.g., `http://192.168.1.10:5000`).

```bash
curl -sSL "http://SERVER_URL/install/agent/YOUR_ORG_TOKEN" | sudo bash
```

**What it does:**
- Installs Python3 & dependencies.
- Creates `/opt/tenshiguard`.
- Sets up a systemd service `tenshiguard-agent`.
- Starts reporting immediately.

**Verify:**
```bash
sudo systemctl status tenshiguard-agent
```

### 🪟 Windows (PowerShell)
Run as **Administrator**:

```powershell
$base="http://SERVER_URL"; $token="YOUR_ORG_TOKEN"; iwr -UseBasicParsing "$base/install/agent/windows/$token" | iex
```

**What it does:**
- Creates `C:\TenshiGuard`.
- Downloads the agent client.
- Registers a **Scheduled Task** to run the agent at system startup/logon.

### 🍎 macOS
**One-Line Installer:**

```bash
curl -sSL "http://SERVER_URL/install/agent/macos/YOUR_ORG_TOKEN" | sudo bash
```

**What it does:**
- Creates `/opt/tenshiguard`.
- Sets up a LaunchDaemon (`com.tenshiguard.agent.plist`).
- Starts the service automatically.

---

## 3. Troubleshooting

### Agent Not Appearing in Dashboard
1. **Check Network:** Ensure the agent machine can reach the server URL.
   ```bash
   curl -v http://SERVER_URL/health
   ```
2. **Check Logs:**
   - **Linux:** `sudo journalctl -u tenshiguard-agent -f`
   - **Windows:** Check `C:\TenshiGuard` for logs or run manually: `python C:\TenshiGuard\agent_client.py`
   - **macOS:** `tail -f /var/log/tenshiguard.out`

### Server Issues
- **Database Locked:** If using SQLite, ensure no other process is holding the lock.
- **Port In Use:** Change the port in `.env` or run with `PORT=5001 python run.py`.

---

## 4. Uninstallation

### Linux
```bash
sudo /opt/uninstall_tenshiguard.sh
```

### Windows
Delete the `C:\TenshiGuard` folder and remove the Scheduled Task "TenshiGuardAgent".

### macOS
```bash
sudo launchctl unload /Library/LaunchDaemons/com.tenshiguard.agent.plist
sudo rm /Library/LaunchDaemons/com.tenshiguard.agent.plist
sudo rm -rf /opt/tenshiguard
```
