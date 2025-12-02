#!/usr/bin/env python3
import requests
import json
import platform
import time
import sys
import os
import socket
import uuid
import threading
from datetime import datetime, timezone

# ==========================================================
# 🧠 Utility Functions
# ==========================================================
def log(msg):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}", flush=True)

def load_config():
    cfg_path = "/opt/tenshiguard/config.json"
    if not os.path.exists(cfg_path):
        log("❌ Config file not found.")
        sys.exit(1)
    with open(cfg_path, "r") as f:
        return json.load(f)

def get_device_info():
    try:
        return {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "mac": hex(uuid.getnode())
        }
    except Exception:
        return {
            "hostname": "unknown",
            "os": "unknown",
            "ip": "0.0.0.0",
            "mac": hex(uuid.getnode())
        }

# ==========================================================
# 🚀 Event Reporter
# ==========================================================
def send_event(cfg, info, category, action, detail, severity="info"):
    """Send structured event telemetry to dashboard"""
    try:
        payload = {
            "org_token": cfg.get("org_token"),
            "mac": info["mac"],
            "category": category,
            "action": action,
            "detail": detail,
            "severity": severity
        }
        r = requests.post(f"{cfg['base_url']}/api/agent/event", json=payload, timeout=5)
        log(f"[EVENT] {category}:{action} → {r.status_code}")
        return r.status_code
    except Exception as e:
        log(f"[EVENT ERROR] {e}")
        return 0

# ==========================================================
# 🔍 AUTH.LOG PARSER (supports sshd + sshd-session both)
# ==========================================================
def parse_auth_line(line: str):
    raw = line.strip()
    lower = raw.lower()

    # Template
    event = {
        "severity": "info",
        "category": "system",
        "action": "log",
        "detail": raw,
    }

    # ---------- SSH invalid user ----------
    if "invalid user" in lower:
        event.update({
            "severity": "low",
            "category": "auth",
            "action": "invalid_user"
        })
        return event

    # ---------- Failed password ----------
    if "failed password" in lower:
        event.update({
            "severity": "medium",
            "category": "auth",
            "action": "failed_login"
        })
        return event

    # ---------- PAM Authentication failure ----------
    if "authentication failure" in lower and ("sshd" in lower or "sshd-session" in lower):
        event.update({
            "severity": "medium",
            "category": "auth",
            "action": "failed_login"
        })
        return event

    # No actionable event
    return None

# ==========================================================
# 📡 Log Watcher Thread (Kali-compatible)
# ==========================================================
def watch_auth_log(cfg, info):
    log("🔍 Starting /var/log/auth.log watcher...")

    # Ensure file exists
    if not os.path.exists("/var/log/auth.log"):
        log("⚠️ auth.log missing — creating empty file.")
        try:
            os.system("sudo touch /var/log/auth.log")
            os.system("sudo chmod +r /var/log/auth.log")
            os.system("sudo chmod o+rx /var/log")
        except:
            pass

    try:
        with open("/var/log/auth.log", "r", errors="ignore") as f:
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                event = parse_auth_line(line)
                if event:
                    send_event(cfg, info,
                               category=event["category"],
                               action=event["action"],
                               detail=event["detail"],
                               severity=event["severity"])
    except Exception as e:
        log(f"[ERROR] Log watcher crashed: {e}")

# ==========================================================
# 🟢 Register Device
# ==========================================================
def register_device(cfg, info):
    try:
        payload = {
            "org_token": cfg["org_token"],
            "mac": info["mac"],
            "hostname": info["hostname"],
            "os": info["os"],
            "ip": info["ip"]
        }
        r = requests.post(f"{cfg['base_url']}/api/agent/register", json=payload, timeout=5)
        log(f"[INFO] Registration response: {r.json()}")
        if r.status_code in [200, 201]:
            send_event(cfg, info, "agent", "registered",
                       f"Agent registered on {info['hostname']}", "low")
            return True
    except Exception as e:
        log(f"[ERROR] Registration failed: {e}")
    return False

# ==========================================================
# 💓 Send Heartbeat
# ==========================================================
def send_heartbeat(cfg, info):
    import psutil
    payload = {
        "org_token": cfg["org_token"],
        "mac": info["mac"],
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory().percent
    }
    try:
        r = requests.post(f"{cfg['base_url']}/api/agent/heartbeat", json=payload, timeout=5)
        log(f"[INFO] 💓 Heartbeat: {r.status_code} | {r.text}")
        return True
    except Exception as e:
        log(f"[ERROR] Heartbeat failed: {e}")
        return False

# ==========================================================
# 🧠 Main
# ==========================================================
def main():
    log("[INFO] 💻 Starting TenshiGuard Agent Service...")
    cfg = load_config()
    info = get_device_info()

    if not register_device(cfg, info):
        log("[ERROR] Registration failed, exiting.")
        sys.exit(1)

    log("[INFO] 📡 Starting log watcher...")
    threading.Thread(target=watch_auth_log, args=(cfg, info), daemon=True).start()

    log("[INFO] 💡 Agent started. Sending heartbeats every 15 seconds.")
    while True:
        send_heartbeat(cfg, info)
        time.sleep(15)

if __name__ == "__main__":
    main()
