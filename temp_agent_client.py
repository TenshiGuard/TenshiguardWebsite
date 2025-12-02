#!/usr/bin/env python3
"""TenshiGuard unified Agent (Linux/Windows/macOS)
- Registers device
- Sends heartbeats every 2s (Real-time)
- Streams login/logout events immediately
"""
import os, time, socket, uuid, threading, subprocess, platform, shutil, sys
from datetime import datetime, timezone

import requests
try:
    import psutil
except ImportError:
    psutil = None

SERVER = "http://127.0.0.1:5002"
ORG_TOKEN = "tg-admin-token"
HEARTBEAT_INTERVAL = 2  # Real-time feedback

# ------------------ Helpers ------------------
def log(msg):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[agent] {now} :: {msg}", flush=True)

def mac_address():
    try:
        mac = uuid.getnode()
        parts = []
        for ele in range(40, -8, -8):
            parts.append(f"{(mac >> ele) & 0xff:02x}")
        return ":".join(parts)
    except Exception:
        return "unknown"

def get_ip():
    # Best-effort outward IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"

def system_info():
    return {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()}",
        "ip": get_ip(),
        "mac": mac_address(),
    }

def post(path, payload):
    url = f"{SERVER}{path}"
    try:
        r = requests.post(url, json=payload, timeout=2) # Fast timeout for real-time
        return r.status_code, r.text
    except Exception as e:
        # log(f"post error: {e}") # Reduce noise
        return 0, str(e)

# -------------- Metrics ----------------
def gather_stats():
    cpu = mem = 0.0
    if psutil:
        try:
            cpu = psutil.cpu_percent(interval=None) # Non-blocking
            mem = psutil.virtual_memory().percent
        except Exception:
            cpu = mem = 0.0
    return cpu, mem

# -------------- API calls --------------
def register():
    info = system_info()
    cpu, mem = gather_stats()
    payload = {
        "org_token": ORG_TOKEN,
        "hostname": info["hostname"],
        "mac": info["mac"],
        "os": info["os"],
        "ip": info["ip"],
        "cpu_percent": cpu,
        "mem_percent": mem,
        "agent_version": "1.0.0",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    code, body = post("/api/agent/register", payload)
    log(f"register -> {code}")
    return code

def heartbeat():
    info = system_info()
    cpu, mem = gather_stats()
    payload = {
        "org_token": ORG_TOKEN,
        "hostname": info["hostname"],
        "mac": info["mac"],
        "os": info["os"],
        "ip": info["ip"],
        "cpu_percent": cpu,
        "mem_percent": mem,
        "status": "online",
        "agent_version": "1.0.0",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    code, body = post("/api/agent/heartbeat", payload)
    # log(f"heartbeat -> {code}") # Too noisy for 2s
    return code

def send_event(category, action, detail, severity="medium"):
    info = system_info()
    payload = {
        "org_token": ORG_TOKEN,
        "mac": info["mac"],
        "category": category,
        "action": action,
        "detail": detail,
        "severity": severity,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    code, body = post("/api/agent/event", payload)
    log(f"event({category}/{action}) -> {code}")
    return code

# -------------- Auth Monitoring (Cross-Platform) --------------

def tail_linux_auth():
    """Stream journald or auth.log for Linux"""
    cmd = None
    source = None

    if shutil.which("journalctl"):
        cmd = ["journalctl", "-f", "-n", "0", "-u", "ssh", "-u", "sshd", "_COMM=sshd", "_COMM=login", "_COMM=sudo"]
        source = "journald"
    elif os.path.exists("/var/log/auth.log"):
        cmd = ["tail", "-n", "0", "-F", "/var/log/auth.log"]
        source = "/var/log/auth.log"
    elif os.path.exists("/var/log/secure"): # RHEL/CentOS
        cmd = ["tail", "-n", "0", "-F", "/var/log/secure"]
        source = "/var/log/secure"

    if not cmd:
        log("No auth log source found (journald/auth.log/secure).")
        return

    log(f"Watching {source} for auth events...")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Keywords for detection
        fail_patterns = ["Failed password", "authentication failure", "Invalid user"]
        success_patterns = ["Accepted password", "session opened for user"]
        logout_patterns = ["session closed for user", "pam_unix(sshd:session): session closed"]

        for line in iter(proc.stdout.readline, ""):
            line = line.strip()
            if not line: continue

            if any(p in line for p in fail_patterns):
                send_event("auth", "failed_login", line, "medium")
            elif any(p in line for p in success_patterns):
                send_event("auth", "login", line, "info")
            elif any(p in line for p in logout_patterns):
                send_event("auth", "logout", line, "info")
    except Exception as e:
        log(f"Linux auth watcher failed: {e}")

def tail_windows_events():
    '''Stream Windows Event Log via PowerShell'''
    # 4624: Logon Success
    # 4625: Logon Failed
    # 4647: User Initiated Logoff
    # 4634: Logoff
    ps_script = '''
    $query = "*[System[(EventID=4624 or EventID=4625 or EventID=4647) and TimeCreated[timediff(@SystemTime) <= 2000]]]"
    while ($true) {
        Get-WinEvent -LogName Security -FilterXPath $query -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Compress
        Start-Sleep -Seconds 1
    }
    '''

    log("Watching Windows Security Event Log...")
    try:
        # We'll use a simpler approach: a loop in python calling powershell is too heavy.
        # Better: Run a powershell process that streams JSON.
        # For simplicity in this python script, we might poll or use a blocking read if we could.
        # Given the constraints, we will poll Get-WinEvent every 2s in a loop here.

        last_time = datetime.now()

        while True:
            # Fetch events since last check
            # We use a small buffer time to avoid missing events

            # Constructing a precise query is hard without a persistent PS session.
            # Let's try a simpler polling loop using subprocess.

            cmd = [
                "powershell", "-Command",
                "Get-WinEvent -LogName Security -MaxEvents 5 -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt (Get-Date).AddSeconds(-3) -and ($_.Id -eq 4624 -or $_.Id -eq 4625 -or $_.Id -eq 4647) } | Select-Object Id, Message, TimeCreated | ConvertTo-Json"
            ]

            try:
                out = subprocess.check_output(cmd, text=True).strip()
                if out:
                    # PowerShell might return a single object or array
                    import json
                    try:
                        data = json.loads(out)
                        if isinstance(data, dict): data = [data]

                        for event in data:
                            eid = event.get("Id")
                            msg = event.get("Message", "")[:200] # Truncate

                            # Deduplication could be added here based on TimeCreated

                            if eid == 4624:
                                # Filter out system/machine logons (usually contain "$" or "SYSTEM")
                                if "Advapi" not in msg and "SYSTEM" not in msg: 
                                    send_event("auth", "login", f"Windows Logon: {msg}", "info")
                            elif eid == 4625:
                                send_event("auth", "failed_login", f"Windows Failed Logon: {msg}", "medium")
                            elif eid == 4647:
                                send_event("auth", "logout", f"Windows Logoff: {msg}", "info")

                    except json.JSONDecodeError:
                        pass
            except subprocess.CalledProcessError:
                pass

            time.sleep(2)
    except Exception as e:
        log(f"Windows event watcher failed: {e}")

def start_auth_watcher():
    sys_plat = platform.system().lower()
    if "linux" in sys_plat or "darwin" in sys_plat: # macOS is similar to Linux (uses unified log, but tailing works for some things)
        # For macOS specifically, 'log stream' is better, but let's stick to linux tail for now as fallback
        # If macOS, we might need a specific handler.
        if "darwin" in sys_plat:
            # macOS 'log stream' TODO
            pass 
        else:
            threading.Thread(target=tail_linux_auth, daemon=True).start()
    elif "windows" in sys_plat:
        threading.Thread(target=tail_windows_events, daemon=True).start()

# -------------- Main loop --------------
def main():
    log(f"Starting TenshiGuard Agent v1.0.0 on {platform.system()}...")

    # Initial Register
    code = register()
    if code not in (200, 201):
        log("Initial register failed; will retry in loop")

    # Start Event Monitoring
    start_auth_watcher()

    # Heartbeat Loop
    while True:
        code = heartbeat()
        if code == 404:
            log("Heartbeat 404: Device not found. Re-registering...")
            register()

        time.sleep(HEARTBEAT_INTERVAL)

if __name__ == "__main__":
    main()
