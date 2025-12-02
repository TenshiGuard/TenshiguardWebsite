#!/usr/bin/env python3
import os
import time
import uuid
import json
import platform
import requests
import psutil
from datetime import datetime

CONFIG_PATH = "/opt/tenshiguard/config.json"
DEVICE_ID_PATH = "/opt/tenshiguard/device_id.txt"


def log(msg: str) -> None:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def load_config() -> dict:
    """
    Load base_url, org_token and (optionally) api_key, org_id from JSON config.
    We keep keys case-insensitive by normalizing to lowercase.
    """
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Missing config file at {CONFIG_PATH}")

    with open(CONFIG_PATH, "r") as f:
        raw = json.load(f)

    # Normalize keys to lowercase for safety
    cfg = {str(k).lower(): v for k, v in raw.items()}

    # Basic sanity check
    if "base_url" not in cfg or "org_token" not in cfg:
        raise ValueError("Config must contain 'base_url' and 'org_token'")

    return cfg


def get_or_create_device_id() -> str:
    """Generate and persist a unique device ID."""
    if os.path.exists(DEVICE_ID_PATH):
        with open(DEVICE_ID_PATH, "r") as f:
            return f.read().strip()

    new_id = str(uuid.uuid4())
    os.makedirs(os.path.dirname(DEVICE_ID_PATH), exist_ok=True)
    with open(DEVICE_ID_PATH, "w") as f:
        f.write(new_id)
    return new_id


def get_device_name(device_id: str) -> str:
    """Consistent device name used in all calls (register, heartbeat, AI)."""
    return f"{platform.node()}-{device_id[:6]}"


def register_device(cfg: dict, device_id: str) -> None:
    """Register this device to TenshiGuard server."""
    try:
        url = f"{cfg['base_url'].rstrip('/')}/api/agent/register"
        payload = {
            "org_token": cfg["org_token"],
            "device_name": get_device_name(device_id),
            "os": f"{platform.system()} {platform.release()}",
            "ip": requests.get("https://api.ipify.org", timeout=5).text,
        }
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            log(f"✅ Registered device → {payload['device_name']}")
        else:
            log(f"❌ Registration failed ({r.status_code}): {r.text}")
    except Exception as e:
        log(f"[ERROR] register_device: {e}")


def send_heartbeat(cfg: dict, device_id: str) -> None:
    """Send CPU + MEM heartbeat."""
    try:
        url = f"{cfg['base_url'].rstrip('/')}/api/agent/heartbeat"
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        payload = {
            "org_token": cfg["org_token"],
            "device_name": get_device_name(device_id),
            "status": "online",
            "cpu": cpu,
            "memory": mem,
        }
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code == 200:
            log(f"🩵 Heartbeat sent → CPU {cpu:.1f}% | MEM {mem:.1f}%")
        else:
            log(f"[WARN] Heartbeat response ({r.status_code}): {r.text}")
    except Exception as e:
        log(f"[ERROR] send_heartbeat: {e}")


def send_ai_process_event(cfg: dict, device_id: str) -> None:
    """
    Lightweight AI telemetry:
    - Picks the highest CPU process.
    - Sends a 'process' AI event to /api/agent/ai/event.
    - Uses X-API-KEY + X-ORG-ID from config.json when available.
    """
    api_key = cfg.get("api_key")
    org_id = cfg.get("org_id")

    if not api_key or org_id is None:
        # AI is optional; don't crash the agent if these are missing.
        log("[AI] api_key or org_id missing in config.json → skipping AI event.")
        return

    try:
        # Find top-CPU process (simple heuristic for demo)
        procs = []
        for p in psutil.process_iter(attrs=["pid", "name", "cmdline", "cpu_percent"]):
            try:
                info = p.info
                procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not procs:
            log("[AI] No processes available to inspect.")
            return

        # Sort by CPU usage descending
        procs.sort(key=lambda p: p.get("cpu_percent") or 0, reverse=True)
        top = procs[0]

        process_name = top.get("name") or "unknown"
        cmdline_list = top.get("cmdline") or []
        cmdline = " ".join(cmdline_list)[:512]

        # Simple risk heuristic: higher CPU -> higher 'risk' (for demo only)
        cpu = top.get("cpu_percent") or 0
        base_risk = 40
        extra = min(int(cpu / 2), 50)  # cap at +50
        risk_score = max(0, min(base_risk + extra, 100))

        flags = []
        if cpu > 70:
            flags.append("high_cpu")
        if "powershell" in process_name.lower():
            flags.append("powershell")
        if "cmd.exe" in process_name.lower():
            flags.append("cmd")

        summary = f"Top CPU process: {process_name} ({cpu:.1f}% CPU)"

        url = f"{cfg['base_url'].rstrip('/')}/api/agent/ai/event"
        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": str(api_key),
            "X-ORG-ID": str(org_id),
        }
        payload = {
            "type": "process",
            "device_name": get_device_name(device_id),
            "process_name": process_name,
            "cmdline": cmdline,
            "flags": flags,
            "risk": risk_score,
            "summary": summary,
        }

        r = requests.post(url, headers=headers, json=payload, timeout=10)
        if r.status_code == 200:
            log(f"🤖 AI event sent → {process_name} | risk={risk_score}")
        else:
            log(f"[AI WARN] AI event response ({r.status_code}): {r.text}")
    except Exception as e:
        log(f"[AI ERROR] send_ai_process_event: {e}")


def main():
    try:
        cfg = load_config()
        device_id = get_or_create_device_id()

        register_device(cfg, device_id)
        log("💡 Agent started. Sending heartbeats every 15 seconds.")
        log("💡 AI process events will be sent periodically when api_key + org_id are set.")

        tick = 0
        while True:
            send_heartbeat(cfg, device_id)

            # Every 4th heartbeat (~60s), send an AI process event
            if tick % 4 == 0:
                send_ai_process_event(cfg, device_id)

            tick += 1
            time.sleep(15)

    except Exception as e:
        log(f"[FATAL] {e}")
        # In production you might want to exit and let systemd restart,
        # but for now we sleep and retry.
        time.sleep(10)
        main()


if __name__ == "__main__":
    main()
