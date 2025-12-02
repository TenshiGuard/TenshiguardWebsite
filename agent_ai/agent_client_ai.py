#!/usr/bin/env python3
import os
import time
import json
import hashlib
import psutil
import requests
import socket

API_BASE = "http://localhost:5000/api/ai"
ORG_TOKEN = os.getenv("TG_ORG_TOKEN", "")
MAC = ":".join(['{:02x}'.format((os.getnode() >> ele) & 0xff)
                for ele in range(0,8*6,8)][::-1])

def send(endpoint, payload):
    try:
        r = requests.post(f"{API_BASE}/{endpoint}", json=payload, timeout=5)
        print(f"[AI-Agent] POST /{endpoint} -> {r.status_code} | {r.json()}")
    except Exception as e:
        print(f"[AI-Agent] ERROR sending to {endpoint}: {e}")

def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except:
        return None

# PROCESS SCAN
def collect_processes():
    data = []
    for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','exe']):
        try:
            data.append({
                "pid": p.info['pid'],
                "name": p.info['name'],
                "cpu": p.info['cpu_percent'],
                "mem": p.info['memory_percent'],
                "path": p.info['exe'] or ""
            })
        except:
            continue
    return data

# FILE SCAN
COMMON_DIRS = ["/home", "/tmp", "/var/tmp"]

def collect_files():
    results = []
    for directory in COMMON_DIRS:
        if not os.path.exists(directory):
            continue
        for root, dirs, files in os.walk(directory):
            for f in files:
                path = os.path.join(root, f)
                sha = hash_file(path)
                if sha:
                    results.append({
                        "name": f,
                        "path": path,
                        "sha256": sha,
                        "size": os.path.getsize(path)
                    })
    return results[:20]  # limit for safety

# NETWORK SCAN
def collect_network():
    conns = []
    for c in psutil.net_connections(kind='inet'):
        conns.append({
            "process": str(c.pid),
            "src_ip": c.laddr.ip if c.laddr else "",
            "dst_ip": c.raddr.ip if c.raddr else "",
            "dst_port": c.raddr.port if c.raddr else "",
            "protocol": "tcp" if c.type == socket.SOCK_STREAM else "udp"
        })
    return conns[:30]

def main_loop():
    global ORG_TOKEN
    if not ORG_TOKEN:
        print("[AI-Agent] ERROR: No ORG_TOKEN")
        return

    print("[AI-Agent] TenshiGuard-AI Agent started")

    while True:
        payload = {"org_token": ORG_TOKEN, "mac": MAC}

        # Send process data
        payload["processes"] = collect_processes()
        send("process", payload)

        # Send file data
        payload["files"] = collect_files()
        send("file", payload)

        # Send network activity
        payload["connections"] = collect_network()
        send("network", payload)

        # Anomaly placeholder
        payload["anomalies"] = [
            {"type": "cpu_spike", "value": 95, "detail": "Test anomaly"}
        ]
        send("anomaly", payload)

        time.sleep(15)

if __name__ == "__main__":
    main_loop()
