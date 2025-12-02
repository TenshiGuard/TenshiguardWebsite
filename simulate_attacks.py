import requests
import json
import time
import random
import sys
from app import create_app
from app.models import Organization, Device
from app.extensions import db

# Configuration
BASE_URL = "http://127.0.0.1:5002"
API_ENDPOINT = f"{BASE_URL}/api/agent/ai/event"

def get_org_token():
    """Fetch the first organization's agent token from the DB."""
    app = create_app()
    with app.app_context():
        org = Organization.query.first()
        if not org:
            print("Error: No organization found in DB.")
            sys.exit(1)
        
        # Ensure agent_token exists
        if not org.agent_token:
            import secrets
            org.agent_token = secrets.token_hex(16)
            db.session.commit()
            print(f"Generated new token for {org.name}")
            
        print(f"Using Organization: {org.name} (Token: {org.agent_token})")
        return org.agent_token

def send_event(token, payload):
    """Send a single event to the API."""
    payload["org_token"] = token
    try:
        resp = requests.post(API_ENDPOINT, json=payload, timeout=5)
        if resp.status_code in (200, 201):
            data = resp.json()
            print(f"[OK] Event sent. AI Match: {data.get('ai_match')} | Severity: {data.get('severity')}")
            return True
        else:
            print(f"[FAIL] {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return False

def simulate_brute_force(token):
    print("\n--- Simulating Auth Brute Force ---")
    mac = "00:11:22:33:44:55"
    hostname = "victim-pc-01"
    
    # Send 6 failed login attempts
    for i in range(6):
        payload = {
            "type": "auth",
            "action": "failed_login",
            "username": "admin",
            "source_ip": "192.168.1.100",
            "hostname": hostname,
            "mac": mac,
            "ip": "10.0.0.5",
            "description": "Failed password for user admin"
        }
        send_event(token, payload)
        time.sleep(0.5)

def simulate_process_network_link(token):
    print("\n--- Simulating Process + Network Link ---")
    mac = "AA:BB:CC:DD:EE:FF"
    hostname = "compromised-server"
    
    # 1. Suspicious Process (Mimikatz)
    proc_payload = {
        "type": "process",
        "process_name": "mimikatz.exe",
        "cmdline": "mimikatz.exe privilege::debug",
        "path": "C:\\Temp\\mimikatz.exe",
        "hostname": hostname,
        "mac": mac,
        "ip": "10.0.0.10"
    }
    send_event(token, proc_payload)
    time.sleep(1)
    
    # 2. Suspicious Network Connection (C2)
    net_payload = {
        "type": "network",
        "dest_ip": "185.100.1.1",
        "dest_port": 4444,
        "domain": "evil-c2.onion",
        "protocol": "tcp",
        "hostname": hostname,
        "mac": mac,
        "ip": "10.0.0.10"
    }
    send_event(token, net_payload)

def simulate_ransomware(token):
    print("\n--- Simulating Ransomware Behavior ---")
    mac = "11:22:33:44:55:66"
    hostname = "fileserver-01"
    
    # 1. File with suspicious extension
    file_payload = {
        "type": "file",
        "file_name": "important_doc.docx.enc",
        "path": "C:\\Users\\Admin\\Documents\\important_doc.docx.enc",
        "file_hash": "a" * 64, # Dummy hash
        "hostname": hostname,
        "mac": mac,
        "ip": "10.0.0.20"
    }
    send_event(token, file_payload)
    
    # 2. Rapid file modifications (20 events)
    print("Sending rapid file modification events...")
    for i in range(25):
        mass_mod_payload = {
            "type": "file",
            "file_name": f"data_{i}.locked",
            "path": f"D:\\Data\\data_{i}.locked",
            "hostname": hostname,
            "mac": mac,
            "ip": "10.0.0.20",
            "behavior_type": "rapid_file_mod",
            "description": "File encrypted"
        }
        send_event(token, mass_mod_payload)
        # No sleep to simulate rapid activity

def simulate_lateral_movement(token):
    print("\n--- Simulating Lateral Movement ---")
    attacker_ip = "192.168.1.200"
    
    # Device 1
    payload1 = {
        "type": "auth",
        "action": "failed_login",
        "username": "admin",
        "source_ip": attacker_ip,
        "hostname": "workstation-01",
        "mac": "AA:00:00:00:00:01",
        "ip": "10.0.0.101"
    }
    send_event(token, payload1)
    
    # Device 2
    payload2 = {
        "type": "auth",
        "action": "failed_login",
        "username": "admin",
        "source_ip": attacker_ip,
        "hostname": "workstation-02",
        "mac": "BB:00:00:00:00:02",
        "ip": "10.0.0.102"
    }
    send_event(token, payload2)
    
    # Device 3
    payload3 = {
        "type": "auth",
        "action": "failed_login",
        "username": "admin",
        "source_ip": attacker_ip,
        "hostname": "server-db",
        "mac": "CC:00:00:00:00:03",
        "ip": "10.0.0.103"
    }
    send_event(token, payload3)

if __name__ == "__main__":
    print("Initializing Simulation...")
    token = get_org_token()
    
    simulate_brute_force(token)
    time.sleep(2)
    
    simulate_process_network_link(token)
    time.sleep(2)
    
    simulate_ransomware(token)
    time.sleep(2)
    
    simulate_lateral_movement(token)
    
    print("\nSimulation Complete. Check the Dashboard for alerts.")
