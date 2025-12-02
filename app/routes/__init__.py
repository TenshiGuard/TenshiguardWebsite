from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import socket

# ============================================================
# 🔹 Blueprint Setup (use a unique name to avoid duplication)
# ============================================================
install_bp = Blueprint("install_bp", __name__, url_prefix="/install")


# ============================================================
# 🧠 Helper: Get Host IP for Local Network
# ============================================================
def get_server_host():
    """Return the current server's LAN IP address for installer commands."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
        return server_ip
    except Exception:
        return request.host.split(":")[0] if request.host else "127.0.0.1"


# ============================================================
# 🌐 Install Overview Page
# ============================================================
@install_bp.route("/")
@login_required
def index():
    """Overview page showing all installation platforms."""
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_index.html", org=org, server_ip=server_ip)


# ============================================================
# 🐧 Linux / Server Installer
# ============================================================
@install_bp.route("/linux")
@login_required
def install_linux():
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_linux.html", org=org, server_ip=server_ip)


# ============================================================
# 🍎 macOS Installer
# ============================================================
@install_bp.route("/mac")
@login_required
def install_mac():
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_mac.html", org=org, server_ip=server_ip)


# ============================================================
# 🪟 Windows Installer
# ============================================================
@install_bp.route("/windows")
@login_required
def install_windows():
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_windows.html", org=org, server_ip=server_ip)


# ============================================================
# 🧱 Firewall / Network Agent Installer
# ============================================================
@install_bp.route("/firewall")
@login_required
def install_firewall():
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_firewall.html", org=org, server_ip=server_ip)


# ============================================================
# 🤖 Android Endpoint Setup
# ============================================================
@install_bp.route("/android")
@login_required
def install_android():
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_android.html", org=org, server_ip=server_ip)


# ============================================================
# ☁️ Cloud / Serverless Agent Installer
# ============================================================
@install_bp.route("/cloud")
@login_required
def install_cloud():
    org = getattr(current_user, "organization", None)
    server_ip = get_server_host()
    return render_template("install/install_cloud.html", org=org, server_ip=server_ip)
