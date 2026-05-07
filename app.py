# simple_launcher.py
# Windows + Linux
# Public access enabled (listen on 0.0.0.0)

import subprocess
import sys
import os
from pathlib import Path
import shutil
import socket

print("🚀 Starting mitmproxy with PUBLIC access...")
print("=" * 60)

# -----------------------------
# Setup
# -----------------------------
os.makedirs("logs", exist_ok=True)

BASE_DIR = Path(__file__).parent.resolve()
SCRIPT_FILE = BASE_DIR / "main.py"

PORT = "8080"
HOST = "0.0.0.0"   # allow public access from all networks

if not SCRIPT_FILE.exists():
    print(f"❌ main.py not found: {SCRIPT_FILE}")
    sys.exit(1)


# -----------------------------
# Find mitmdump
# -----------------------------
def find_mitmdump():
    win_path = BASE_DIR / "venv" / "Scripts" / "mitmdump.exe"
    linux_path = BASE_DIR / "venv" / "bin" / "mitmdump"

    if win_path.exists():
        return str(win_path)

    if linux_path.exists():
        return str(linux_path)

    global_cmd = shutil.which("mitmdump")
    if global_cmd:
        return global_cmd

    return None


# -----------------------------
# Get Local IP
# -----------------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


# -----------------------------
# Get Public IP
# -----------------------------
def get_public_ip():
    try:
        import urllib.request
        return urllib.request.urlopen(
            "https://api.ipify.org", timeout=5
        ).read().decode()
    except:
        return "Unavailable"


local_ip = get_local_ip()
public_ip = get_public_ip()

print("Network:")
print(f"  Listen Host : {HOST}")
print(f"  Proxy Port  : {PORT}")
print()

print("Local Access:")
print(f"  http://127.0.0.1:{PORT}")
print(f"  http://{local_ip}:{PORT}")
print()

print("Public Access:")
if public_ip != "Unavailable":
    print(f"  http://{public_ip}:{PORT}")
    print("⚠ Router port forwarding may be required")
else:
    print("  Public IP unavailable")

print()
print("=" * 60)

mitmdump_path = find_mitmdump()

if not mitmdump_path:
    print("❌ mitmdump not found")
    print("Run:")
    print("pip install mitmproxy")
    sys.exit(1)

cmd = [
    mitmdump_path,
    "--listen-host",
    HOST,
    "--listen-port",
    PORT,
    "-s",
    str(SCRIPT_FILE),
]

try:
    subprocess.run(cmd, check=True)

except KeyboardInterrupt:
    print("\n✅ Proxy stopped by user")

except subprocess.CalledProcessError as e:
    print(f"\n❌ mitmdump exited with error: {e}")

except Exception as e:
    print(f"\n❌ Unexpected error: {e}")