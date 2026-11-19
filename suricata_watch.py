"""
Suricata alert watcher (CodeAlpha Cyber Security Internship, Task 4)

Suricata does the detecting and writes every alert to eve.json.
This script follows that file while Suricata runs and, for every alert:
  1. prints it,
  2. RESPONDS by blocking the attacker's IP address in the firewall,
  3. saves it to alerts.jsonl (report.py turns that file into the dashboard).

Live use:  start Suricata (run_suricata.bat), then run   python suricata_watch.py
Test run:  python suricata_watch.py sample_eve.json     (reads a saved file once, Suricata not needed)
"""

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time

# ============================== SETTINGS ==============================
EVE_FILE = r"C:\Program Files\Suricata\log\eve.json"   # Suricata's JSON log, alerts are written here
ALERT_FILE = "alerts.jsonl"      # every alert is saved here; report.py reads it
READ_FROM_START = False          # False = only new alerts. True = also the alerts already in eve.json
BLOCK_SEVERITIES = {1}           # block the source of alerts with these Suricata severities (1 = highest)
DRY_RUN = True                   # True = only PRINT the block command. False = really block (run as administrator)
SAFE_IPS = set()                 # extra addresses that must never be blocked, e.g. {"192.168.1.1"}
# ======================================================================

SEVERITY_NAMES = {1: "HIGH", 2: "MEDIUM", 3: "INFO"}   # Suricata severity -> label used by report.py


def local_addresses():
    """Every IP address this computer has."""
    found = set()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))           # sends nothing, only asks which address would be used
        found.add(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0])
    except OSError:
        pass
    return found


def safe_addresses():
    """Addresses that are never blocked: this computer, the router (usually x.x.x.1) and loopback."""
    safe = {"127.0.0.1", "::1"} | set(SAFE_IPS)
    mine = local_addresses()
    for ip in mine:
        safe.add(ip)
        if "." in ip:                            # IPv4: the router is usually the .1 address
            safe.add(ip.rsplit(".", 1)[0] + ".1")
    if not mine:
        print("Warning: could not find this computer's IP address, so it is not protected from blocking.")
    return safe


def convert(event):
    """Turn one Suricata alert (a line of eve.json) into the simple record report.py understands."""
    alert = event["alert"]
    where = str(event.get("proto", "?"))
    if event.get("dest_port"):
        where += f" port {event['dest_port']}"
    details = f"{where}, sid {alert.get('signature_id')}"
    http = event.get("http")
    if isinstance(http, dict):
        details += f", {http.get('hostname', '')}{http.get('url', '')}"
    return {
        "time": str(event.get("timestamp", ""))[:19].replace("T", " "),
        "severity": SEVERITY_NAMES.get(alert.get("severity"), "INFO"),
        "rule": str(alert.get("signature", "unknown rule")),
        "src": str(event.get("src_ip", "?")),
        "dst": str(event.get("dest_ip", "?")),
        "details": details[:150],
    }


def respond(src, severity, safe, blocked):
    """Response mechanism: block the attacker's IP address in the firewall.
    Returns a short text that is saved with the alert and shown on the dashboard."""
    if severity not in BLOCK_SEVERITIES:
        return "-"
    try:
        ip = ipaddress.ip_address(src)           # only act on real IP addresses
    except ValueError:
        return "-"
    if src in safe or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        print(f"   [RESPONSE] Not blocking {src} (this computer, your router or the safe list).")
        return "safe address, not blocked"
    if src in blocked:                           # already handled earlier
        return "already blocked" if blocked[src] == "blocked" else blocked[src]

    if sys.platform.startswith("win"):
        rule_name = "Suricata_block_" + src.replace(":", "-")
        command = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}",
                   "dir=in", "action=block", f"remoteip={src}"]
        undo = f"netsh advfirewall firewall delete rule name={rule_name}"
    else:
        command = ["iptables", "-A", "INPUT", "-s", src, "-j", "DROP"]
        undo = f"iptables -D INPUT -s {src} -j DROP"

    if DRY_RUN:
        print(f"   [RESPONSE] DRY RUN, would block {src} with: {' '.join(command)}")
        blocked[src] = "dry run"
        return "dry run"
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    except OSError as error:
        print(f"   [RESPONSE] Could not run the firewall command: {error}")
        blocked[src] = "failed"
        return "failed"
    if result.returncode == 0:
        print(f"   [RESPONSE] BLOCKED {src}. To undo: {undo}")
        blocked[src] = "blocked"
        return "blocked"
    print(f"   [RESPONSE] Could not block {src} (not running as administrator?): "
          f"{(result.stdout or result.stderr).strip()}")
    blocked[src] = "failed"
    return "failed"


def handle(line, safe, blocked):
    """Process one line of eve.json."""
    try:
        event = json.loads(line)
    except ValueError:
        return                                   # not valid JSON, skip it
    # eve.json also holds flows, DNS, stats ... we only want alerts
    if not isinstance(event, dict) or event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
        return
    record = convert(event)
    print(f"[ALERT] {record['time']} [{record['severity']}] {record['rule']} | "
          f"{record['src']} -> {record['dst']} | {record['details']}")
    record["response"] = respond(record["src"], event["alert"].get("severity"), safe, blocked)
    with open(ALERT_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def watch():
    """Follow eve.json while Suricata is running."""
    safe = safe_addresses()
    blocked = {}
    print(f"Watching {EVE_FILE}   (DRY_RUN = {DRY_RUN})")
    print("Never blocked:", ", ".join(sorted(safe)))

    if not os.path.exists(EVE_FILE):
        print("eve.json does not exist yet. Start Suricata first (run_suricata.bat). Waiting ...")
        print("(If Suricata is already running, EVE_FILE at the top of this script must match its log folder.)")
        while not os.path.exists(EVE_FILE):
            time.sleep(2)

    with open(EVE_FILE, "rb") as log:
        if not READ_FROM_START:
            log.seek(0, os.SEEK_END)             # skip old alerts, only show new ones
        print("Ready. Waiting for alerts (press Stop or Ctrl+C to quit).\n")
        pending = b""
        while True:
            chunk = log.readline()
            if not chunk:                        # nothing new yet
                if os.path.getsize(EVE_FILE) < log.tell():   # the file was emptied, start again from the top
                    log.seek(0)
                time.sleep(0.5)
                continue
            pending += chunk
            if pending.endswith(b"\n"):          # a full line has arrived
                handle(pending.decode("utf-8", errors="replace"), safe, blocked)
                pending = b""


def replay(path):
    """Read a saved eve.json once (for testing without Suricata)."""
    safe = safe_addresses()
    blocked = {}
    print(f"Reading {path}   (DRY_RUN = {DRY_RUN})")
    print("Never blocked:", ", ".join(sorted(safe)), "\n")
    with open(path, "rb") as log:
        for line in log:
            handle(line.decode("utf-8", errors="replace"), safe, blocked)
    print(f"\nDone. Alerts saved to {ALERT_FILE}. Run report.py to build the dashboard.")


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(errors="replace")  # never crash on odd characters inside an alert
    except AttributeError:
        pass
    try:
        if len(sys.argv) > 1:
            replay(sys.argv[1])
        else:
            watch()
    except KeyboardInterrupt:
        print("\nStopped.")
    except OSError as error:
        print(f"Problem: {error}")
