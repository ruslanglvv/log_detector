import re
import json
import argparse
from collections import Counter
from datetime import datetime

BRUTE_FORCE_THRESHOLD = 3

# --------------------------
# Утилита для ALERT с цветом ANSI
# --------------------------
def alert(msg):
    RED = "\033[91m"
    RESET = "\033[0m"
    print(f"{RED}[ALERT] {msg}{RESET}")
    return {"type": "ALERT", "message": msg, "time": datetime.now().isoformat()}


# --------------------------
# SSH парсер
# --------------------------
def parse_ssh_logs(file_path):
    pattern = r'Failed password.*from (\d+\.\d+\.\d+\.\d+)'
    attempts = []
    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                attempts.append(ip)
    return attempts


def detect_bruteforce(attempts):
    alerts = []
    counter = Counter(attempts)
    for ip, count in counter.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append(alert(f"Possible brute-force from IP {ip} ({count} failed attempts)"))
    return alerts


# --------------------------
# WEB парсер
# --------------------------
def parse_web_logs(file_path):
    suspicious_patterns = {
        r"'.*OR.*=.*": "SQL Injection attempt",
        r"\.\./": "Path Traversal attempt",
        r"<script>": "XSS attempt"
    }

    alerts = []
    for line in open(file_path):
        for pat, attack_type in suspicious_patterns.items():
            if re.search(pat, line, re.IGNORECASE):
                msg = f"{attack_type}: {line.strip()}"
                alerts.append(alert(msg))
    return alerts


# --------------------------
# Запись алертов
# --------------------------
def write_alerts_to_log(alerts, filename="alerts.log"):
    with open(filename, "a") as f:
        for a in alerts:
            f.write(f"{a['time']} | {a['message']}\n")


def write_json_report(alerts, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(alerts, f, indent=4)


# --------------------------
# MAIN
# --------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple SOC-style log detector")
    parser.add_argument("--ssh", default="logs/ssh.log")
    parser.add_argument("--web", default="logs/web.log")
    args = parser.parse_args()

    print("\033[96m=== Checking SSH logs ===\033[0m")
    ssh_attempts = parse_ssh_logs(args.ssh)
    ssh_alerts = detect_bruteforce(ssh_attempts)

    print("\033[96m\n=== Checking Web logs ===\033[0m")
    web_alerts = parse_web_logs(args.web)

    all_alerts = ssh_alerts + web_alerts

    if all_alerts:
        write_alerts_to_log(all_alerts)
        write_json_report(all_alerts)
        print(f"\033[93m\n[INFO] {len(all_alerts)} alerts saved to alerts.log and report.json\033[0m")
    else:
        print("\033[92mNo suspicious activity detected.\033[0m")
