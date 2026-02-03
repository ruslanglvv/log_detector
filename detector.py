import re
import json
import argparse
from collections import Counter
from datetime import datetime, timedelta

# --------------------------
# Настройки
# --------------------------
with open("config.json") as f:
    cfg = json.load(f)

BRUTE_FORCE_THRESHOLD = cfg["BRUTE_FORCE_THRESHOLD"]
TIME_WINDOW_MINUTES = cfg["TIME_WINDOW_MINUTES"]
SSH_LOG = cfg["SSH_LOG"]
WEB_LOG = cfg["WEB_LOG"]
ALERT_LOG_FILE = cfg["ALERT_LOG_FILE"]
JSON_REPORT_FILE = cfg["JSON_REPORT_FILE"]
CRITICALITY_LEVELS = cfg["CRITICALITY_LEVELS"]

RESET = "\033[0m"

# --------------------------
# ALERT функция с цветом ANSI и критичностью
# --------------------------
def alert(msg, ip=None, attack_type=None):
    COLORS = {
        "HIGH": "\033[91m",
        "MEDIUM": "\033[93m",
        "LOW": "\033[92m"
    }
    criticality = CRITICALITY_LEVELS.get(attack_type, "LOW")
    color = COLORS.get(criticality, "\033[97m")
    return {
        "time": datetime.now().isoformat(),
        "ip": ip,
        "type": attack_type,
        "criticality": criticality,
        "message": f"{color}[{attack_type} | {criticality}] {msg}{RESET}"
    }

# --------------------------
# SSH парсер и детект
# --------------------------
def parse_ssh_logs(file_path):
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (\d+\.\d+\.\d+\.\d+)'
    attempts = []
    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                time_str = match.group(1)
                ip = match.group(2)
                time_obj = datetime.strptime(time_str, "%b %d %H:%M:%S")
                attempts.append({'ip': ip, 'time': time_obj})
    return attempts

def detect_bruteforce(attempts):
    alerts = []
    ip_dict = {}
    for a in attempts:
        ip_dict.setdefault(a['ip'], []).append(a['time'])
    for ip, times in ip_dict.items():
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)
            count = sum(1 for t in times if window_start <= t <= window_end)
            if count >= BRUTE_FORCE_THRESHOLD:
                msg = f"Possible brute-force from IP {ip} ({count} failed attempts in {TIME_WINDOW_MINUTES} min)"
                alerts.append(alert(msg, ip=ip, attack_type="SSH Brute-force"))
                break
    return alerts

# --------------------------
# Web парсер для ALERT
# --------------------------
def parse_web_logs(file_path):
    suspicious_patterns = {
        r"'.*OR.*=.*": "SQL Injection",
        r"\.\./": "Path Traversal",
        r"<script>": "XSS"
    }
    alerts = []
    attempts = []
    with open(file_path, 'r') as f:
        for line in f:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else None
            if ip:
                attempts.append({'ip': ip, 'time': datetime.now()})
            for pat, attack_type in suspicious_patterns.items():
                if re.search(pat, line, re.IGNORECASE):
                    msg = f"{attack_type} attempt: {line.strip()}"
                    alerts.append(alert(msg, ip=ip, attack_type=attack_type))
    return alerts, attempts

# --------------------------
# Web парсер для summary
# --------------------------
def parse_web_summary(file_path):
    attempts = []
    with open(file_path, 'r') as f:
        for line in f:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                attempts.append({'ip': ip_match.group(1), 'time': datetime.now()})
    return attempts

# --------------------------
# Запись ALERT'ов и JSON
# --------------------------
def write_alerts(alerts):
    with open(ALERT_LOG_FILE, "a") as f:
        for a in alerts:
            f.write(f"{datetime.now().isoformat()} | {a['message']}\n")

def write_json(alerts):
    with open(JSON_REPORT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

# --------------------------
# TOP IP
# --------------------------
def summarize_ip(attempts):
    counter = Counter([a['ip'] for a in attempts])
    print(f"\033[96m=== Top IP by failed attempts ==={RESET}")
    for ip, count in counter.most_common(5):
        print(f"{ip}: {count} failed attempts")

# --------------------------
# MAIN
# --------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", default=SSH_LOG)
    parser.add_argument("--web", default=WEB_LOG)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    print(f"\033[96m=== Checking SSH logs ==={RESET}")
    ssh_attempts = parse_ssh_logs(args.ssh)
    ssh_alerts = detect_bruteforce(ssh_attempts)
    for a in ssh_alerts:
        print(a['message'])

    print(f"\033[96m=== Checking Web logs ==={RESET}")
    if args.summary:
        web_attempts = parse_web_summary(args.web)
        print(f"\033[96m=== Summary mode: Top IP ==={RESET}")
        summarize_ip(ssh_attempts + web_attempts)
        exit(0)

    web_alerts, web_attempts = parse_web_logs(args.web)
    for a in web_alerts:
        print(a['message'])

    summarize_ip(ssh_attempts + web_attempts)

    all_alerts = ssh_alerts + web_alerts
    if all_alerts:
        write_alerts(all_alerts)
        write_json(all_alerts)
        print(f"\033[93m[INFO] {len(all_alerts)} alerts saved to {ALERT_LOG_FILE} and {JSON_REPORT_FILE}{RESET}")
    else:
        print("\033[92mNo suspicious activity detected.{RESET}")
