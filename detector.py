import re
import json
import argparse
from collections import Counter
from datetime import datetime, timedelta

# ==========================================================
# Configuration loading
# ==========================================================

with open("config.json") as f:
    cfg = json.load(f)

BRUTE_FORCE_THRESHOLD = cfg["BRUTE_FORCE_THRESHOLD"]
TIME_WINDOW_MINUTES = cfg["TIME_WINDOW_MINUTES"]

SSH_LOG = cfg["SSH_LOG"]
WEB_LOG = cfg["WEB_LOG"]

ALERT_LOG_FILE = cfg["ALERT_LOG_FILE"]
JSON_REPORT_FILE = cfg["JSON_REPORT_FILE"]

CRITICALITY_LEVELS = cfg["CRITICALITY_LEVELS"]

# ANSI reset code
RESET = "\033[0m"

# ==========================================================
# ALERT generator
# ==========================================================

def alert(message, ip=None, attack_type=None):
    """
    Purpose:
        Create a structured security alert with severity classification.

    Security Context:
        Standardized alerts allow SOC analysts to quickly
        assess threat severity and prioritize response.

    Args:
        message (str): Human-readable alert description
        ip (str, optional): Source IP address
        attack_type (str, optional): Type of detected attack

    Returns:
        dict:
            Structured alert object used for:
            - console output
            - log file storage
            - JSON reporting
    """
    COLORS = {
        "HIGH": "\033[91m",     # Red
        "MEDIUM": "\033[93m",   # Yellow
        "LOW": "\033[92m"       # Green
    }

    criticality = CRITICALITY_LEVELS.get(attack_type, "LOW")
    color = COLORS.get(criticality, "\033[97m")

    return {
        "time": datetime.now().isoformat(),
        "ip": ip,
        "type": attack_type,
        "criticality": criticality,
        "message": f"{color}[{attack_type} | {criticality}] {message}{RESET}"
    }

# ==========================================================
# SSH log parsing & brute-force detection
# ==========================================================

def parse_ssh_logs(file_path):
    """
     Purpose:
        Parse SSH authentication logs and extract failed login attempts.

    Security Context:
        Failed SSH logins are a primary indicator of brute-force attacks.
        Collected data is later used for time-based correlation and detection.

    Args:
        file_path (str): Path to SSH log file (e.g. /var/log/auth.log)

    Returns:
        list[dict]:
            List of failed authentication attempts with:
            - ip (str): source IP address
            - time (datetime): timestamp of the attempt
    """
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password.*from (\d+\.\d+\.\d+\.\d+)'
    attempts = []

    with open(file_path, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                time_str = match.group(1)
                ip = match.group(2)

                time_obj = datetime.strptime(time_str, "%b %d %H:%M:%S")
                attempts.append({"ip": ip, "time": time_obj})

    return attempts


def detect_bruteforce(attempts):
    """
    Purpose:
        Detect SSH brute-force attacks using a sliding time window approach.

    Security Context:
        Multiple failed authentication attempts from a single IP
        within a short period of time indicate a brute-force attack.

    Detection Logic:
        - Group attempts by source IP
        - Sort attempts by time
        - Count failed logins within TIME_WINDOW_MINUTES
        - Trigger alert if threshold is exceeded

    Args:
        attempts (list[dict]):
            Parsed SSH failed login attempts

    Returns:
        list[dict]:
            List of generated security alerts    
    """
    alerts = {}
    alerts_list = []

    # Group attempts by IP
    for attempt in attempts:
        alerts.setdefault(attempt["ip"], []).append(attempt["time"])

    # Check time windows
    for ip, times in alerts.items():
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            window_end = window_start + timedelta(minutes=TIME_WINDOW_MINUTES)

            count = sum(1 for t in times if window_start <= t <= window_end)

            if count >= BRUTE_FORCE_THRESHOLD:
                msg = (
                    f"Possible brute-force from IP {ip} "
                    f"({count} failed attempts in {TIME_WINDOW_MINUTES} min)"
                )
                alerts_list.append(
                    alert(msg, ip=ip, attack_type="SSH Brute-force")
                )
                break

    return alerts_list

# ==========================================================
# Web log parsing
# ==========================================================

def parse_web_logs(file_path):
    """
     Purpose:
        Analyze web server access logs and detect common web attacks.

    Security Context:
        Web logs may contain exploitation attempts such as:
        - SQL Injection
        - Cross-Site Scripting (XSS)
        - Path Traversal

    Detection Method:
        Pattern-based matching using regular expressions.

    Args:
        file_path (str): Path to web access log file

    Returns:
        tuple:
            - alerts (list[dict]): detected attack alerts
            - attempts (list[dict]): all observed IP addresses for statistics
    """
    suspicious_patterns = {
        r"'.*OR.*=.*": "SQL Injection",
        r"\.\./": "Path Traversal",
        r"<script>": "XSS"
    }

    alerts = []
    attempts = []

    with open(file_path, "r") as f:
        for line in f:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            ip = ip_match.group(1) if ip_match else None

            if ip:
                attempts.append({"ip": ip, "time": datetime.now()})

            for pattern, attack_type in suspicious_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    msg = f"{attack_type} attempt: {line.strip()}"
                    alerts.append(alert(msg, ip=ip, attack_type=attack_type))

    return alerts, attempts


def parse_web_summary(file_path):
    """
    Parse web logs only to collect IP statistics (summary mode)
    """
    attempts = []

    with open(file_path, "r") as f:
        for line in f:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                attempts.append({"ip": ip_match.group(1), "time": datetime.now()})

    return attempts

# ==========================================================
# Output & reporting
# ==========================================================

def write_alerts(alerts):
    """
    Append alerts to text log file
    """
    with open(ALERT_LOG_FILE, "a") as f:
        for alert_item in alerts:
            f.write(f"{alert_item['time']} | {alert_item['message']}\n")


def write_json(alerts):
    """
    Write alerts to JSON report
    """
    with open(JSON_REPORT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


def summarize_ip(attempts):
    """
    Print TOP IPs by number of events
    """
    counter = Counter(a["ip"] for a in attempts)

    print(f"\033[96m=== Top IP by failed attempts ==={RESET}")
    for ip, count in counter.most_common(5):
        print(f"{ip}: {count} attempts")

# ==========================================================
# Main entry point
# ==========================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC-style log detector")
    parser.add_argument("--ssh", default=SSH_LOG, help="Path to SSH log file")
    parser.add_argument("--web", default=WEB_LOG, help="Path to Web log file")
    parser.add_argument("--summary", action="store_true", help="Show statistics only")

    args = parser.parse_args()

    # --- SSH analysis ---
    print(f"\033[96m=== Checking SSH logs ==={RESET}")
    ssh_attempts = parse_ssh_logs(args.ssh)
    ssh_alerts = detect_bruteforce(ssh_attempts)

    for alert_item in ssh_alerts:
        print(alert_item["message"])

    # --- Web analysis ---
    print(f"\033[96m=== Checking Web logs ==={RESET}")

    if args.summary:
        web_attempts = parse_web_summary(args.web)
        summarize_ip(ssh_attempts + web_attempts)
        exit(0)

    web_alerts, web_attempts = parse_web_logs(args.web)

    for alert_item in web_alerts:
        print(alert_item["message"])

    # --- Statistics ---
    summarize_ip(ssh_attempts + web_attempts)

    # --- Save results ---
    all_alerts = ssh_alerts + web_alerts

    if all_alerts:
        write_alerts(all_alerts)
        write_json(all_alerts)
        print(
            f"\033[93m[INFO] {len(all_alerts)} alerts saved to "
            f"{ALERT_LOG_FILE} and {JSON_REPORT_FILE}{RESET}"
        )
    else:
        print("\033[92mNo suspicious activity detected.\033[0m")
