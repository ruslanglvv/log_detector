import re
from collections import Counter
from datetime import datetime, timedelta
import argparse

# --------------------------
# Конфиги
# --------------------------
BRUTE_FORCE_THRESHOLD = 3  # количество неудачных логинов
TIME_WINDOW_MINUTES = 5    # время в минутах

# --------------------------
# Функции
# --------------------------

def parse_ssh_logs(file_path):
    """Парсим SSH лог для неудачных логинов"""
    pattern = r'Failed password.*from (\d+\.\d+\.\d+\.\d+)'
    attempts = []
    with open(file_path, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                ip = match.group(1)
                # можно парсить время, если нужно для временного окна
                attempts.append(ip)
    return attempts

def parse_web_logs(file_path):
    """Парсим веб-логи на простые SQLi/XSS/Path traversal"""
    suspicious_patterns = [r"'.*OR.*=.*", r"\.\./", r"<script>"]
    alerts = []
    with open(file_path, 'r') as f:
        for line in f:
            for pat in suspicious_patterns:
                if re.search(pat, line, re.IGNORECASE):
                    alerts.append(line.strip())
    return alerts

def detect_bruteforce(attempts):
    counter = Counter(attempts)
    for ip, count in counter.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            print(f"[ALERT] Possible brute-force from IP {ip} ({count} failed attempts)")

# --------------------------
# Основная логика
# --------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple log detector for SSH and web attacks")
    parser.add_argument("--ssh", help="SSH log file", default="logs/ssh.log")
    parser.add_argument("--web", help="Web log file", default="logs/web.log")
    args = parser.parse_args()

    print("=== Checking SSH logs ===")
    ssh_attempts = parse_ssh_logs(args.ssh)
    detect_bruteforce(ssh_attempts)

    print("\n=== Checking Web logs ===")
    web_alerts = parse_web_logs(args.web)
    for alert in web_alerts:
        print(f"[ALERT] Suspicious request: {alert}")
