# 🛡️ SOC Log Detector (Python)

A small SOC-style attack detection tool written in Python.\
It analyzes **SSH** and **Web server** logs, detects suspicious
activity, and generates security alerts and reports --- similar to
workflows used by real SOC analysts.

This project demonstrates skills in:

-   Log analysis\
-   Attack detection logic\
-   Regular expressions\
-   Time-window based correlation\
-   Basic security alerting and reporting

------------------------------------------------------------------------

## 🚨 Detected Attacks

### 🔐 SSH

  Attack                   Description
  ------------------------ ----------------------------------------------
  **Brute-force**          Multiple failed login attempts from the same
                           IP within a defined time window

  -----------------------------------------------------------------------

### 🌐 Web

  Attack               Detection Pattern
  -------------------- -------------------------------------------------
  **SQL Injection**    `OR 1=1`-style injections in request parameters
  **Path Traversal**   `../` attempts to access files outside web root
  **XSS**              `<script>` tags inside request parameters

------------------------------------------------------------------------

## ⚙️ How the Detector Works

### 1️⃣ SSH Brute-force Detection

1.  Parses log lines like:

        Failed password for invalid user admin from 192.168.1.10 port 22 ssh2

2.  Groups failed login attempts by IP address

3.  Triggers an alert if: \> An IP makes **X or more failed attempts**
    within **N minutes**

Configured in `config.json`:

``` json
"BRUTE_FORCE_THRESHOLD": 5,
"TIME_WINDOW_MINUTES": 5
```

------------------------------------------------------------------------

### 2️⃣ Web Attack Detection

Each web log line is checked against regex patterns:

  Pattern        Attack Type
  -------------- ----------------
  `'.*OR.*=.*`   SQL Injection
  `\.\./`        Path Traversal
  `<script>`     XSS

If a pattern matches, an alert is generated with the source IP.

------------------------------------------------------------------------

## 📁 Project Structure

    detector/
    │
    ├── detector.py        # Main detection script
    ├── config.json        # Configuration (thresholds, paths, severity levels)
    ├── logs/
    │   ├── ssh.log
    │   └── web.log
    ├── alerts.log         # Text log of detected alerts
    └── report.json        # JSON report (structured security events)

------------------------------------------------------------------------

## 🧠 Configuration (`config.json`)

``` json
{
  "BRUTE_FORCE_THRESHOLD": 3,
  "TIME_WINDOW_MINUTES": 5,
  "SSH_LOG": "logs/ssh.log",
  "WEB_LOG": "logs/web.log",
  "ALERT_LOG_FILE": "alerts.log",
  "JSON_REPORT_FILE": "report.json",

  "CRITICALITY_LEVELS": {
    "SSH Brute-force": "HIGH",
    "SQL Injection": "HIGH",
    "Path Traversal": "MEDIUM",
    "XSS": "LOW"
  }
}
```

Security policies (like alert severity) can be adjusted **without
modifying the code**, similar to real SOC detection tuning.

------------------------------------------------------------------------

## ▶️ Usage

### Run with default log paths

``` bash
python detector.py
```

### Specify custom log files

``` bash
python detector.py --ssh /var/log/auth.log --web /var/log/nginx/access.log
```

------------------------------------------------------------------------

## 🖥️ Example Output

    === Checking SSH logs ===
    [SSH Brute-force | HIGH] Possible brute-force from IP 192.168.1.10 (3 failed attempts in 5 min)

    === Checking Web logs ===
    [SQL Injection | HIGH] SQL Injection attempt: 192.168.1.15 ...
    [Path Traversal | MEDIUM] Path Traversal attempt: 192.168.1.16 ...
    [XSS | LOW] XSS attempt: 192.168.1.18 ...

    === Top IP by failed attempts ===
    192.168.1.10: 3 failed attempts
    192.168.1.15: 1 failed attempts

    [INFO] 4 alerts saved to alerts.log and report.json

------------------------------------------------------------------------

## 📊 Output Files

### `alerts.log`

Plain-text log of detected incidents:

    2026-02-03T14:20:11 | [SQL Injection | HIGH] SQL Injection attempt: ...

### `report.json`

Structured report for further analysis or SIEM ingestion:

``` json
[
  {
    "time": "2026-02-03T14:20:11",
    "ip": "192.168.1.15",
    "type": "SQL Injection",
    "criticality": "HIGH",
    "message": "[SQL Injection | HIGH] SQL Injection attempt: ..."
  }
]
```

------------------------------------------------------------------------

## 🛠 Technologies Used

-   **Python 3**
-   `re` --- log parsing with regular expressions\
-   `datetime` --- time-window correlation\
-   `argparse` --- command-line interface\
-   `json` --- configuration and reporting\
-   SOC-style detection logic

------------------------------------------------------------------------

## 🎯 Project Goal

This project simulates a simplified **Security Operations Center (SOC)**
detection tool and demonstrates:

✔ Understanding of Linux and web server logs\
✔ Basic attack detection techniques\
✔ Handling and correlating security events\
✔ Preparing structured data for SOC/SIEM workflows

------------------------------------------------------------------------

This project is designed as a hands-on learning exercise for aspiring
**Junior SOC Analysts** and cybersecurity beginners.
