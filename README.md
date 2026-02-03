import pypandoc

md_content = """
# 🛡️ SOC Log Detector (Python)

A small SOC-style attack detection tool written in Python.  
It analyzes **SSH** and **Web server** logs, detects suspicious activity, and generates security alerts and reports — similar to workflows used by real SOC analysts.

This project demonstrates skills in:

- Log analysis  
- Attack detection logic  
- Regular expressions  
- Time-window based correlation  
- Basic security alerting and reporting  

---

## 🚨 Detected Attacks

### 🔐 SSH
| Attack | Description |
|-------|-------------|
| **Brute-force** | Multiple failed login attempts from the same IP within a defined time window |

### 🌐 Web
| Attack | Detection Pattern |
|--------|-------------------|
| **SQL Injection** | `OR 1=1`-style injections in request parameters |
| **Path Traversal** | `../` attempts to access files outside web root |
| **XSS** | `<script>` tags inside request parameters |

---

## ⚙️ How the Detector Works

### 1️⃣ SSH Brute-force Detection

1. Parses log lines like:
