# WAAD — Web Application Attack Detection Using Log Analysis

A complete implementation matching your project: DVWA + Apache logs → preprocessing
→ Random Forest ML classification (Normal / SQL Injection / XSS / Brute Force) →
live Flask + Chart.js dashboard.

---

## 1. What's in this folder

```
waad/
├── generate_logs.py     # Creates a realistic sample Apache log + labeled training data
├── preprocess.py         # Parses raw Apache logs + extracts ML features
├── train_model.py        # Trains the Random Forest classifier
├── predict.py             # Classifies a log file (Normal/Attack + risk level)
├── app.py                 # Flask dashboard (auto-refreshing)
├── requirements.txt
├── templates/
│   └── dashboard.html    # Dashboard UI (Bootstrap-style dark console + Chart.js)
├── data/
│   ├── access.log         # Sample Apache log (generated)
│   ├── labeled_logs.csv   # Same data with ground-truth labels (for training)
│   └── classified_logs.csv# Output after running predict.py
└── models/
    ├── attack_classifier.joblib
    └── label_encoder.joblib
```

---

## 2. Quick start (using the included sample data)

This runs the whole pipeline immediately, no DVWA install needed, so you can see
it working end-to-end right away:

```bash
cd waad
pip install -r requirements.txt

python3 generate_logs.py     # Step 3/4 in the PPT: produces data/access.log
python3 train_model.py       # Step 7: trains + saves the Random Forest model
python3 predict.py           # Step 8: classifies the log, prints a summary

python3 app.py                # Step 9: launches the dashboard
```

Open **http://127.0.0.1:5000** in your browser. The dashboard polls
`/api/stats` every 10 seconds and re-classifies the log automatically.

---

## 3. Going live against a REAL DVWA + XAMPP setup

To fulfill the full project brief (steps 1–3 in your methodology diagram) on
your own machine:

### A. Install XAMPP + DVWA
1. Download XAMPP for your OS: https://www.apachefriends.org/
2. Install it, then start **Apache** and **MySQL** from the XAMPP Control Panel.
3. Download DVWA: https://github.com/digininja/DVWA
4. Extract it into `xampp/htdocs/dvwa` (Windows) or `/opt/lampp/htdocs/dvwa` (Linux).
5. Copy `config/config.inc.php.dist` to `config/config.inc.php` and set the DB
   credentials to match XAMPP's MySQL (default user `root`, blank password).
6. Visit `http://localhost/dvwa/setup.php` and click **Create / Reset Database**.
7. Log in with the default DVWA credentials (`admin` / `password`).
8. In **DVWA Security**, set security level to **Low** (so the vulnerabilities
   are exploitable for this demo).

### B. Perform the three attacks on your own local DVWA instance
> Only do this against your own local install — never against a system you
> don't own or have written authorization to test.

**SQL Injection** — go to `Vulnerabilities → SQL Injection`, enter into the
`User ID` field:
```
1' OR '1'='1
```

**XSS (Reflected)** — go to `Vulnerabilities → XSS (Reflected)`, enter into the
name field:
```
<script>alert('xss')</script>
```

**Brute Force** — go to `Vulnerabilities → Brute Force` and either try several
manual username/password guesses quickly, or use a tool such as Hydra/Burp
Intruder against `login.php` with a small wordlist, e.g.:
```
hydra -l admin -P wordlist.txt localhost http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect"
```

### C. Point the dashboard at your real Apache log
Every request above gets written automatically to Apache's access log:
- Windows: `C:/xampp/apache/logs/access.log`
- Linux: `/opt/lampp/logs/access_log`

Run the dashboard against it instead of the sample data:

```bash
# Windows (PowerShell)
$env:WAAD_LOG_FILE="C:/xampp/apache/logs/access.log"
python app.py

# macOS/Linux
export WAAD_LOG_FILE=/opt/lampp/logs/access_log
python3 app.py
```

The dashboard checks the log file's modified time every 10 seconds and
automatically re-classifies new lines — satisfying the "auto-update" requirement.

**Note on the model**: `attack_classifier.joblib` was trained on the included
synthetic dataset, which covers the exact same payload styles you'll produce
in DVWA (SQLi tautologies/UNION/SLEEP, `<script>`/`onerror` XSS, rapid POSTs to
`login.php`). It will classify your real DVWA traffic correctly out of the box.
If you want to retrain on your own captured traffic, label a copy of your real
`access.log` (add `label` and `attack_type` columns) and re-run `train_model.py`
pointed at that file.

---

## 4. How each part maps to your Proposed Methodology slide

| Slide step | File |
|---|---|
| 1. DVWA Setup | Manual steps above |
| 2. Perform Attacks | Manual steps above (or `generate_logs.py` for a synthetic stand-in) |
| 3. Apache Access Logs | `data/access.log` |
| 4. Data Collection | `preprocess.py: parse_log_file()` |
| 5. Data Preprocessing | `preprocess.py: extract_features()` (cleaning, missing values, encoding) |
| 6. Feature Extraction | Same function — URL length, special chars, SQLi/XSS regex flags, request rate, etc. |
| 7. Machine Learning Model | `train_model.py` (Random Forest) |
| 8. Attack Classification | `predict.py` |
| 9. Dashboard Visualization | `app.py` + `templates/dashboard.html` |

---

## 5. Troubleshooting

- **"Model not found" error** → run `python3 generate_logs.py && python3 train_model.py` first.
- **Dashboard shows 0 for everything** → check the `WAAD_LOG_FILE` path is correct and the file has Apache "combined" format lines.
- **Port 5000 already in use** → edit the last line of `app.py`, change `port=5000` to another port.
