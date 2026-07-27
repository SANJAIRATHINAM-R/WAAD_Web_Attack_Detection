"""
app.py
------
Flask dashboard for the Web Application Attack Detection project.

Run:
    python3 app.py
Then open: http://127.0.0.1:5000

Auto-refresh:
The dashboard polls /api/stats every 10 seconds. Point LOG_FILE at your real
XAMPP access.log (xampp/apache/logs/access.log on Windows, or
/opt/lampp/logs/access_log on Linux) and every refresh will re-classify
whatever new lines have been appended -- satisfying requirement #8
("dashboard update automatically whenever new logs are added").
"""

import os
import time
import threading
from flask import Flask, jsonify, render_template

from predict import classify_log_file

app = Flask(__name__)

# ---- Point this at your REAL Apache log to go live against actual DVWA traffic ----
# Windows XAMPP default:  C:/xampp/apache/logs/access.log
# Linux XAMPP default:    /opt/lampp/logs/access_log
LOG_FILE = os.environ.get("WAAD_LOG_FILE", "data/access.log")
REFRESH_SECONDS = 10

_cache = {"df": None, "last_mtime": 0, "last_check": 0}
_lock = threading.Lock()


def get_classified_df():
    """Re-classify the log file only when it has changed on disk (cheap polling)."""
    with _lock:
        try:
            mtime = os.path.getmtime(LOG_FILE)
        except OSError:
            mtime = 0
        now = time.time()
        if _cache["df"] is None or mtime != _cache["last_mtime"] or now - _cache["last_check"] > REFRESH_SECONDS:
            _cache["df"] = classify_log_file(LOG_FILE)
            _cache["last_mtime"] = mtime
            _cache["last_check"] = now
        return _cache["df"]


@app.route("/")
def dashboard():
    return render_template("dashboard.html", refresh_seconds=REFRESH_SECONDS)


@app.route("/api/stats")
def api_stats():
    df = get_classified_df()

    total_requests = len(df)
    attacks = df[df["prediction"] == "Malicious"]
    total_attacks = len(attacks)
    normal_requests = total_requests - total_attacks

    attack_counts = attacks["attack_type"].value_counts().to_dict()
    risk_counts = attacks["risk_level"].value_counts().to_dict()

    overall_risk = "Low"
    if risk_counts.get("Critical", 0) > 0:
        overall_risk = "Critical"
    elif risk_counts.get("High", 0) > 0:
        overall_risk = "High"
    elif risk_counts.get("Medium", 0) > 0:
        overall_risk = "Medium"

    # Daily attack counts for the trend chart (last 7 distinct days present in data)
    df["_day"] = df["timestamp"].str.slice(0, 11)  # e.g. '04/Jul/2026'
    daily = attacks.assign(_day=attacks["timestamp"].str.slice(0, 11)) \
                    .groupby("_day").size()
    daily = daily.reindex(sorted(daily.index, key=lambda d: time.strptime(d, "%d/%b/%Y"))[-7:], fill_value=0)

    top_ips = attacks["ip"].value_counts().head(5).to_dict()

    recent = df.head(25).drop(columns=["_day"], errors="ignore").to_dict(orient="records")

    return jsonify({
        "total_requests": total_requests,
        "total_attacks": total_attacks,
        "normal_requests": normal_requests,
        "overall_risk": overall_risk,
        "attack_counts": {
            "SQL Injection": attack_counts.get("SQL Injection", 0),
            "XSS": attack_counts.get("XSS", 0),
            "Brute Force": attack_counts.get("Brute Force", 0),
        },
        "risk_counts": {
            "Critical": risk_counts.get("Critical", 0),
            "High": risk_counts.get("High", 0),
            "Medium": risk_counts.get("Medium", 0),
            "Low": risk_counts.get("Low", 0),
        },
        "daily_labels": list(daily.index),
        "daily_values": [int(v) for v in daily.values],
        "top_ips": top_ips,
        "recent_logs": recent,
        "source_file": LOG_FILE,
    })


if __name__ == "__main__":
    if not os.path.exists("models/attack_classifier.joblib"):
        raise SystemExit(
            "Model not found. Run: python3 generate_logs.py && python3 train_model.py  first."
        )
    app.run(debug=False, port=5000, host="0.0.0.0")
