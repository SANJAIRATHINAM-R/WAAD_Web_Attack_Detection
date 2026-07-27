"""
preprocess.py
-------------
Parses a raw Apache 'combined' log format file into structured rows, then
does cleaning + feature extraction ready for the ML model.

Works on:
  - A REAL access.log copied from XAMPP (xampp/apache/logs/access.log)
  - The synthetic data/access.log produced by generate_logs.py

Usage:
    from preprocess import parse_log_file, extract_features
    df = parse_log_file("data/access.log")
    df = extract_features(df)
"""

import re
import pandas as pd
from urllib.parse import unquote

# Apache combined log format regex
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

SQLI_PATTERNS = [
    r"('|\%27)\s*(or|and)\s*('|\%27|\d)\s*=\s*('|\%27|\d)",
    r"union\s+select", r"select\s+.*\s+from", r"drop\s+table",
    r"sleep\(\d+\)", r"benchmark\(", r"--\s", r"#\s*$", r"' ?or ?1 ?= ?1",
    r"information_schema", r"xp_cmdshell", r";\s*drop", r"waitfor\s+delay",
]
XSS_PATTERNS = [
    r"<script", r"onerror\s*=", r"onload\s*=", r"javascript:", r"<img[^>]+src",
    r"<svg", r"alert\(", r"document\.cookie", r"<iframe", r"%3cscript",
]


def parse_log_file(path: str) -> pd.DataFrame:
    records = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if not m:
                continue
            d = m.groupdict()
            records.append(d)
    df = pd.DataFrame(records)
    if df.empty:
        raise ValueError("No lines matched the Apache combined log format.")
    return df


def _clean_status(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def _clean_size(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Data Preprocessing (cleaning, handle missing, normalize) +
    Feature Extraction (numeric features a model can use), matching the
    'Proposed Methodology' steps 5 & 6 in the project slides.
    """
    df = df.copy()

    # ---- Data Cleaning ----
    df["status"] = df["status"].apply(_clean_status)
    df["size"] = df["size"].apply(_clean_size)
    df["url"] = df["url"].fillna("").astype(str)
    df["user_agent"] = df["user_agent"].fillna("unknown").astype(str)
    df["method"] = df["method"].fillna("GET").astype(str)

    df["decoded_url"] = df["url"].apply(lambda u: unquote(u).lower())

    # ---- Feature Extraction ----
    df["url_length"] = df["decoded_url"].apply(len)
    df["num_params"] = df["decoded_url"].apply(lambda u: u.count("&") + (1 if "?" in u else 0))
    df["num_special_chars"] = df["decoded_url"].apply(
        lambda u: sum(u.count(c) for c in ["'", '"', "<", ">", ";", "--", "=", "(", ")"])
    )

    df["has_sqli_pattern"] = df["decoded_url"].apply(
        lambda u: int(any(re.search(p, u, re.IGNORECASE) for p in SQLI_PATTERNS))
    )
    df["has_xss_pattern"] = df["decoded_url"].apply(
        lambda u: int(any(re.search(p, u, re.IGNORECASE) for p in XSS_PATTERNS))
    )
    df["is_login_endpoint"] = df["decoded_url"].apply(lambda u: int("login" in u))
    df["is_post"] = df["method"].apply(lambda m: int(m.upper() == "POST"))
    df["status_is_error"] = df["status"].apply(lambda s: int(s in (401, 403, 500)))
    df["is_known_attack_tool_ua"] = df["user_agent"].str.lower().str.contains(
        "sqlmap|hydra|nikto|nmap|python-requests|curl|acunetix|burp", regex=True
    ).astype(int)

    # Requests-per-IP-per-minute -> brute force burst detector
    if "timestamp" in df.columns:
        df["parsed_time"] = pd.to_datetime(
            df["timestamp"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce"
        )
        df["minute_bucket"] = df["parsed_time"].dt.floor("min")
        freq = df.groupby(["ip", "minute_bucket"])["ip"].transform("count")
        df["requests_per_minute"] = freq.fillna(1).astype(int)
    else:
        df["requests_per_minute"] = 1

    df["login_burst"] = ((df["is_login_endpoint"] == 1) & (df["requests_per_minute"] >= 5)).astype(int)

    return df


FEATURE_COLUMNS = [
    "url_length", "num_params", "num_special_chars",
    "has_sqli_pattern", "has_xss_pattern", "is_login_endpoint",
    "is_post", "status_is_error", "is_known_attack_tool_ua",
    "requests_per_minute", "login_burst",
]

if __name__ == "__main__":
    df = parse_log_file("data/access.log")
    df = extract_features(df)
    print(df[["ip", "url", "method"] + FEATURE_COLUMNS].head(10).to_string())
    print(f"\nParsed {len(df)} log lines.")
