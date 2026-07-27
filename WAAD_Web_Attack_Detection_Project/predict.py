"""
predict.py
----------
Loads the trained model and classifies a raw Apache access.log file into
Normal / Attack + Attack Type + Risk Level. Used by the Flask dashboard.
"""

import joblib
import pandas as pd

from preprocess import parse_log_file, extract_features, FEATURE_COLUMNS

MODEL_PATH = "models/attack_classifier.joblib"
ENCODER_PATH = "models/label_encoder.joblib"


def risk_level(attack_type: str, requests_per_minute: int) -> str:
    """Risk scoring logic matching the dashboard's Risk Level column."""
    if attack_type == "None":
        return "Low"
    if attack_type == "SQL Injection":
        return "Critical" if requests_per_minute >= 5 else "High"
    if attack_type == "Brute Force":
        return "High" if requests_per_minute >= 5 else "Medium"
    if attack_type == "XSS":
        return "Medium"
    return "Low"


def classify_log_file(log_path: str) -> pd.DataFrame:
    model = joblib.load(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)

    df = parse_log_file(log_path)
    df = extract_features(df)

    X = df[FEATURE_COLUMNS]
    preds_encoded = model.predict(X)
    df["attack_type"] = le.inverse_transform(preds_encoded)
    df["prediction"] = df["attack_type"].apply(lambda a: "Normal" if a == "None" else "Malicious")
    df["risk_level"] = df.apply(
        lambda r: risk_level(r["attack_type"], r["requests_per_minute"]), axis=1
    )

    out_cols = [
        "timestamp", "ip", "method", "url", "status", "user_agent",
        "attack_type", "prediction", "risk_level",
    ]
    return df[out_cols].sort_values("timestamp", ascending=False).reset_index(drop=True)


if __name__ == "__main__":
    result = classify_log_file("data/access.log")
    result.to_csv("data/classified_logs.csv", index=False)
    print(result.head(15).to_string())
    print(f"\nTotal requests: {len(result)}")
    print(f"Total attacks: {(result['prediction'] == 'Malicious').sum()}")
    print(result["attack_type"].value_counts())
