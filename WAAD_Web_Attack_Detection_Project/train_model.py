"""
train_model.py
---------------
Trains the Machine Learning model (Random Forest, as specified in the
project's Proposed Methodology) to classify each request as:
    Normal / SQL Injection / XSS / Brute Force

Input:  data/labeled_logs.csv  (produced by generate_logs.py, OR your own
        labeled data if you hand-labeled a real DVWA attack session)
Output: models/attack_classifier.joblib
        models/label_encoder.joblib
        Console: accuracy, classification report, confusion matrix
"""

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from preprocess import extract_features, FEATURE_COLUMNS


def load_training_data(path="data/labeled_logs.csv"):
    df = pd.read_csv(path, keep_default_na=False, na_values=[])
    # labeled_logs.csv already has url/method/status/etc columns matching
    # what extract_features expects, plus ground-truth attack_type/label
    df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%d/%b/%Y:%H:%M:%S +0530")
    df = extract_features(df)
    return df


def train():
    df = load_training_data()

    X = df[FEATURE_COLUMNS]
    y = df["attack_type"]  # None / SQL Injection / XSS / Brute Force

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.25, random_state=42, stratify=y_encoded
    )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, class_weight="balanced"
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"Test Accuracy: {acc*100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("Confusion Matrix:")
    print(pd.DataFrame(
        confusion_matrix(y_test, y_pred),
        index=le.classes_, columns=le.classes_
    ))

    print("\nFeature Importances:")
    fi = pd.Series(model.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print(fi.to_string())

    joblib.dump(model, "models/attack_classifier.joblib")
    joblib.dump(le, "models/label_encoder.joblib")
    print("\nSaved model -> models/attack_classifier.joblib")
    print("Saved label encoder -> models/label_encoder.joblib")


if __name__ == "__main__":
    train()
