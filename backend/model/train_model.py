"""
Train the Random Forest phishing-detection model.

Run this once (or whenever dataset.csv is updated):
    cd backend/model
    python train_model.py

This will create model.pkl in the same folder, which app.py loads at startup.
"""

import os
import sys
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Allow importing feature_extraction.py from the parent (backend) folder
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from feature_extraction import extract_features, FEATURE_COLUMNS  # noqa: E402


def load_dataset(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    feature_rows = [extract_features(url) for url in df["url"]]
    features_df = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
    features_df["label"] = df["label"].values
    return features_df


def train():
    here = os.path.dirname(__file__)
    csv_path = os.path.join(here, "dataset.csv")
    model_path = os.path.join(here, "model.pkl")

    data = load_dataset(csv_path)
    X = data[FEATURE_COLUMNS]
    y = data["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print(f"Test accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"]))

    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")


if __name__ == "__main__":
    train()
