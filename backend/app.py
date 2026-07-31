"""
Phishing Website Detection Tool — Backend (FYP Skeleton)
----------------------------------------------------------
Flask REST API that serves the Random Forest phishing-URL model.

Endpoints:
    GET  /health         -> simple health check
    POST /scan            -> { "url": "..." }        -> prediction + confidence
                              + domain age, SSL check, typosquat check
    POST /scan-bulk        -> { "urls": [...] }        -> /scan result for each URL
    POST /scan-email      -> { "email_text": "..." } -> basic keyword-based check

Run:
    pip install -r requirements.txt
    python model/train_model.py      # trains and saves model.pkl (run once)
    python app.py                    # starts the API on http://localhost:5000
"""

import os
from urllib.parse import urlparse
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature_extraction import extract_features, features_to_vector
from domain_age import check_domain_age
from ssl_check import check_ssl_certificate
from typosquat_check import check_typosquatting

app = Flask(__name__)
CORS(app)  # allow React (port 3000/5173) to call this API

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "model.pkl")
model = None

# Basic keyword list for the email scanner skeleton.
# TODO (future feature): replace with a proper NLP/ML-based classifier.
PHISHING_KEYWORDS = [
    "verify your account", "account suspended", "click here immediately",
    "confirm your password", "urgent action required", "your account has been locked",
    "update your billing", "unusual login attempt", "claim your prize",
    "limited time offer", "security alert", "reset your password now",
]


def load_model():
    """Load the trained model into memory. Called once at startup."""
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("Model loaded successfully.")
    else:
        model = None
        print("WARNING: model.pkl not found. Run model/train_model.py first.")


def risk_level(confidence: float) -> str:
    """Map a phishing-probability score to a human-readable risk label."""
    if confidence >= 0.75:
        return "High"
    elif confidence >= 0.5:
        return "Medium"
    elif confidence >= 0.25:
        return "Low"
    return "Very Safe"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})


def run_full_scan(url: str) -> dict:
    """
    Run the ML prediction plus the 3 extra basic checks for a single URL.
    Shared by /scan (one URL) and /scan-bulk (many URLs) so the logic
    lives in one place.
    """
    features = extract_features(url)
    vector = [features_to_vector(features)]

    prediction = model.predict(vector)[0]                # 0 = safe, 1 = phishing
    probability = model.predict_proba(vector)[0][1]       # probability of phishing

    domain = urlparse(url if "://" in url else "http://" + url).netloc.split(":")[0]

    return {
        "url": url,
        "is_phishing": bool(prediction),
        "confidence": round(float(probability) * 100, 2),
        "risk_level": risk_level(probability),
        "features": features,
        # ---- Basic extra checks (FYP-I level — simple, not exhaustive) ----
        "domain_age": check_domain_age(domain),
        "ssl_certificate": check_ssl_certificate(domain),
        "typosquatting": check_typosquatting(url),
        # --------------------------------------------------------------
        # FUTURE FEATURE HOOKS for FYP-II, e.g.:
        #   "virustotal": check_virustotal(url),
        # --------------------------------------------------------------
    }


@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please provide a 'url' field."}), 400

    if model is None:
        return jsonify({"error": "Model not loaded. Train the model first."}), 503

    result = run_full_scan(url)
    return jsonify(result)


@app.route("/scan-bulk", methods=["POST"])
def scan_bulk():
    """
    Basic bulk scanner: accepts a list of URLs and returns the same
    result shape as /scan for each one.
    Body: { "urls": ["http://a.com", "http://b.com", ...] }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Please provide a non-empty 'urls' list."}), 400

    if model is None:
        return jsonify({"error": "Model not loaded. Train the model first."}), 503

    # Basic cap so a demo can't accidentally submit thousands of URLs at once
    urls = [u.strip() for u in urls if u.strip()][:25]

    results = []
    for url in urls:
        try:
            results.append(run_full_scan(url))
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return jsonify({"count": len(results), "results": results})


@app.route("/scan-email", methods=["POST"])
def scan_email():
    data = request.get_json(silent=True) or {}
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "Please provide an 'email_text' field."}), 400

    text_lower = email_text.lower()
    matched = [kw for kw in PHISHING_KEYWORDS if kw in text_lower]

    # Very simple scoring for the skeleton — refine later with a trained model
    score = min(len(matched) / 3, 1.0)
    is_phishing = score >= 0.34

    result = {
        "is_phishing": is_phishing,
        "confidence": round(score * 100, 2),
        "risk_level": risk_level(score),
        "matched_keywords": matched,
    }
    return jsonify(result)


if __name__ == "__main__":
    load_model()
    app.run(debug=True, port=5000)
