"""
Phishing Website Detection Tool — Backend
------------------------------------------
Handles Single & Bulk Scans across all common frontend routes.
"""

import os
import re
from urllib.parse import urlparse
import joblib
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify
from flask_cors import CORS

from feature_extraction import extract_features, features_to_vector
from domain_age import check_domain_age
from ssl_check import check_ssl_certificate
from typosquat_check import check_typosquatting

TOP_DOMAINS = [
    'facebook.com', 'google.com', 'youtube.com', 'instagram.com', 
    'twitter.com', 'x.com', 'linkedin.com', 'github.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'paypal.com'
]

app = Flask(__name__)
# Universal CORS setup to avoid fetch block
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "model.pkl")
model = None


def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("Model loaded successfully.")
    else:
        model = None
        print("WARNING: model.pkl not found.")


def sanitize_and_normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    raw_url = raw_url.replace(",com", ".com").replace(",net", ".net").replace(",org", ".org")
    raw_url = re.sub(r',([a-zA-Z]{2,10})', r'.\1', raw_url)
    raw_url = raw_url.rstrip(".,;")
    raw_url = re.sub(r'[\.,]{2,}', '.', raw_url)

    if not raw_url.startswith(("http://", "https://")):
        return "https://" + raw_url

    return raw_url


def is_official_domain(domain: str) -> bool:
    domain_clean = domain.lower()
    if domain_clean.startswith("www."):
        domain_clean = domain_clean[4:]
    elif domain_clean.startswith("m."):
        domain_clean = domain_clean[2:]
        
    return domain_clean in TOP_DOMAINS


def inspect_dom(normalized_url: str) -> dict:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(normalized_url, timeout=2, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        
        domain = urlparse(normalized_url).netloc.lower().replace("www.", "")
        dom_alerts = []
        
        has_password = bool(soup.find("input", {"type": "password"}))
        official = is_official_domain(domain)

        if has_password and not official:
            dom_alerts.append("Credential Input Alert: Active password field found on an unverified domain.")
            
        page_title = soup.title.string.strip() if soup.title and soup.title.string else ""
        title_lower = page_title.lower()
        
        top_brands = ["microsoft", "google", "paypal", "netflix", "facebook", "apple", "amazon"]
        for brand in top_brands:
            if brand in title_lower and brand not in domain:
                dom_alerts.append(f"Brand Impersonation: Page references '{brand.capitalize()}'.")

        return {
            "scraped_title": page_title or "N/A",
            "has_login_form": has_password,
            "dom_alerts": dom_alerts
        }
    except Exception:
        return {
            "scraped_title": "Unable to inspect (Offline or unreachable)",
            "has_login_form": False,
            "dom_alerts": []
        }


def run_full_scan(raw_url: str) -> dict:
    normalized_url = sanitize_and_normalize_url(raw_url)
    parsed_netloc = urlparse(normalized_url).netloc

    # Smart Check for Malformed / Fake Domain structures (like @ symbols or invalid extensions)
    if "@" in raw_url or not re.search(r'\.[a-zA-Z]{2,}$', parsed_netloc):
        return {
            "url": normalized_url,
            "is_phishing": True,
            "confidence": 95.0,
            "risk_level": "High",
            "features": {},
            "domain_age": {"suspicious": True, "days": None},
            "ssl_certificate": {"valid": False},
            "typosquatting": {"is_typosquat": True},
            "dom_inspection": {"scraped_title": "Malformed URL", "has_login_form": False, "dom_alerts": ["Malformed or Suspicious URL Structure Detected"]}
        }
    
    features = extract_features(normalized_url)
    vector = [features_to_vector(features)]

    ml_prediction = bool(model.predict(vector)[0]) if model else False
    ml_phishing_prob = float(model.predict_proba(vector)[0][1]) if model else 0.0

    domain = parsed_netloc.split(":")[0].lower()

    domain_age_res = check_domain_age(domain)
    ssl_res = check_ssl_certificate(domain)
    typo_res = check_typosquatting(normalized_url)
    dom_res = inspect_dom(normalized_url)

    whitelisted = is_official_domain(domain)

    suspicious_keywords = ["account", "login", "signin", "verify", "secure", "update", "banking", "auth", "security"]
    has_brand_keyword_impersonation = False

    if not whitelisted:
        for brand in ["google", "facebook", "paypal", "microsoft", "apple", "amazon"]:
            if brand in domain:
                for kw in suspicious_keywords:
                    if kw in domain or kw in raw_url.lower():
                        has_brand_keyword_impersonation = True
                        break

    if whitelisted:
        is_phishing = False
        confidence = 99.0
        risk = "Very Safe"
    else:
        risk_score = ml_phishing_prob * 0.35

        if dom_res.get("dom_alerts"):
            risk_score += 0.25

        is_typosquat = typo_res.get("is_typosquat", False)
        if is_typosquat or has_brand_keyword_impersonation:
            risk_score += 0.40

        if not ssl_res.get("valid", True):
            risk_score += 0.15

        if domain_age_res.get("suspicious", False) or domain_age_res.get("days") is None:
            risk_score += 0.10

        is_phishing = (risk_score >= 0.35) or is_typosquat or has_brand_keyword_impersonation
        
        computed_conf = risk_score * 100
        if (is_typosquat or has_brand_keyword_impersonation) and computed_conf < 75.0:
            computed_conf = 82.0

        confidence = round(min(max(computed_conf, 15.0), 99.0), 1)

        if confidence >= 70.0:
            risk = "High"
        elif confidence >= 45.0:
            risk = "Medium"
        elif confidence >= 25.0:
            risk = "Low"
        else:
            risk = "Very Safe"

    return {
        "url": normalized_url,
        "is_phishing": is_phishing,
        "confidence": confidence,
        "risk_level": risk,
        "features": features,
        "domain_age": domain_age_res,
        "ssl_certificate": ssl_res,
        "typosquatting": typo_res,
        "dom_inspection": dom_res
    }


# Home Route for Render URL
@app.route('/')
def home():
    return "Phishing Detector API is running!"


# Single URL Scan Route
@app.route("/scan", methods=["POST", "OPTIONS"])
@app.route("/api/scan", methods=["POST", "OPTIONS"])
def scan_url():
    if request.method == "OPTIONS":
        return "", 200
        
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "Please provide a 'url' field."}), 400

    return jsonify(run_full_scan(url))


# Catch-All Bulk Scan Endpoints for Any Frontend Naming
@app.route("/bulk-scan", methods=["POST", "OPTIONS"])
@app.route("/bulk", methods=["POST", "OPTIONS"])
@app.route("/scan-bulk", methods=["POST", "OPTIONS"])
@app.route("/api/bulk-scan", methods=["POST", "OPTIONS"])
@app.route("/api/bulk", methods=["POST", "OPTIONS"])
def bulk_scan():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    
    # Accept 'urls', 'url_list', or 'data' formats
    urls = data.get("urls") or data.get("url_list") or data.get("data") or []

    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split("\n") if u.strip()]

    if not urls:
        return jsonify({"error": "Please provide a list of URLs."}), 400

    results = [run_full_scan(u) for u in urls[:25]]
    
    # Return both list formats in case frontend expects an array or object
    return jsonify({"results": results, "data": results, "total": len(results)})


if __name__ == "__main__":
    load_model()
    app.run(debug=True, host="0.0.0.0", port=5000)