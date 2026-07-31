"""
Feature Extraction Module
--------------------------
Extracts 8 URL-based features used by the Random Forest model
to classify a URL as phishing or safe.

Features:
1. url_length        -> total length of the URL
2. has_https         -> 1 if URL uses HTTPS, else 0
3. has_at_symbol      -> 1 if '@' appears in the URL, else 0
4. has_ip             -> 1 if the domain is a raw IP address, else 0
5. dot_count          -> number of '.' characters in the URL
6. hyphen_count       -> number of '-' characters in the URL
7. domain_length      -> length of the domain portion
8. has_subdomain      -> 1 if there is more than one subdomain level
"""

import re
from urllib.parse import urlparse


def _get_domain(url: str) -> str:
    """Safely extract the domain (netloc) from a URL."""
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        return parsed.netloc
    except Exception:
        return ""


def _is_ip_address(domain: str) -> bool:
    """Check whether the domain portion is a raw IPv4 address."""
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    domain_no_port = domain.split(":")[0]
    return bool(ip_pattern.match(domain_no_port))


def extract_features(url: str) -> dict:
    """
    Extract the 8 features from a given URL.
    Returns a dict so it can be used both for training (via a DataFrame)
    and for a single live prediction from the Flask API.
    """
    url = url.strip()
    domain = _get_domain(url)

    features = {
        "url_length": len(url),
        "has_https": 1 if url.lower().startswith("https://") else 0,
        "has_at_symbol": 1 if "@" in url else 0,
        "has_ip": 1 if _is_ip_address(domain) else 0,
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "domain_length": len(domain),
        "has_subdomain": 1 if domain.count(".") > 1 else 0,
    }
    return features


# Keep a fixed column order — must match the order used during training
FEATURE_COLUMNS = [
    "url_length",
    "has_https",
    "has_at_symbol",
    "has_ip",
    "dot_count",
    "hyphen_count",
    "domain_length",
    "has_subdomain",
]


def features_to_vector(features: dict) -> list:
    """Convert a features dict into an ordered list for model.predict()."""
    return [features[col] for col in FEATURE_COLUMNS]
