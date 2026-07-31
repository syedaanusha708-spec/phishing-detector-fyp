"""
Typosquatting Detector (basic version)
------------------------------------------
Catches lookalike domains such as "paypa1.com", "g00gle.com", or
"micros0ft-support.com" that mimic popular brand names.

Basic approach for FYP-I: compare the domain against a small hardcoded
list of popular brands using Levenshtein (edit) distance. A small distance
(1-2 edits) to a known brand — but not an exact match — is flagged as
likely typosquatting.

For FYP-II this list could be expanded or replaced with a larger public
brand dataset.
"""

from urllib.parse import urlparse

# Small starter list of commonly-impersonated brands.
POPULAR_DOMAINS = [
    "google.com", "facebook.com", "paypal.com", "amazon.com", "apple.com",
    "microsoft.com", "netflix.com", "instagram.com", "linkedin.com",
    "twitter.com", "bankofamerica.com", "dropbox.com", "github.com",
    "yahoo.com", "outlook.com",
]


def _levenshtein(a: str, b: str) -> int:
    """Basic edit-distance implementation (no external library needed)."""
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def check_typosquatting(url: str) -> dict:
    """
    Compare the URL's domain against known popular domains.
    Flags it if it's a close-but-not-exact match (edit distance 1-2).
    """
    try:
        domain = urlparse(url if "://" in url else "http://" + url).netloc
        domain = domain.split(":")[0].lower()
        # strip a leading "www."
        if domain.startswith("www."):
            domain = domain[4:]

        for brand in POPULAR_DOMAINS:
            if domain == brand:
                return {"is_typosquat": False, "matched_brand": None}

            distance = _levenshtein(domain, brand)
            if 0 < distance <= 2:
                return {
                    "is_typosquat": True,
                    "matched_brand": brand,
                    "edit_distance": distance,
                }

        return {"is_typosquat": False, "matched_brand": None}
    except Exception as e:
        return {"is_typosquat": False, "matched_brand": None, "reason": str(e)}
