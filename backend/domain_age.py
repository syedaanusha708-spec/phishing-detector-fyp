"""
Domain Age Checker (basic version)
------------------------------------
Newly registered domains are a common phishing signal — attackers register
a fresh domain, use it for a short phishing campaign, then abandon it.

This is a BASIC implementation for FYP-I demo purposes:
- Uses the `python-whois` library to fetch registration info
- Returns age in days + a simple "suspicious" flag if the domain is very new
- Wrapped in try/except because WHOIS lookups can fail (rate limits, privacy
  protection, missing records, network issues) — this should never crash
  the /scan endpoint.
"""

import socket
from datetime import datetime, timezone
import whois  # pip install python-whois

# WHOIS servers can be slow or unreachable — cap the socket timeout so a
# single bad lookup can't hang the whole /scan request.
socket.setdefaulttimeout(5)


def check_domain_age(domain: str) -> dict:
    """
    Look up how old a domain is.
    Returns a dict with age_days, creation_date, and a suspicious flag.
    If the lookup fails, returns available=False so the caller can
    gracefully skip this signal instead of crashing.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # python-whois sometimes returns a list of dates — take the earliest
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"available": False, "reason": "No creation date found"}

        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation_date).days

        return {
            "available": True,
            "age_days": age_days,
            "creation_date": creation_date.strftime("%Y-%m-%d"),
            # Basic heuristic: domains younger than 90 days are treated as
            # more suspicious. This threshold is intentionally simple for
            # FYP-I — can be tuned with real data later.
            "suspicious": age_days < 90,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}
