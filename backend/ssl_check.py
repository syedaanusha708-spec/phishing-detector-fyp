"""
SSL Certificate Checker (basic version)
------------------------------------------
Checks whether a domain has a valid, currently-trusted SSL certificate.
Phishing sites often use no certificate, a self-signed one, or an expired
one — this is a quick basic signal, not a full certificate-chain audit.

Uses only Python's built-in `ssl` and `socket` modules — no extra
dependency needed.
"""

import ssl
import socket
from datetime import datetime


def check_ssl_certificate(domain: str, timeout: int = 5) -> dict:
    """
    Connect to the domain on port 443 and inspect its SSL certificate.
    Returns valid=True/False plus the certificate expiry date if available.
    """
    # Strip protocol/path if a full URL was passed instead of a bare domain
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.split(":")[0]

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert.get("notAfter")
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        is_expired = expiry_date < datetime.utcnow()

        return {
            "available": True,
            "valid": not is_expired,
            "issuer": dict(x[0] for x in cert.get("issuer", [])).get(
                "organizationName", "Unknown"
            ),
            "expires": expiry_date.strftime("%Y-%m-%d"),
        }
    except Exception as e:
        # No cert, connection refused, self-signed cert rejected, timeout, etc.
        return {"available": False, "valid": False, "reason": str(e)}
