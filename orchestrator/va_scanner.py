from typing import List, Dict
import uuid

class VAAlert:
    def __init__(self, title: str, severity: str, description: str, recommendation: str):
        self.id = str(uuid.uuid4())
        self.title = title
        self.severity = severity # Low, Medium, High, Critical
        self.description = description
        self.recommendation = recommendation

def scan_security_headers(headers: Dict) -> List[VAAlert]:
    alerts = []

    # Check for Strict-Transport-Security
    if "Strict-Transport-Security" not in headers and "strict-transport-security" not in headers:
        alerts.append(VAAlert(
            title="Missing HSTS Header",
            severity="Medium",
            description="The Strict-Transport-Security header is missing. This could allow protocol downgrade attacks.",
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to your response headers."
        ))

    # Check for Content-Security-Policy
    if "Content-Security-Policy" not in headers and "content-security-policy" not in headers:
        alerts.append(VAAlert(
            title="Missing Content-Security-Policy",
            severity="High",
            description="The Content-Security-Policy (CSP) header is missing. This increases the risk of XSS attacks.",
            recommendation="Implement a robust CSP header to restrict where resources can be loaded from."
        ))

    # Check for X-Content-Type-Options
    if "X-Content-Type-Options" not in headers and "x-content-type-options" not in headers:
        alerts.append(VAAlert(
            title="Missing X-Content-Type-Options",
            severity="Low",
            description="The X-Content-Type-Options header is missing. This might allow MIME-sniffing vulnerabilities.",
            recommendation="Add 'X-Content-Type-Options: nosniff' to your response headers."
        ))

    return alerts
