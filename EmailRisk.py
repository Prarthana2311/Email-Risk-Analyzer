import email
from email import policy
import re
from urllib.parse import urlparse

# Detection dictionaries and patterns
URGENT_PHRASES = [
    r"\burgent\b",
    r"\bimmediate action required\b",
    r"\baccount suspended\b",
    r"\bverify your account\b",
    r"\bpassword reset\b",
    r"\blogin immediately\b",
    r"\bupdate payment\b",
    r"\bunauthorized access\b",
    r"\bsecurity alert\b",
    r"\bwire transfer\b",
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".buzz", ".work", ".tk", ".ml", ".ga"}


def extract_email_address(header_value: str) -> str:
    """Extracts raw email from header formats like 'Name <user@domain.com>'."""
    if not header_value:
        return ""
    match = re.search(r"[\w\.-]+@[\w\.-]+", header_value)
    return match.group(0).lower() if match else ""


def extract_domain(email_str: str) -> str:
    """Extracts domain part from an email string."""
    if "@" in email_str:
        return email_str.split("@")[-1].strip().lower()
    return ""


def analyze_email(raw_eml_str: str) -> dict:
    msg = email.message_from_string(raw_eml_str, policy=policy.default)
    score = 0
    findings = []

    # 1. Header Checks: From vs Return-Path Spoofing
    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    from_addr = extract_email_address(from_header)
    return_addr = extract_email_address(return_path)

    from_domain = extract_domain(from_addr)
    return_domain = extract_domain(return_addr)

    if return_domain and from_domain and return_domain != from_domain:
        score += 30
        findings.append(
            f"Domain Mismatch: 'From' domain ({from_domain}) != 'Return-Path' ({return_domain})"
        )

    # 2. Authentication Headers (SPF & DKIM)
    auth_results = (
        msg.get("Authentication-Results", "")
        + " "
        + msg.get("Received-SPF", "")
    ).lower()

    if "spf=fail" in auth_results or "spf=softfail" in auth_results:
        score += 25
        findings.append("SPF check failed or soft-failed")
    elif "spf=" not in auth_results:
        score += 10
        findings.append("Missing SPF authentication records")

    if "dkim=fail" in auth_results:
        score += 25
        findings.append("DKIM signature validation failed")

    # 3. Body Extraction (Plain text & HTML fallback)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ["text/plain", "text/html"]:
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        body = msg.get_content()

    body_lower = body.lower()

    # 4. Urgent & Coercive Lure Keywords
    matched_phrases = []
    for pattern in URGENT_PHRASES:
        if re.search(pattern, body_lower):
            matched_phrases.append(pattern.replace(r"\b", ""))

    if matched_phrases:
        weight = min(len(matched_phrases) * 10, 30)
        score += weight
        findings.append(f"Urgent lure patterns detected: {', '.join(matched_phrases)}")

    # 5. Link & URL Analysis
    urls = re.findall(
        r'https?://[^\s<>"\']+|href=["\'](https?://[^"\']+)["\']', body
    )
    # Flatten regex capture groups
    extracted_urls = [u[0] or u[1] for u in urls] if urls and isinstance(urls[0], tuple) else urls

    suspicious_urls = []
    for url in set(extracted_urls):
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        # IP address in URL
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            suspicious_urls.append(f"{url} (Raw IP host)")
            score += 20
            continue

        # Suspicious TLD
        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            suspicious_urls.append(f"{url} (High-risk TLD)")
            score += 15

    if suspicious_urls:
        findings.append(f"Suspicious link targets: {', '.join(suspicious_urls)}")

    # Score clamping & verdict
    score = min(score, 100)
    if score >= 70:
        verdict = "HIGH RISK (Likely Phishing / Malicious)"
    elif score >= 40:
        verdict = "MEDIUM RISK (Suspicious Indicators Present)"
    else:
        verdict = "LOW RISK (Legitimate / Clean)"

    return {
        "subject": msg.get("Subject", "N/A"),
        "from": from_header,
        "return_path": return_path,
        "score": score,
        "verdict": verdict,
        "findings": findings,
    }


def print_audit_report(report: dict):
    print("=" * 60)
    print("           EMAIL SECURITY AUDIT REPORT")
    print("=" * 60)
    print(f"Subject       : {report['subject']}")
    print(f"From          : {report['from']}")
    print(f"Return-Path   : {report['return_path']}")
    print(f"Risk Score    : {report['score']}/100")
    print(f"Verdict       : {report['verdict']}")
    print("-" * 60)
    print("Key Findings:")
    if report["findings"]:
        for idx, item in enumerate(report["findings"], 1):
            print(f"  [{idx}] {item}")
    else:
        print("  None detected.")
    print("=" * 60)


# ================= Example Usage =================
if __name__ == "__main__":
    sample_phishing_email = """From: Security Team <alerts@paypal-security-center.xyz>
Return-Path: <bounce@attacker-relay.com>
Subject: URGENT: Account Suspended - Immediate Action Required
Authentication-Results: mx.google.com; spf=fail; dkim=fail
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We detected unauthorized access to your account. Your account suspended until verified.
Immediate action required: please login immediately to verify your account and avoid permanent closure.

Follow link: http://192.168.1.55/update-login

Thank you,
Support Team
"""
    result = analyze_email(sample_phishing_email)
    print_audit_report(result)