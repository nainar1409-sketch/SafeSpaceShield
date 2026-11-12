
# SafeSpace Shield - Detection Engine

import re
import ipaddress
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "immediately",
    "account blocked",
    "account is blocked",
    "account suspended",
    "verify your account",
    "click here",
    "limited time",
    "won a prize",
    "claim your reward",
    "otp",
    "password",
    "bank details"
]


SUSPICIOUS_URL_KEYWORDS = [
    "bank-verify",
    "account-verify",
    "free-prize",
    "claim-reward",
    "login-verify",
    "secure-update",
     "account-suspended",
    "verify-identity",
    "password-reset",
    "secure-login",
    "update-payment",
    "free-gift"
]

def detect_suspicious_keywords(message):
    detected_keywords = []

    message = message.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in message:
            detected_keywords.append(keyword)

    return detected_keywords


def detect_suspicious_url_patterns(message):
    detected_url_patterns = []

    message = message.lower()

    # Extract URLs from the message
    urls = re.findall(
        r'''(?:https?://|www\.)[^\s<>"']+''',
        message,
        flags=re.IGNORECASE
    )

    # Remove punctuation at the end of URLs
    urls = [
        url.rstrip(".,!?;:)]}")
        for url in urls
    ]

    # Check suspicious patterns only inside URLs
    for url in urls:
        for pattern in SUSPICIOUS_URL_KEYWORDS:
            if pattern in url and pattern not in detected_url_patterns:
                detected_url_patterns.append(pattern)

    return detected_url_patterns


def detect_ip_based_urls(message):

    detected_ip_urls = []

    # Extract URLs from the message
    urls = re.findall(
        r'https?://\S+|www\.\S+',
        message.lower()
    )

    # Remove punctuation at the end
    urls = [
        url.rstrip(".,!?;:)")
        for url in urls
    ]

    for url in urls:

        # Extract the hostname
        parsed_url = urlparse(
            url if "://" in url else "//" + url
        )

        hostname = parsed_url.hostname

        if hostname is None:
            continue

        try:
            # Check whether hostname is a valid IP address
            ipaddress.ip_address(hostname)

            detected_ip_urls.append(url)

        except ValueError:
            continue

    return detected_ip_urls



def calculate_risk(message):

    keyword_results = detect_suspicious_keywords(message)

    url_results = detect_suspicious_url_patterns(message)

    ip_results = detect_ip_based_urls(message)

    sensitive_keywords = ["otp", "password", "bank details"]

    score = (
        sum(
            3 if keyword in sensitive_keywords else 1
            for keyword in keyword_results
        )
        + (len(url_results) * 2)
        + (len(ip_results) * 2)
    )

    if score >= 5:
        risk_level = "High"

    elif score >= 2:
        risk_level = "Medium"

    else:
        risk_level = "Low"

    return {
        "score": score,
        "risk_level": risk_level,
        "keyword_count": len(keyword_results),
        "url_pattern_count": len(url_results),
        "ip_url_count": len(ip_results)
    }


def generate_explanation(message):

    keyword_results = detect_suspicious_keywords(message)
    url_results = detect_suspicious_url_patterns(message)
    risk_results = calculate_risk(message)

    reasons = []
    recommendations = []

    if keyword_results:
        reasons.append(
            "The message contains suspicious words or phrases."
        )

    if "urgent" in keyword_results or "immediately" in keyword_results:
        reasons.append(
            "The message uses urgency or pressure tactics."
        )

    if "account is blocked" in keyword_results or "account blocked" in keyword_results:
        reasons.append(
            "The message claims that an account is blocked."
        )

    if "verify your account" in keyword_results:
        reasons.append(
            "The message asks the recipient to verify an account."
        )

    if url_results:
        reasons.append(
            "The message contains potentially suspicious URL patterns."
        )

        ip_results = detect_ip_based_urls(message)

        if ip_results:
            reasons.append(
                "The message contains a URL that uses an IP address instead of a domain name."
            )

    if "otp" in keyword_results:
        reasons.append(
            "The message may be attempting to obtain a one-time password (OTP)."
        )

    if "password" in keyword_results:
        reasons.append(
            "The message requests sensitive login credentials."
        )        

    if "bank details" in keyword_results:
        reasons.append(
            "The message requests sensitive banking information."
        )

    if risk_results["risk_level"] == "High":
        recommendations = [
            "Do not click suspicious links.",
            "Never share passwords or OTPs.",
            "Contact the organization through its official website or phone number.",
            "Report the suspicious message."
        ]

    elif risk_results["risk_level"] == "Medium":
        recommendations = [
            "Check the sender's identity carefully.",
            "Avoid clicking unexpected links.",
            "Never share sensitive information.",
            "Verify important claims through official channels."
        ]

    else:
        recommendations = [
            "Remain cautious when interacting with unexpected messages.",
            "Check links and sender details before taking action.",
            "Never share passwords or OTPs."
        ]

    ip_results = detect_ip_based_urls(message)

    if ip_results:
        reasons.append(
            "The message contains a URL that uses an IP address instead of a domain name."
        )

    if not reasons:
        reasons.append(
            "No suspicious indicators from the current detection rules were found."
        )

    return {
        "reasons": reasons,
        "recommendations": recommendations
    }

