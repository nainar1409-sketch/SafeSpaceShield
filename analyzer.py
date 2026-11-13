
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
    "bank details",
    "account has been suspended",
    "account suspended",
    "account is suspended",
    "account access will be suspended",
    "package is on hold",
    "pay the delivery fee",
    "redelivery fee",
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
    "free-gift",
    "delivery-update",
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
        r'''(?:https?://|www\.)[^\s<>"']+''',
        message,
        flags=re.IGNORECASE
    )

    # Remove punctuation at the end
    urls = [
        url.rstrip(".,!?;:)]}")
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

    # Identify IP URLs that do not already contain
    # a suspicious URL pattern.
    ip_urls_without_pattern = [
        url for url in ip_results
        if not any(
            pattern in url.lower()
            for pattern in SUSPICIOUS_URL_KEYWORDS
        )
    ]

    # Calculate risk score without double-counting.
    score = (
        sum(
            3 if keyword in sensitive_keywords else 1
            for keyword in keyword_results
        )
        + (len(url_results) * 2)
        + (len(ip_urls_without_pattern) * 2)
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
    ip_results = detect_ip_based_urls(message)
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
        recommendations.append(
            "Do not let urgent language pressure you into acting quickly."
        )

    if "account is blocked" in keyword_results or "account blocked" in keyword_results:
        reasons.append(
            "The message claims that an account is blocked."
        )
        recommendations.append(
            "Check your account directly through the organization's official website."
        )

    if any(
        keyword in keyword_results
        for keyword in [
            "account has been suspended",
            "account is suspended",
            "account access will be suspended"
        ]
    ):
        reasons.append(
            "The message claims that an account has been suspended or will be suspended."
        )
        recommendations.append(
            "Verify account suspension claims directly through the organization's official website."
        )
        

    if "verify your account" in keyword_results:
        reasons.append(
            "The message asks the recipient to verify an account."
        )

    if url_results:
        reasons.append(
            "The message contains potentially suspicious URL patterns."
        )
        recommendations.append(
            "Avoid clicking suspicious links. Visit the official website directly instead."
        )

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

    if any(
        keyword in keyword_results
        for keyword in ["otp", "password", "bank details"]
    ):
        recommendations.append(
            "Never share OTPs, passwords, or sensitive banking information."
        )

    if risk_results["risk_level"] == "High":
        recommendations.extend([
            "Contact the organization through its official website or phone number.",
            "Report the suspicious message."
        ])

    elif risk_results["risk_level"] == "Medium":
        recommendations.extend([
            "Check the sender's identity carefully.",
            "Verify important claims through official channels."
        ])

    else:
        recommendations.extend([
            "Remain cautious when interacting with unexpected messages.",
            "Check links and sender details before taking action."
        ])

    if not reasons:
        reasons.append(
            "No suspicious indicators from the current detection rules were found."
        )

    # Remove duplicate recommendations while preserving order.
    recommendations = list(dict.fromkeys(recommendations))

    return {
        "reasons": reasons,
        "recommendations": recommendations
    }

