
from analyzer import (
    detect_suspicious_keywords,
    detect_suspicious_url_patterns,
    detect_ip_based_urls,
    calculate_risk,
    generate_explanation
)

test_message = """
URGENT! Your bank account is blocked.
Verify your account immediately.
Visit http://bank-verify.example.com to restore access.
"""

keyword_results = detect_suspicious_keywords(test_message)
url_results = detect_suspicious_url_patterns(test_message)
risk_results = calculate_risk(test_message)
explanation_results = generate_explanation(test_message)

print("SAFE SPACE SHIELD - ANALYSIS REPORT")
print("-----------------------------------")

print("\nSuspicious Keywords:", keyword_results)
print("Suspicious URL Patterns:", url_results)

print("\nRisk Score:", risk_results["score"])
print("Risk Level:", risk_results["risk_level"])

print("\nWHY IS THIS MESSAGE SUSPICIOUS?")

for reason in explanation_results["reasons"]:
    print("-", reason)

print("\nSAFETY RECOMMENDATIONS")

for recommendation in explanation_results["recommendations"]:
    print("-", recommendation)

print("\nIP-BASED URL DETECTION TESTS")
print("----------------------------")

# Test 1: Valid IP-based URL
test1 = detect_ip_based_urls(
    "Visit http://192.168.1.10/login"
)
assert len(test1) == 1
print("Test 1 passed: Valid IP URL detected.")

# Test 2: Normal domain
test2 = detect_ip_based_urls(
    "Visit https://google.com/login"
)
assert len(test2) == 0
print("Test 2 passed: Normal domain not flagged.")

# Test 3: Invalid IP address
test3 = detect_ip_based_urls(
    "Visit http://256.300.1.5/login"
)
assert len(test3) == 0
print("Test 3 passed: Invalid IP rejected.")

print("\nAll IP detection tests passed!")

print("\nADDITIONAL URL PATTERN TESTS")
print("----------------------------")

new_patterns = [
    "account-suspended",
    "verify-identity",
    "password-reset",
    "secure-login",
    "update-payment",
    "free-gift"
]

for pattern in new_patterns:
    result = detect_suspicious_url_patterns(
        f"Visit https://{pattern}.example.com/login"
    )

    assert pattern in result
    print(f"Passed: {pattern}")

print("\nFALSE POSITIVE TESTS")
print("--------------------")

assert detect_suspicious_url_patterns(
    "I received a free-gift from my friend."
) == []

assert detect_suspicious_url_patterns(
    "The words secure-login appeared in our meeting notes."
) == []

assert detect_suspicious_url_patterns(
    "Visit https://google.com for information."
) == []

print("All 3 false-positive tests passed!")