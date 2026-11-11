
from analyzer import (
    detect_suspicious_keywords,
    detect_suspicious_url_patterns,
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
