
import streamlit as st

from analyzer import (
    detect_suspicious_keywords,
    detect_suspicious_url_patterns,
    calculate_risk,
    generate_explanation
)

# Page configuration
st.set_page_config(
    page_title="SafeSpace Shield",
    page_icon="🛡️",
    layout="centered"
)

# Application heading
st.title("🛡️ SafeSpace Shield")

st.subheader(
    "Think Before You Click. Understand Before You Trust."
)

st.write(
    "Analyze suspicious messages, identify warning signs, "
    "and learn how to stay safer online."
)

st.divider()

# Message input section
st.header("Message Analyzer")

message = st.text_area(
    "Paste a suspicious message here:",
    placeholder="Paste an SMS, email, or suspicious message...",
    height=150
)

# Analysis button
if st.button("🔍 Analyze Message", use_container_width=True):

    if message.strip():

        # Run detection engine
        keyword_results = detect_suspicious_keywords(message)

        url_results = detect_suspicious_url_patterns(message)

        risk_results = calculate_risk(message)

        explanation_results = generate_explanation(message)

        # Display analysis results
        st.divider()

        st.header("Analysis Report")

        # Display risk classification
        risk_level = risk_results["risk_level"]

        if risk_level == "High":
            st.error("🚨 High Risk Message")

        elif risk_level == "Medium":
            st.warning("⚠️ Medium Risk Message")

        else:
            st.info("ℹ️ Low Risk - No major indicators detected")

        # Display score and detection counts
        col1, col2, col3 = st.columns(3)

        col1.metric("Risk Score", risk_results["score"])

        col2.metric("Suspicious Keywords", len(keyword_results))

        col3.metric("URL Patterns", len(url_results))

        # Display detected keywords
        st.subheader("🔎 Detected Suspicious Keywords")

        if keyword_results:
            for keyword in keyword_results:
                st.write(f"⚠️ {keyword}")
        else:
            st.write("No suspicious keywords detected.")

        # Display URL patterns
        st.subheader("🔗 Detected URL Patterns")

        if url_results:
            for pattern in url_results:
                st.write(f"⚠️ {pattern}")
        else:
            st.write("No suspicious URL patterns detected.")

        # Display explanations
        st.subheader("🧠 Why Was This Message Flagged?")

        for reason in explanation_results["reasons"]:
            st.write(f"• {reason}")

        # Display safety recommendations
        st.subheader("🛡️ Safety Recommendations")

        for recommendation in explanation_results["recommendations"]:
            st.write(f"✅ {recommendation}")

        st.divider()

        st.caption(
            "SafeSpace Shield provides an initial automated assessment. "
            "A low-risk result does not guarantee that a message is safe. "
            "Always verify important requests through official channels."
        )

    else:
        st.warning("Please enter a message before analyzing.")

# Footer
st.divider()

st.caption("SafeSpace Shield | Your Online Safety Companion")
