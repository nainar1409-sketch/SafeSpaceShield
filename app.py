
import streamlit as st

from analyzer import (
    detect_suspicious_keywords,
    detect_suspicious_url_patterns,
    detect_ip_based_urls,
    calculate_risk,
    generate_explanation
)

# Page configuration
st.set_page_config(
    page_title="SafeSpace Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Sidebar
with st.sidebar:
    st.title("🛡️ SafeSpace Shield")

    st.markdown("### About")

    st.write(
        "An intelligent cybersecurity awareness tool "
        "that helps identify potential phishing and scam messages."
    )

    st.divider()

    st.markdown("### Features")

    st.markdown(
        """
        - Suspicious keyword detection
        - URL pattern detection
        - IP-based URL detection
        - Risk scoring
        - Safety recommendations
        """
    )

    st.divider()

    st.caption("Think Before You Click.")

# Function to clear the message
def clear_message():
    st.session_state["message_input"] = ""

# Application heading
st.title("🛡️ SafeSpace Shield")

st.markdown(
    "### Think Before You Click. Understand Before You Trust."
)

st.markdown(
    """
    Your personal online safety companion.

    Analyze suspicious SMS messages, emails, and links.
    Understand potential threats and learn how to protect yourself.
    """
)

st.divider()

# Message input section
st.header("🔍 Analyze a Message")

st.write(
    "Paste the message you want to check. "
    "SafeSpace Shield will analyze it for potential warning signs."
)

message = st.text_area(
    "Your message",
    placeholder=(
        "Example: Your bank account is blocked! "
        "Verify your account immediately..."
    ),
    height=180,
    max_chars=5000,
    key="message_input"
)

st.button(
    "🗑️ Clear Message",
    on_click=clear_message
)

st.caption(
    "Your message is analyzed locally by the application. "
    "Avoid entering real passwords, OTPs, or other sensitive information."
)

# Analysis button
if st.button("🔍 Analyze Message", use_container_width=True):

    if message.strip():

        # Run detection engine
        keyword_results = detect_suspicious_keywords(message)
        url_results = detect_suspicious_url_patterns(message)
        ip_results = detect_ip_based_urls(message)
        risk_results = calculate_risk(message)
        explanation_results = generate_explanation(message)

        # Analysis report
        st.divider()
        st.header("📋 Analysis Report")

        # Risk classification
        risk_level = risk_results["risk_level"]
        risk_score = risk_results["score"]

        with st.container(border=True):

            st.subheader("🚦 Security Assessment")

            if risk_level == "High":
                st.error(
                    "🚨 HIGH RISK — Multiple suspicious indicators detected."
                )

            elif risk_level == "Medium":
                st.warning(
                    "⚠️ MEDIUM RISK — Some suspicious indicators detected."
                )

            else:
                st.info(
                    "ℹ️ LOW RISK — No major indicators detected by current rules."
                )

            st.metric("Overall Risk Score", risk_score)

        # Detection metrics
        st.subheader("📊 Detection Summary")

        col1, col2, col3 = st.columns(3)

        col1.metric("Suspicious Keywords", len(keyword_results))
        col2.metric("URL Patterns", len(url_results))
        col3.metric("IP-Based URLs", len(ip_results))

        # Suspicious keywords
        st.subheader("🔎 Detected Suspicious Keywords")

        if keyword_results:
            for keyword in keyword_results:
                st.warning(keyword)
        else:
            st.success("No suspicious keywords detected.")

        # URL security analysis
        st.subheader("🔗 URL Security Analysis")

        if url_results:
            st.markdown("**Suspicious URL patterns detected:**")

            for pattern in url_results:
                st.warning(pattern)
        else:
            st.success("No suspicious URL patterns detected.")

        if ip_results:
            st.markdown("**IP-Based URLs detected:**")

            for ip_url in ip_results:
                st.warning(ip_url)
        else:
            st.info("No IP-based URLs detected.")

        # Explanations and recommendations
        col1, col2 = st.columns(2)

        with col1:
            with st.container(border=True):
                st.subheader("🧠 Why Was It Flagged?")

                for reason in explanation_results["reasons"]:
                    st.markdown(f"- {reason}")

        with col2:
            with st.container(border=True):
                st.subheader("🛡️ Safety Recommendations")

                for recommendation in explanation_results["recommendations"]:
                    st.markdown(f"- {recommendation}")

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
