
# SafeSpace Shield

### Think Before You Click. Understand Before You Trust.

SafeSpace Shield is a cybersecurity awareness application that analyzes potentially suspicious messages, identifies common phishing indicators, explains possible risks, and provides practical safety recommendations.

## Problem

People frequently receive suspicious messages pretending to be from banks, delivery services, and other trusted organizations. These messages may use urgency, impersonation, or malicious-looking links to trick recipients into revealing sensitive information.

## Solution

SafeSpace Shield helps users understand potential warning signs in suspicious messages through a simple, accessible interface.

## Features

- Analyze pasted text messages.
- Detect suspicious words and phrases.
- Identify selected suspicious URL patterns.
- Classify messages as Low, Medium, or High risk.
- Explain why a message may be suspicious.
- Provide practical safety recommendations.
- Process messages locally without requiring a paid API.

## Technology Stack

- Python 3.13
- Streamlit
- Regular Expressions (Regex)
- Git and GitHub

## Run Locally

1. Clone this repository.
2. Open the project folder in a terminal.
3. Create a virtual environment:

   ```bash
   py -3.13 -m venv .venv
   ```

4. Activate it on Windows PowerShell:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

5. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

6. Start the application:

   ```bash
   python -m streamlit run app.py
   ```

## Run the Detection Tests

```bash
python test_analyzer.py
```

## Privacy

Messages are analyzed locally by the application. The current version does not require users to create accounts or submit messages to a paid external API.

## Important Limitations

- Detection is based on predefined keywords and URL patterns.
- Risk levels are heuristic indicators, not probabilities.
- A Low Risk result does not guarantee that a message is safe.
- The application does not verify the reputation or actual maliciousness of a website.

Always verify suspicious requests through official communication channels.

## Project Category

Cybersecurity | Online Safety | Scam Awareness

---

**SafeSpace Shield — Think Before You Click. Understand Before You Trust.**
