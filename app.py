
from flask import Flask, render_template, request
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)

# Project configuration
LONG_URL_LIMIT = 75

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "password",
    "account",
    "update"
]


def validate_url(url):
    """Check whether the input has a valid HTTP/HTTPS URL structure."""
    url = url.strip()

    if not url:
        return False, "Please enter a URL."

    # Reject spaces and control characters in the URL
    if re.search(r"\s", url):
        return False, "URL must not contain spaces."

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return False, "URL must start with http:// or https://."

        if not parsed.hostname:
            return False, "Please enter a valid URL with a hostname."

        # Reject malformed ports and invalid bracketed addresses
        _ = parsed.port

        return True, ""

    except (ValueError, UnicodeError):
        return False, "The URL format is invalid."


def check_url(url):
    """Apply the five rule-based checks from the project specification."""

    parsed = urlparse(url)
    score = 0
    reasons = []

    # 1. HTTPS Check: +20
    if parsed.scheme.lower() != "https":
        score += 20
        reasons.append({
            "name": "Missing HTTPS",
            "points": 20,
            "detail": "The URL does not use HTTPS."
        })

    # 2. URL Length Check: +15
    if len(url) > LONG_URL_LIMIT:
        score += 15
        reasons.append({
            "name": "Very long URL",
            "points": 15,
            "detail": f"The URL exceeds {LONG_URL_LIMIT} characters."
        })

    # 3. IP Address Check: +25
    hostname = parsed.hostname or ""
    is_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        is_ip_address = True
    except ValueError:
        pass

    if is_ip_address:
        score += 25
        reasons.append({
            "name": "IP address in URL",
            "points": 25,
            "detail": "The hostname is a numeric IP address."
        })

    # 4. @ Symbol Check: +20
    if "@" in url:
        score += 20
        reasons.append({
            "name": "@ symbol detected",
            "points": 20,
            "detail": "The URL contains the @ character."
        })

    # 5. Suspicious Keyword Check: +10
    url_lower = url.lower()
    found_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in url_lower
    ]

    if found_keywords:
        score += 10
        reasons.append({
            "name": "Suspicious keyword",
            "points": 10,
            "detail": "Detected: " + ", ".join(found_keywords)
        })

    # Determine risk category using the project's thresholds
    if score < 30:
        risk = "Low Risk"
        level = "low"
    elif score < 60:
        risk = "Medium Risk"
        level = "medium"
    else:
        risk = "High Risk"
        level = "high"

    if not reasons:
        reasons.append({
            "name": "No listed indicators detected",
            "points": 0,
            "detail": "None of the five configured warning rules triggered."
        })

    return {
        "score": score,
        "risk": risk,
        "level": level,
        "reasons": reasons
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    entered_url = ""
    error = None

    if request.method == "POST":
        entered_url = request.form.get("url", "").strip()

        is_valid, error_message = validate_url(entered_url)

        if not is_valid:
            error = error_message
        else:
            result = check_url(entered_url)

    return render_template(
        "index.html",
        result=result,
        entered_url=entered_url,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True)
