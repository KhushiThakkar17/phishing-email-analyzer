import re
import json
import email
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict

import requests
import nltk
import dns.resolver
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
REPORT_FILE = "phishing_report.json"

# Urgency words commonly used in phishing
URGENCY_WORDS = [
    "urgent", "immediately", "account suspended", "verify now",
    "click here", "limited time", "expires", "action required",
    "confirm your", "unusual activity", "security alert",
    "your account", "winner", "congratulations", "free",
    "password", "update your", "validate", "suspended",
    "blocked", "unauthorized", "login attempt", "unusual sign"
]

# Suspicious attachment extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".doc", ".docm", ".xlsm", ".ps1"
]

# Known phishing URL patterns
SUSPICIOUS_URL_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address URLs
    r'bit\.ly|tinyurl|goo\.gl|t\.co',          # URL shorteners
    r'@',                                        # @ in URLs
    r'paypal.*\.(?!com)',                        # fake paypal
    r'apple.*\.(?!com)',                         # fake apple
    r'google.*\.(?!com)',                        # fake google
    r'microsoft.*\.(?!com)',                     # fake microsoft
    r'amazon.*\.(?!com)',                        # fake amazon
    r'bank.*login',                              # bank login
    r'secure.*login',                            # secure login
    r'account.*verify',                          # account verify
]

# Findings storage
findings = {
    "critical": [],
    "high":     [],
    "medium":   [],
    "low":      [],
    "passed":   []
}

# ──────────────────────────────────────────
# HELPER — Add finding
# ──────────────────────────────────────────
def add_finding(severity, check, detail, recommendation):
    emoji = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🔵",
        "passed":   "✅"
    }
    findings[severity].append({
        "check":          check,
        "detail":         detail,
        "recommendation": recommendation
    })
    print(f"  {emoji[severity]} [{severity.upper()}] {check}")
    print(f"      Detail: {detail[:80]}")

# ──────────────────────────────────────────
# SAMPLE EMAILS — for testing
# ──────────────────────────────────────────
SAMPLE_EMAILS = {
    "phishing_1": """From: security@paypa1.com
To: victim@gmail.com
Subject: URGENT: Your PayPal account has been suspended!
Date: Thu, 3 Apr 2026 10:00:00 +0000
Message-ID: <abc123@paypa1.com>
Return-Path: hacker@evil.com

Dear Customer,

URGENT ACTION REQUIRED! Your PayPal account has been suspended due to 
unusual activity. You must verify your account immediately or it will 
be permanently deleted within 24 hours.

Click here to verify now: http://192.168.1.100/paypal-login/verify.php

Your account will be blocked if you do not act immediately!

PayPal Security Team""",

    "phishing_2": """From: noreply@amaz0n-security.net
To: user@email.com
Subject: Action Required: Confirm your Amazon account
Date: Thu, 3 Apr 2026 11:00:00 +0000
Message-ID: <xyz456@amaz0n.net>
Return-Path: bounce@suspicious-domain.ru

Hello,

We detected unauthorized access to your Amazon account.
Please confirm your identity immediately by clicking:

http://bit.ly/amaz0n-verify-account

Failure to verify within 2 hours will result in account suspension.

Amazon Customer Service""",

    "legitimate": """From: newsletter@github.com
To: developer@gmail.com
Subject: GitHub Actions: New features available
Date: Thu, 3 Apr 2026 09:00:00 +0000
Message-ID: <news123@github.com>
Return-Path: bounce@github.com

Hi there,

We're excited to announce new GitHub Actions features available 
in your repositories. Check out what's new in our documentation.

Visit: https://github.com/features/actions

Thanks for using GitHub!
The GitHub Team"""
}

# ──────────────────────────────────────────
# CHECK 1 — Sender Analysis
# Checks for spoofing and suspicious domains
# ──────────────────────────────────────────
def check_sender(msg, email_name):
    print("\n[*] Analyzing Sender...")

    sender    = msg.get("From", "")
    reply_to  = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")

    # Check for domain mismatch (spoofing)
    sender_domain = re.findall(r'@([\w.-]+)', sender)
    return_domain = re.findall(r'@([\w.-]+)', return_path)

    if sender_domain and return_domain:
        if sender_domain[0] != return_domain[0]:
            add_finding("critical", "Email Spoofing Detected",
                f"From: {sender} | Return-Path: {return_path}",
                "Sender domain does not match return path — classic spoofing indicator")

    # Check for typosquatting in sender domain
    legit_domains = ["paypal.com", "amazon.com", "google.com",
                     "microsoft.com", "apple.com", "github.com"]
    for domain in sender_domain:
        for legit in legit_domains:
            brand = legit.split(".")[0]
            if brand in domain and domain != legit:
                add_finding("critical", "Typosquatting Domain",
                    f"Suspicious domain: {domain} (mimics {legit})",
                    f"Real domain is {legit} — this is a fake!")

    # Check for suspicious TLDs
    suspicious_tlds = [".ru", ".tk", ".ml", ".ga", ".cf", ".gq"]
    for domain in sender_domain + return_domain:
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                add_finding("high", "Suspicious TLD",
                    f"Domain {domain} uses suspicious TLD {tld}",
                    "Avoid clicking links from emails with suspicious TLDs")

    if not any([
        "critical" in str(findings["critical"]),
        "high" in str(findings["high"])
    ]):
        add_finding("passed", "Sender Looks Legitimate",
            f"From: {sender}", "No spoofing detected")

# ──────────────────────────────────────────
# CHECK 2 — Subject Line Analysis
# ──────────────────────────────────────────
def check_subject(msg):
    print("\n[*] Analyzing Subject Line...")

    subject = msg.get("Subject", "").lower()

    urgency_found = []
    for word in URGENCY_WORDS:
        if word.lower() in subject:
            urgency_found.append(word)

    if len(urgency_found) >= 2:
        add_finding("high", "High Urgency Subject Line",
            f"Subject: '{msg.get('Subject')}' | Urgency words: {urgency_found}",
            "Phishing emails use urgency to pressure victims into acting fast")
    elif len(urgency_found) == 1:
        add_finding("medium", "Moderate Urgency in Subject",
            f"Urgency word found: {urgency_found}",
            "Be cautious of emails creating a sense of urgency")
    else:
        add_finding("passed", "Subject Line Looks Normal",
            f"Subject: '{msg.get('Subject')}'",
            "No urgency manipulation detected")

# ──────────────────────────────────────────
# CHECK 3 — URL Analysis
# Extracts and scans all URLs in email body
# ──────────────────────────────────────────
def check_urls(body):
    print("\n[*] Analyzing URLs...")

    # Extract all URLs
    urls = re.findall(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
        r'(?:%[0-9a-fA-F][0-9a-fA-F]))+', body
    )

    if not urls:
        add_finding("passed", "No URLs Found", "Email contains no links",
                   "No action needed")
        return

    print(f"  📎 Found {len(urls)} URL(s)")

    for url in urls:
        url_lower = url.lower()

        # Check suspicious patterns
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url_lower):
                add_finding("critical", "Suspicious URL Detected",
                    f"URL: {url[:60]}",
                    "Do not click this URL — matches phishing pattern")
                break

        # Check for IP address instead of domain
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            add_finding("critical", "IP Address URL",
                f"URL uses raw IP: {url[:60]}",
                "Legitimate sites use domain names, not IP addresses")

        # Check for URL shorteners
        shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
        for shortener in shorteners:
            if shortener in url_lower:
                add_finding("high", "URL Shortener Detected",
                    f"Shortened URL hides true destination: {url}",
                    "Expand shortened URLs before clicking")

# ──────────────────────────────────────────
# CHECK 4 — Body Content Analysis (NLP)
# Detects urgency language using NLP
# ──────────────────────────────────────────
def check_body_content(body):
    print("\n[*] Analyzing Email Body (NLP)...")

    body_lower = body.lower()
    found_words = []

    for word in URGENCY_WORDS:
        if word.lower() in body_lower:
            found_words.append(word)

    score = len(found_words)

    if score >= 5:
        add_finding("critical", "High Phishing Language Score",
            f"Found {score} phishing indicators: {found_words[:5]}",
            "Email body contains multiple phishing manipulation tactics")
    elif score >= 3:
        add_finding("high", "Moderate Phishing Language",
            f"Found {score} urgency indicators: {found_words[:3]}",
            "Email uses pressure tactics common in phishing")
    elif score >= 1:
        add_finding("medium", "Some Urgency Language",
            f"Found indicators: {found_words}",
            "Exercise caution with this email")
    else:
        add_finding("passed", "Body Content Looks Normal",
            "No significant urgency language detected",
            "No action needed")

# ──────────────────────────────────────────
# CHECK 5 — Attachment Analysis
# ──────────────────────────────────────────
def check_attachments(msg):
    print("\n[*] Analyzing Attachments...")

    attachments_found = []

    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments_found.append(filename)
            ext = "." + filename.split(".")[-1].lower()
            if ext in SUSPICIOUS_EXTENSIONS:
                add_finding("critical", "Dangerous Attachment",
                    f"Suspicious file: {filename}",
                    f"Never open {ext} attachments from unknown senders")

    if not attachments_found:
        add_finding("passed", "No Attachments",
            "Email contains no attachments",
            "No action needed")

# ──────────────────────────────────────────
# CHECK 6 — Header Authenticity
# Checks SPF/DKIM/DMARC indicators in headers
# ──────────────────────────────────────────
def check_headers(msg):
    print("\n[*] Analyzing Email Headers...")

    # Check for authentication results
    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    if "fail" in auth_results.lower() or "fail" in received_spf.lower():
        add_finding("critical", "SPF/DKIM Authentication Failed",
            "Email failed sender authentication checks",
            "Email is not from the claimed sender — likely spoofed")
    elif "pass" in auth_results.lower():
        add_finding("passed", "Authentication Passed",
            "SPF/DKIM checks passed",
            "No action needed")
    else:
        add_finding("medium", "No Authentication Headers",
            "Missing SPF/DKIM/DMARC authentication results",
            "Legitimate emails typically include authentication headers")

    # Check Message-ID
    msg_id = msg.get("Message-ID", "")
    if not msg_id:
        add_finding("high", "Missing Message-ID",
            "Email has no Message-ID header",
            "Legitimate emails always have a Message-ID")
    else:
        add_finding("passed", "Message-ID Present",
            f"Message-ID: {msg_id[:40]}",
            "No action needed")

# ──────────────────────────────────────────
# PHISHING SCORE CALCULATOR
# ──────────────────────────────────────────
def calculate_score():
    weights = {
        "critical": 25,
        "high":     15,
        "medium":   8,
        "low":      3,
        "passed":   0
    }
    total_risk = sum(
        len(findings[sev]) * weights[sev]
        for sev in ["critical", "high", "medium", "low"]
    )

    if total_risk >= 50:
        verdict  = "⚠️  PHISHING"
        color    = Fore.RED
    elif total_risk >= 25:
        verdict  = "🟡 SUSPICIOUS"
        color    = Fore.YELLOW
    else:
        verdict  = "✅ LIKELY LEGITIMATE"
        color    = Fore.GREEN

    return total_risk, verdict, color

# ──────────────────────────────────────────
# REPORT GENERATOR
# ──────────────────────────────────────────
def generate_report(email_name, total_risk, verdict):
    total  = sum(len(v) for v in findings.values())
    now    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n{'='*55}")
    print(f"   📧 PHISHING ANALYSIS REPORT")
    print(f"{'='*55}")
    print(f"   Email        : {email_name}")
    print(f"   Scan Time    : {now} UTC")
    print(f"   Risk Score   : {total_risk}/100")
    print(f"   Verdict      : {verdict}")
    print(f"{'='*55}")
    print(f"   🔴 Critical  : {len(findings['critical'])}")
    print(f"   🟠 High      : {len(findings['high'])}")
    print(f"   🟡 Medium    : {len(findings['medium'])}")
    print(f"   🔵 Low       : {len(findings['low'])}")
    print(f"   ✅ Passed    : {len(findings['passed'])}")
    print(f"{'='*55}\n")

    report = {
        "email":      email_name,
        "scan_time":  datetime.now(timezone.utc).isoformat(),
        "risk_score": total_risk,
        "verdict":    verdict,
        "summary": {
            "total_checks": total,
            "critical":     len(findings["critical"]),
            "high":         len(findings["high"]),
            "medium":       len(findings["medium"]),
            "low":          len(findings["low"]),
            "passed":       len(findings["passed"])
        },
        "findings": findings
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[+] Report saved to: {REPORT_FILE}")

# ──────────────────────────────────────────
# ANALYZE ONE EMAIL
# ──────────────────────────────────────────
def analyze_email(email_name, raw_email):
    # Reset findings for each email
    for key in findings:
        findings[key] = []

    print(f"\n{'='*55}")
    print(f"   📧 Analyzing: {email_name}")
    print(f"{'='*55}")

    # Parse email
    msg  = email.message_from_string(raw_email)
    body = ""

    # Extract body
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body += part.get_payload(decode=False) or ""
    if not body:
        body = raw_email

    # Run all checks
    check_sender(msg, email_name)
    check_subject(msg)
    check_urls(body)
    check_body_content(body)
    check_attachments(msg)
    check_headers(msg)

    # Calculate verdict
    total_risk, verdict, color = calculate_score()
    print(f"\n{color}  VERDICT: {verdict}{Style.RESET_ALL}")

    generate_report(email_name, total_risk, verdict)
    return verdict

# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    print("=" * 55)
    print("   Phishing Email Analyzer")
    print("   Checks: Sender, Subject, URLs, NLP, Headers")
    print("=" * 55)

    results = {}
    for name, raw in SAMPLE_EMAILS.items():
        verdict = analyze_email(name, raw)
        results[name] = verdict
        print("\n" + "-"*55)

    print(f"\n{'='*55}")
    print(f"   📊 BATCH ANALYSIS SUMMARY")
    print(f"{'='*55}")
    for name, verdict in results.items():
        print(f"   {name:20} → {verdict}")
    print(f"{'='*55}\n")

if __name__ == "__main__":
    main()
