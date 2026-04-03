import re
import json
import email
from datetime import datetime, timezone

import nltk
from colorama import Fore, Style, init

init(autoreset=True)

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
REPORT_FILE = "phishing_report.json"

URGENCY_WORDS = [
    "urgent", "immediately", "account suspended", "verify now",
    "click here", "limited time", "expires", "action required",
    "confirm your", "unusual activity", "security alert",
    "password", "update your", "validate", "suspended",
    "blocked", "unauthorized", "login attempt", "unusual sign",
    "winner", "congratulations", "free gift"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".docm", ".xlsm", ".ps1"
]

SUSPICIOUS_URL_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'bit\.ly|tinyurl|goo\.gl|t\.co',
    r'paypal.*\.(?!com)',
    r'apple.*\.(?!com)',
    r'google.*\.(?!com)',
    r'microsoft.*\.(?!com)',
    r'amazon.*\.(?!com)',
    r'bank.*login',
    r'secure.*login',
    r'account.*verify',
]

LEGITIMATE_DOMAINS = [
    "github.com", "google.com", "microsoft.com",
    "amazon.com", "apple.com", "linkedin.com",
    "twitter.com", "facebook.com", "youtube.com",
    "gmail.com", "outlook.com", "yahoo.com"
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
    print(f"      Detail: {str(detail)[:80]}")

# ──────────────────────────────────────────
# SAMPLE EMAILS
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

We are excited to announce new GitHub Actions features available
in your repositories. Check out what is new in our documentation.

Visit: https://github.com/features/actions

Thanks for using GitHub!
The GitHub Team"""
}

# ──────────────────────────────────────────
# CHECK 1 — Sender Analysis
# ──────────────────────────────────────────
def check_sender(msg):
    print("\n[*] Analyzing Sender...")

    sender      = msg.get("From", "")
    return_path = msg.get("Return-Path", "")

    sender_domain  = re.findall(r'@([\w.-]+)', sender)
    return_domain  = re.findall(r'@([\w.-]+)', return_path)

    # Domain mismatch = spoofing
    if sender_domain and return_domain:
        if sender_domain[0] != return_domain[0]:
            add_finding("critical", "Email Spoofing Detected",
                f"From: {sender} | Return-Path: {return_path}",
                "Sender domain does not match return path")
        else:
            add_finding("passed", "Sender Domain Matches",
                f"From and Return-Path domains match",
                "No spoofing detected")

    # Typosquatting check
    legit_brands = {
        "paypal": "paypal.com", "amazon": "amazon.com",
        "google": "google.com", "microsoft": "microsoft.com",
        "apple": "apple.com", "github": "github.com"
    }
    spoofed = False
    for domain in sender_domain:
        for brand, legit in legit_brands.items():
            if brand in domain.lower() and domain.lower() != legit:
                add_finding("critical", "Typosquatting Domain",
                    f"Fake domain: {domain} (mimics {legit})",
                    f"Real domain is {legit}")
                spoofed = True

    # Suspicious TLDs
    suspicious_tlds = [".ru", ".tk", ".ml", ".ga", ".cf"]
    for domain in sender_domain + return_domain:
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                add_finding("high", "Suspicious TLD",
                    f"Domain {domain} uses high-risk TLD {tld}",
                    "Avoid emails from these domains")

    if not spoofed and sender_domain:
        # Check if sender is from known legitimate domain
        for domain in sender_domain:
            if any(legit in domain for legit in LEGITIMATE_DOMAINS):
                add_finding("passed", "Sender from Known Domain",
                    f"Sender domain: {domain}",
                    "No action needed")

# ──────────────────────────────────────────
# CHECK 2 — Subject Analysis
# ──────────────────────────────────────────
def check_subject(msg):
    print("\n[*] Analyzing Subject Line...")

    subject = msg.get("Subject", "").lower()
    urgency_found = [w for w in URGENCY_WORDS if w.lower() in subject]

    if len(urgency_found) >= 2:
        add_finding("high", "High Urgency Subject",
            f"Urgency words: {urgency_found}",
            "Phishing emails use urgency to pressure victims")
    elif len(urgency_found) == 1:
        add_finding("medium", "Urgency Language in Subject",
            f"Found: {urgency_found}",
            "Be cautious of urgent-sounding emails")
    else:
        add_finding("passed", "Subject Looks Normal",
            f"Subject: '{msg.get('Subject', '')}'",
            "No urgency manipulation detected")

# ──────────────────────────────────────────
# CHECK 3 — URL Analysis
# Only flags genuinely suspicious URLs
# ──────────────────────────────────────────
def check_urls(body):
    print("\n[*] Analyzing URLs...")

    urls = re.findall(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+!*\\(\\),]|'
        r'(?:%[0-9a-fA-F][0-9a-fA-F]))+', body
    )

    if not urls:
        add_finding("passed", "No URLs Found",
            "Email contains no links", "No action needed")
        return

    print(f"  📎 Found {len(urls)} URL(s)")

    suspicious_count = 0
    safe_count       = 0

    for url in urls:
        url_lower = url.lower()

        # Skip known legitimate domains
        is_legit = any(legit in url_lower for legit in LEGITIMATE_DOMAINS)
        if is_legit:
            safe_count += 1
            continue

        # Check IP address URLs
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            add_finding("critical", "IP Address URL",
                f"URL uses raw IP: {url[:60]}",
                "Legitimate sites use domain names not IPs")
            suspicious_count += 1
            continue

        # Check URL shorteners
        shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co"]
        if any(s in url_lower for s in shorteners):
            add_finding("high", "URL Shortener Detected",
                f"Shortened URL hides destination: {url[:60]}",
                "Expand shortened URLs before clicking")
            suspicious_count += 1
            continue

        # Check suspicious patterns
        for pattern in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url_lower):
                add_finding("high", "Suspicious URL Pattern",
                    f"URL matches phishing pattern: {url[:60]}",
                    "Do not click this URL")
                suspicious_count += 1
                break

    if safe_count > 0 and suspicious_count == 0:
        add_finding("passed", f"{safe_count} Safe URL(s) Found",
            "All URLs point to known legitimate domains",
            "No action needed")

# ──────────────────────────────────────────
# CHECK 4 — Body NLP Analysis
# Only counts HIGH-CONFIDENCE phishing words
# ──────────────────────────────────────────
def check_body_content(body):
    print("\n[*] Analyzing Email Body (NLP)...")

    body_lower = body.lower()

    # High confidence phishing phrases only
    high_confidence_phrases = [
        "account suspended", "verify now", "action required",
        "unusual activity", "login attempt", "account will be",
        "click here to verify", "confirm your account",
        "permanently deleted", "unauthorized access detected"
    ]

    found_phrases = [p for p in high_confidence_phrases
                     if p in body_lower]

    # General urgency words (lower weight)
    general_urgency = [w for w in URGENCY_WORDS
                      if w in body_lower and
                      w not in " ".join(found_phrases)]

    if len(found_phrases) >= 3:
        add_finding("critical", "High Confidence Phishing Language",
            f"Found {len(found_phrases)} phishing phrases: {found_phrases[:3]}",
            "Email contains classic phishing manipulation language")
    elif len(found_phrases) >= 1:
        add_finding("high", "Phishing Language Detected",
            f"Found phrases: {found_phrases}",
            "Email uses pressure tactics common in phishing")
    elif len(general_urgency) >= 4:
        add_finding("medium", "Some Urgency Language",
            f"Found {len(general_urgency)} urgency indicators",
            "Exercise caution with this email")
    else:
        add_finding("passed", "Body Content Looks Normal",
            "No significant phishing language detected",
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
                    f"Never open {ext} files from unknown senders")

    if not attachments_found:
        add_finding("passed", "No Attachments",
            "Email contains no attachments",
            "No action needed")

# ──────────────────────────────────────────
# CHECK 6 — Header Analysis
# ──────────────────────────────────────────
def check_headers(msg):
    print("\n[*] Analyzing Email Headers...")

    auth_results = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    if "fail" in auth_results.lower() or \
       "fail" in received_spf.lower():
        add_finding("critical", "Authentication Failed",
            "Email failed SPF/DKIM checks",
            "Email is not from claimed sender — likely spoofed")
    elif "pass" in auth_results.lower():
        add_finding("passed", "Authentication Passed",
            "SPF/DKIM checks passed",
            "No action needed")
    else:
        add_finding("low", "No Authentication Headers",
            "Missing SPF/DKIM/DMARC results",
            "Legitimate emails typically include auth headers")

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
# SCORE CALCULATOR — Capped at 100
# ──────────────────────────────────────────
def calculate_score():
    weights = {
        "critical": 20,
        "high":     10,
        "medium":   5,
        "low":      2,
        "passed":   0
    }

    # Cap score at 100
    total_risk = min(100, sum(
        len(findings[sev]) * weights[sev]
        for sev in ["critical", "high", "medium", "low"]
    ))

    if total_risk >= 50:
        verdict = "⚠️  PHISHING"
        color   = Fore.RED
    elif total_risk >= 25:
        verdict = "🟡 SUSPICIOUS"
        color   = Fore.YELLOW
    else:
        verdict = "✅ LIKELY LEGITIMATE"
        color   = Fore.GREEN

    return total_risk, verdict, color

# ──────────────────────────────────────────
# REPORT GENERATOR
# ──────────────────────────────────────────
def generate_report(email_name, total_risk, verdict):
    total = sum(len(v) for v in findings.values())
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

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
# ANALYZE EMAIL
# ──────────────────────────────────────────
def analyze_email(email_name, raw_email):
    for key in findings:
        findings[key] = []

    print(f"\n{'='*55}")
    print(f"   📧 Analyzing: {email_name}")
    print(f"{'='*55}")

    msg  = email.message_from_string(raw_email)
    body = ""

    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            payload = part.get_payload(decode=False)
            if payload:
                body += payload
    if not body:
        body = raw_email

    check_sender(msg)
    check_subject(msg)
    check_urls(body)
    check_body_content(body)
    check_attachments(msg)
    check_headers(msg)

    total_risk, verdict, color = calculate_score()
    print(f"\n{color}  VERDICT: {verdict}{Style.RESET_ALL}")

    generate_report(email_name, total_risk, verdict)
    return verdict

# ──────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────
def main():
    print("=" * 55)
    print("   Phishing Email Analyzer v2.0")
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
