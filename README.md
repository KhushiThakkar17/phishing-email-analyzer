# 📧 Phishing Email Analyzer

![Python](https://img.shields.io/badge/Python-3.13-blue)
![NLP](https://img.shields.io/badge/NLP-NLTK-green)
![Checks](https://img.shields.io/badge/Checks-6%20Analysis%20Types-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-100%25-brightgreen)

An automated phishing email detection tool that analyzes emails
across 6 dimensions using NLP and pattern matching, generating
a risk score and color-coded HTML report with verdict.

---

## 🎯 What It Analyzes

| Check | What It Detects |
|-------|----------------|
| **Sender Analysis** | Spoofing, typosquatting, suspicious TLDs |
| **Subject Analysis** | Urgency manipulation tactics |
| **URL Analysis** | IP URLs, shorteners, phishing patterns |
| **NLP Body Analysis** | Phishing language scoring |
| **Attachment Analysis** | Dangerous file extensions |
| **Header Analysis** | SPF/DKIM/DMARC authentication |

---

## 📊 Risk Scoring

| Score | Verdict |
|-------|---------|
| 50+ | ⚠️ PHISHING |
| 25-49 | 🟡 SUSPICIOUS |
| 0-24 | ✅ LIKELY LEGITIMATE |

---

## ⚙️ Installation
```bash
git clone https://github.com/KhushiThakkar17/phishing-email-analyzer.git
cd phishing-email-analyzer
python3 -m venv venv
source venv/bin/activate
pip install requests beautifulsoup4 scikit-learn pandas numpy nltk colorama dnspython
python3 -c "import nltk; nltk.download('stopwords'); nltk.download('punkt')"
```

## 🚀 Usage
```bash
# Analyze sample emails
python3 analyzer.py

# Generate HTML report
python3 report_generator.py

# View in browser
firefox /tmp/phishing_report.html
```

---

## 🛠️ Tech Stack
- **Language:** Python 3.13
- **NLP:** NLTK
- **Libraries:** Requests, BeautifulSoup4, Colorama, DNSPython
- **Platform:** Kali Linux

---

## 👩‍💻 Author
**Khushi Thakkar**
M.Eng Cybersecurity — University of Maryland
[LinkedIn](https://linkedin.com/in/khushithakkar17)
