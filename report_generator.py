import json
from datetime import datetime, timezone

with open("phishing_report.json", "r") as f:
    data = json.load(f)

summary  = data["summary"]
findings = data["findings"]
verdict  = data["verdict"]
score    = data["risk_score"]
email    = data["email"]
scantime = data["scan_time"]

# ──────────────────────────────────────────
# Verdict color
# ──────────────────────────────────────────
if "PHISHING" in verdict:
    verdict_color = "#e74c3c"
    verdict_bg    = "#3d1515"
elif "SUSPICIOUS" in verdict:
    verdict_color = "#f1c40f"
    verdict_bg    = "#3d350f"
else:
    verdict_color = "#2ecc71"
    verdict_bg    = "#0f3d1f"

score_color = verdict_color

# ──────────────────────────────────────────
# Build findings rows
# ──────────────────────────────────────────
def build_rows(items, badge_class):
    rows = ""
    for item in items:
        rows += f"""
        <tr>
            <td><span class="badge {badge_class}">{badge_class.upper()}</span></td>
            <td>{item['check']}</td>
            <td>{item.get('detail','')[:80]}</td>
            <td>{item['recommendation']}</td>
        </tr>"""
    return rows

all_rows  = build_rows(findings["critical"], "critical")
all_rows += build_rows(findings["high"],     "high")
all_rows += build_rows(findings["medium"],   "medium")
all_rows += build_rows(findings["low"],      "low")
all_rows += build_rows(findings["passed"],   "passed")

# ──────────────────────────────────────────
# Generate HTML
# ──────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Phishing Analysis Report</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0f1117;
            color: #e0e0e0;
            padding: 30px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1f2e, #252d3d);
            border: 1px solid #2d3748;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header h1 {{ font-size:26px; color:#fff; margin-bottom:6px; }}
        .header p  {{ color:#8892a4; font-size:13px; margin-top:4px; }}
        .verdict-box {{
            background: {verdict_bg};
            border: 2px solid {verdict_color};
            border-radius: 10px;
            padding: 15px 25px;
            text-align: center;
            min-width: 180px;
        }}
        .verdict-box .verdict-text {{
            font-size: 18px;
            font-weight: bold;
            color: {verdict_color};
        }}
        .verdict-box .score-text {{
            font-size: 13px;
            color: #8892a4;
            margin-top: 4px;
        }}
        .summary-grid {{
            display:grid;
            grid-template-columns:repeat(5,1fr);
            gap:15px; margin-bottom:25px;
        }}
        .summary-card {{
            background:#1a1f2e;
            border:1px solid #2d3748;
            border-radius:10px;
            padding:20px; text-align:center;
        }}
        .summary-card .count {{
            font-size:36px; font-weight:bold; margin-bottom:5px;
        }}
        .summary-card .label {{
            font-size:12px; color:#8892a4;
            text-transform:uppercase; letter-spacing:1px;
        }}
        .critical-count {{ color:#e74c3c; }}
        .high-count     {{ color:#e67e22; }}
        .medium-count   {{ color:#f1c40f; }}
        .low-count      {{ color:#3498db; }}
        .passed-count   {{ color:#2ecc71; }}
        .table-container {{
            background:#1a1f2e;
            border:1px solid #2d3748;
            border-radius:12px;
            overflow:hidden;
        }}
        .table-header {{
            padding:20px 25px;
            border-bottom:1px solid #2d3748;
        }}
        .table-header h2 {{ font-size:16px; color:#fff; }}
        table {{ width:100%; border-collapse:collapse; }}
        th {{
            background:#252d3d; padding:12px 16px;
            text-align:left; font-size:12px;
            text-transform:uppercase; letter-spacing:1px;
            color:#8892a4;
        }}
        td {{
            padding:12px 16px;
            border-bottom:1px solid #1e2535;
            font-size:12px; vertical-align:top;
        }}
        tr:last-child td {{ border-bottom:none; }}
        tr:hover td {{ background:#1e2535; }}
        .badge {{
            display:inline-block; padding:3px 10px;
            border-radius:20px; font-size:11px;
            font-weight:bold; text-transform:uppercase;
            letter-spacing:0.5px; white-space:nowrap;
        }}
        .badge.critical {{ background:#3d1515; color:#e74c3c; border:1px solid #e74c3c; }}
        .badge.high     {{ background:#3d2a0f; color:#e67e22; border:1px solid #e67e22; }}
        .badge.medium   {{ background:#3d350f; color:#f1c40f; border:1px solid #f1c40f; }}
        .badge.low      {{ background:#0f253d; color:#3498db; border:1px solid #3498db; }}
        .badge.passed   {{ background:#0f3d1f; color:#2ecc71; border:1px solid #2ecc71; }}
        .footer {{
            text-align:center; margin-top:25px;
            color:#4a5568; font-size:12px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>📧 Phishing Email Analysis Report</h1>
            <p>Email: {email}</p>
            <p>Scan Time: {scantime}</p>
            <p>Checks: Sender • Subject • URLs • NLP • Attachments • Headers</p>
        </div>
        <div class="verdict-box">
            <div class="verdict-text">{verdict}</div>
            <div class="score-text">Risk Score: {score}/100</div>
        </div>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="count critical-count">{summary['critical']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="count high-count">{summary['high']}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="count medium-count">{summary['medium']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="count low-count">{summary['low']}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-card">
            <div class="count passed-count">{summary['passed']}</div>
            <div class="label">Passed</div>
        </div>
    </div>

    <div class="table-container">
        <div class="table-header">
            <h2>🔍 Detailed Findings ({summary['total_checks']} total checks)</h2>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Check</th>
                    <th>Detail</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>{all_rows}</tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by Phishing Email Analyzer</p>
        <p>Built by Khushi Thakkar | github.com/KhushiThakkar17</p>
    </div>
</body>
</html>"""

with open("phishing_report.html", "w") as f:
    f.write(html)

print("[+] HTML report generated: phishing_report.html")
print(f"[+] Verdict: {verdict}")
print(f"[+] Risk Score: {score}/100")
print("[+] Copy to /tmp and open in Firefox!")
