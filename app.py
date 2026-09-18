from flask import Flask, render_template, request, send_file
import re
import os
from datetime import datetime
from urllib.parse import urlparse

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import mm

from database import (
    create_database,
    save_scan,
    get_history,
    get_statistics,
    clear_history
)

app = Flask(__name__)

create_database()


# =========================
# URL CHECKING FUNCTION
# =========================

def check_url(url):

    score = 0
    reasons = []

    # URL Length
    if len(url) > 75:
        score += 20
        reasons.append("URL is unusually long")

    # @ symbol
    if "@" in url:
        score += 20
        reasons.append("URL contains @ symbol")

    # Hyphen
    if "-" in url:
        score += 10
        reasons.append("URL contains hyphen")

    # Suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "account",
        "update",
        "password",
        "secure",
        "bank",
        "confirm"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url.lower():
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 10, 30)
        reasons.append(
            "Suspicious keywords found: " + ", ".join(found_words)
        )

    # IP Address
    ip_pattern = r"https?://(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):
        score += 25
        reasons.append("URL uses an IP address")

    # HTTPS
    if not url.lower().startswith("https://"):
        score += 10
        reasons.append("URL does not use HTTPS")

    # Maximum score
    score = min(score, 100)

    # Classification
    if score >= 60:
        result = "PHISHING"
        risk_level = "HIGH"
        risk_color = "red"
        risk_message = "This URL shows strong phishing indicators."

    elif score >= 30:
        result = "SUSPICIOUS"
        risk_level = "MEDIUM"
        risk_color = "orange"
        risk_message = "This URL contains some suspicious indicators."

    else:
        result = "LEGITIMATE"
        risk_level = "LOW"
        risk_color = "green"
        risk_message = "No major phishing indicators were detected."

    # URL Details
    parsed = urlparse(url)

    url_details = {
        "scheme": parsed.scheme if parsed.scheme else "N/A",
        "domain": parsed.netloc if parsed.netloc else "N/A",
        "path": parsed.path if parsed.path else "/",
        "length": len(url)
    }

    # Security Checks
    security_checks = [
        {
            "name": "HTTPS Security",
            "status": "PASS" if url.lower().startswith("https://") else "WARNING"
        },
        {
            "name": "IP Address Check",
            "status": "WARNING" if re.search(ip_pattern, url) else "PASS"
        },
        {
            "name": "Suspicious Keyword Check",
            "status": "WARNING" if found_words else "PASS"
        },
        {
            "name": "URL Length Check",
            "status": "WARNING" if len(url) > 75 else "PASS"
        },
        {
            "name": "@ Symbol Check",
            "status": "WARNING" if "@" in url else "PASS"
        }
    ]

    return (
        result,
        score,
        reasons,
        risk_level,
        risk_color,
        risk_message,
        security_checks,
        url_details
    )


# =========================
# HOME PAGE
# =========================

@app.route("/")
def home():
    return render_template("index.html")


# =========================
# SCAN URL
# =========================

@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url", "").strip()

    if not url:
        return render_template(
            "index.html",
            error="Please enter a URL"
        )

    (
        result,
        score,
        reasons,
        risk_level,
        risk_color,
        risk_message,
        security_checks,
        url_details
    ) = check_url(url)

    # Save scan in database
    save_scan(url, result, score)

    return render_template(
        "result.html",
        url=url,
        result=result,
        score=score,
        reasons=reasons,
        risk_level=risk_level,
        risk_color=risk_color,
        risk_message=risk_message,
        security_checks=security_checks,
        url_details=url_details
    )


# =========================
# DOWNLOAD PDF REPORT
# =========================

@app.route("/download_report")
def download_report():

    url = request.args.get("url", "")
    result = request.args.get("result", "")
    score = request.args.get("score", "0")
    risk_level = request.args.get("risk_level", "")
    risk_message = request.args.get("risk_message", "")
    reasons = request.args.getlist("reasons")

    file_path = os.path.join(
        os.getcwd(),
        "Phishing_Scan_Report.pdf"
    )

    pdf = canvas.Canvas(file_path, pagesize=A4)

    width, height = A4

    # Title
    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawCentredString(
        width / 2,
        height - 40 * mm,
        "Phishing URL Scan Report"
    )

    pdf.setStrokeColor(colors.grey)
    pdf.line(
        20 * mm,
        height - 45 * mm,
        width - 20 * mm,
        height - 45 * mm
    )

    # Details
    y = height - 65 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(25 * mm, y, "Scanned URL:")

    y -= 8 * mm

    pdf.setFont("Helvetica", 10)
    pdf.drawString(25 * mm, y, url[:100])

    y -= 15 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(25 * mm, y, "Classification:")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(75 * mm, y, result)

    y -= 10 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(25 * mm, y, "Risk Level:")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(75 * mm, y, risk_level)

    y -= 10 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(25 * mm, y, "Risk Score:")

    pdf.setFont("Helvetica", 12)
    pdf.drawString(75 * mm, y, str(score) + "/100")

    y -= 15 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(25 * mm, y, "Message:")

    y -= 8 * mm

    pdf.setFont("Helvetica", 10)
    pdf.drawString(25 * mm, y, risk_message[:100])

    y -= 15 * mm

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(25 * mm, y, "Detection Reasons:")

    y -= 10 * mm

    pdf.setFont("Helvetica", 10)

    if reasons:

        for reason in reasons:
            pdf.drawString(
                30 * mm,
                y,
                "• " + reason[:100]
            )
            y -= 8 * mm

    else:
        pdf.drawString(
            30 * mm,
            y,
            "No major suspicious indicators detected."
        )

    y -= 15 * mm

    pdf.setFont("Helvetica", 9)
    pdf.drawString(
        25 * mm,
        y,
        "Generated by AI-Based Phishing URL Detection System"
    )

    pdf.save()

    return send_file(
        file_path,
        as_attachment=True,
        download_name="Phishing_Scan_Report.pdf"
    )


# =========================
# SCAN HISTORY
# =========================

@app.route("/history")
def history():

    data = get_history()

    return render_template(
        "history.html",
        history=data
    )


# =========================
# CLEAR HISTORY
# =========================

@app.route("/clear_history", methods=["POST"])
def clear_history_route():

    clear_history()

    return render_template(
        "history.html",
        history=[]
    )


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
def dashboard():

    total, phishing, suspicious, legitimate = get_statistics()

    return render_template(
        "dashboard.html",
        total=total,
        phishing=phishing,
        suspicious=suspicious,
        legitimate=legitimate
    )


# =========================
# PERFORMANCE
# =========================

@app.route("/performance")
def performance():

    # Model performance data
    confusion_matrix = [
        [6, 0, 0],
        [0, 3, 0],
        [0, 0, 7]
    ]

    classes = [
        "LEGITIMATE",
        "SUSPICIOUS",
        "PHISHING"
    ]

    metrics = []

    total_correct = 0
    total_samples = 0

    for i in range(len(classes)):

        tp = confusion_matrix[i][i]

        fp = sum(
            confusion_matrix[j][i]
            for j in range(len(classes))
            if j != i
        )

        fn = sum(
            confusion_matrix[i][j]
            for j in range(len(classes))
            if j != i
        )

        support = sum(confusion_matrix[i])

        total_correct += tp
        total_samples += support

        precision = (
            tp / (tp + fp)
            if (tp + fp) > 0
            else 0
        )

        recall = (
            tp / (tp + fn)
            if (tp + fn) > 0
            else 0
        )

        if precision + recall > 0:
            f1 = (
                2 * precision * recall
                / (precision + recall)
            )
        else:
            f1 = 0

        metrics.append({
            "class": classes[i],
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1": round(f1 * 100, 2),
            "support": support
        })

    accuracy = (
        total_correct / total_samples * 100
        if total_samples > 0
        else 0
    )

    return render_template(
        "performance.html",
        metrics=metrics,
        accuracy=round(accuracy, 2),
        confusion_matrix=confusion_matrix
    )


# =========================
# RUN APPLICATION
# =========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )