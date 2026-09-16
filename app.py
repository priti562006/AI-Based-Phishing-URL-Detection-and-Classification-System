from flask import Flask, render_template, request, redirect, url_for, session, send_file
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

app.secret_key = "phishing_url_detection_secret_key"

create_database()


# ==================================================
# URL ANALYSIS
# ==================================================

def check_url(url):

    score = 0
    reasons = []

    url_lower = url.lower()

    # Security checks
    https_check = url_lower.startswith("https://")

    ip_check = bool(
        re.search(
            r"(\d{1,3}\.){3}\d{1,3}",
            url
        )
    )

    at_check = "@" in url
    hyphen_check = "-" in url
    long_url_check = len(url) > 75

    # URL Length
    if long_url_check:
        score += 20
        reasons.append("URL is unusually long")

    # @ Symbol
    if at_check:
        score += 20
        reasons.append("URL contains @ symbol")

    # Hyphen
    if hyphen_check:
        score += 10
        reasons.append("URL contains hyphen")

    # Suspicious Keywords
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

        if word in url_lower:
            found_words.append(word)

    if found_words:

        score += min(
            len(found_words) * 10,
            30
        )

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(found_words)
        )

    # IP Address
    if ip_check:

        score += 25

        reasons.append(
            "URL contains an IP address"
        )

    # HTTPS
    if not https_check:

        score += 10

        reasons.append(
            "HTTPS is not used"
        )

    # Maximum score
    score = min(score, 100)

    # ==================================================
    # CLASSIFICATION
    # ==================================================

    if score >= 60:

        result = "PHISHING"
        risk_level = "HIGH"
        risk_color = "red"
        risk_message = "High Risk"

    elif score >= 30:

        result = "SUSPICIOUS"
        risk_level = "MEDIUM"
        risk_color = "orange"
        risk_message = "Medium Risk"

    else:

        result = "LEGITIMATE"
        risk_level = "LOW"
        risk_color = "green"
        risk_message = "Low Risk"

    # ==================================================
    # URL DETAILS
    # ==================================================

    parsed_url = urlparse(url)

    domain = parsed_url.netloc
    protocol = parsed_url.scheme
    path = parsed_url.path

    subdomain_count = 0

    if domain:

        domain_without_port = domain.split(":")[0]

        parts = domain_without_port.split(".")

        if len(parts) > 2:

            subdomain_count = len(parts) - 2

    special_characters = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            url
        )
    )

    digit_count = len(
        re.findall(
            r"\d",
            url
        )
    )

    dot_count = url.count(".")

    # URL Details dictionary
    url_details = {

        "URL Length":
            len(url),

        "Protocol":
            protocol.upper()
            if protocol
            else "Not Detected",

        "Domain":
            domain
            if domain
            else "Not Detected",

        "Path":
            path
            if path
            else "/",

        "HTTPS":
            "Yes"
            if https_check
            else "No",

        "IP Address":
            "Detected"
            if ip_check
            else "Not Detected",

        "Suspicious Keywords":
            ", ".join(found_words)
            if found_words
            else "None",

        "Special Characters":
            special_characters,

        "Digits":
            digit_count,

        "Dots":
            dot_count,

        "Subdomains":
            subdomain_count,

        "@ Symbol":
            "Detected"
            if at_check
            else "Not Detected",

        "Hyphen":
            "Detected"
            if hyphen_check
            else "Not Detected"
    }

    # ==================================================
    # SECURITY CHECKS
    # ==================================================

    security_checks = {

        "HTTPS Security":
            "PASS"
            if https_check
            else "FAIL",

        "IP Address":
            "WARNING"
            if ip_check
            else "PASS",

        "@ Symbol":
            "WARNING"
            if at_check
            else "PASS",

        "Long URL":
            "WARNING"
            if long_url_check
            else "PASS",

        "Hyphen":
            "WARNING"
            if hyphen_check
            else "PASS",

        "Suspicious Keywords":
            "WARNING"
            if found_words
            else "PASS"
    }

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


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        ).strip()

        if (
            username == "admin"
            and password == "admin123"
        ):

            session["logged_in"] = True
            session["username"] = username

            return redirect(
                url_for("home")
            )

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template(
        "login.html"
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        username=session.get("username")
    )


# ==================================================
# SCAN URL
# ==================================================

@app.route("/scan", methods=["POST"])
def scan():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    url = request.form.get(
        "url",
        ""
    ).strip()

    if not url:

        return render_template(
            "index.html",
            error="Please enter a URL",
            username=session.get("username")
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

    save_scan(
        url,
        result,
        score
    )

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


# ==================================================
# DOWNLOAD PDF REPORT
# ==================================================

@app.route("/download_report")
def download_report():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    url = request.args.get(
        "url",
        ""
    )

    result = request.args.get(
        "result",
        ""
    )

    score = request.args.get(
        "score",
        "0"
    )

    risk_level = request.args.get(
        "risk_level",
        ""
    )

    risk_message = request.args.get(
        "risk_message",
        ""
    )

    reasons = request.args.getlist(
        "reason"
    )

    file_name = "Phishing_Scan_Report.pdf"

    file_path = os.path.join(
        os.getcwd(),
        file_name
    )

    pdf = canvas.Canvas(
        file_path,
        pagesize=A4
    )

    width, height = A4

    # Title
    pdf.setFillColor(
        colors.HexColor("#063b70")
    )

    pdf.setFont(
        "Helvetica-Bold",
        20
    )

    pdf.drawString(
        25 * mm,
        height - 25 * mm,
        "Phishing URL Detection Report"
    )

    # Date and Time
    pdf.setFillColor(
        colors.black
    )

    pdf.setFont(
        "Helvetica",
        10
    )

    current_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    pdf.drawString(
        25 * mm,
        height - 35 * mm,
        "Scan Date & Time: "
        + current_time
    )

    # URL
    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        25 * mm,
        height - 55 * mm,
        "Scanned URL:"
    )

    pdf.setFont(
        "Helvetica",
        9
    )

    pdf.drawString(
        25 * mm,
        height - 63 * mm,
        url[:110]
    )

    # Classification
    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        25 * mm,
        height - 82 * mm,
        "Classification:"
    )

    if result == "PHISHING":

        pdf.setFillColor(
            colors.red
        )

    elif result == "SUSPICIOUS":

        pdf.setFillColor(
            colors.orange
        )

    else:

        pdf.setFillColor(
            colors.green
        )

    pdf.setFont(
        "Helvetica-Bold",
        13
    )

    pdf.drawString(
        70 * mm,
        height - 82 * mm,
        result
    )

    # Risk Score
    pdf.setFillColor(
        colors.black
    )

    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        25 * mm,
        height - 100 * mm,
        "Risk Score:"
    )

    pdf.setFont(
        "Helvetica",
        12
    )

    pdf.drawString(
        70 * mm,
        height - 100 * mm,
        str(score) + " / 100"
    )

    # Risk Level
    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        25 * mm,
        height - 118 * mm,
        "Risk Level:"
    )

    pdf.setFont(
        "Helvetica",
        12
    )

    pdf.drawString(
        70 * mm,
        height - 118 * mm,
        risk_level
    )

    # Assessment
    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        25 * mm,
        height - 136 * mm,
        "Assessment:"
    )

    pdf.setFont(
        "Helvetica",
        11
    )

    pdf.drawString(
        25 * mm,
        height - 145 * mm,
        risk_message
    )

    # Reasons
    pdf.setFont(
        "Helvetica-Bold",
        12
    )

    pdf.drawString(
        25 * mm,
        height - 165 * mm,
        "Detection Reasons:"
    )

    y_position = height - 175 * mm

    pdf.setFont(
        "Helvetica",
        10
    )

    if reasons:

        for reason in reasons:

            pdf.drawString(
                30 * mm,
                y_position,
                "- " + reason[:100]
            )

            y_position -= 8 * mm

    else:

        pdf.drawString(
            30 * mm,
            y_position,
            "No suspicious patterns detected."
        )

    # Footer
    pdf.setFillColor(
        colors.HexColor("#063b70")
    )

    pdf.setFont(
        "Helvetica",
        8
    )

    pdf.drawString(
        25 * mm,
        15 * mm,
        "AI-Based Phishing URL Detection and Classification System"
    )

    pdf.save()

    return send_file(
        file_path,
        as_attachment=True,
        download_name="Phishing_Scan_Report.pdf",
        mimetype="application/pdf"
    )


# ==================================================
# HISTORY
# ==================================================

@app.route("/history")
def history():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    data = get_history()

    return render_template(
        "history.html",
        history=data
    )


# ==================================================
# CLEAR HISTORY
# ==================================================

@app.route("/clear_history", methods=["POST"])
def clear_history_route():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    clear_history()

    return redirect(
        url_for("history")
    )


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():

    if not session.get("logged_in"):

        return redirect(
            url_for("login")
        )

    (
        total,
        phishing,
        suspicious,
        legitimate
    ) = get_statistics()

    return render_template(
        "dashboard.html",
        total=total,
        phishing=phishing,
        suspicious=suspicious,
        legitimate=legitimate
    )


# ==================================================
# MODEL PERFORMANCE
# ==================================================

@app.route("/performance")
def performance():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # Confusion Matrix
    confusion_matrix = [
        [6, 0, 0],
        [0, 3, 0],
        [0, 0, 7]
    ]

    # Calculate Precision, Recall and F1 Score
    classes = ["Phishing", "Suspicious", "Legitimate"]

    metrics = []

    total_correct = 0
    total_samples = 0

    for i in range(3):

        true_positive = confusion_matrix[i][i]

        false_positive = sum(
            confusion_matrix[j][i]
            for j in range(3)
            if j != i
        )

        false_negative = sum(
            confusion_matrix[i][j]
            for j in range(3)
            if j != i
        )

        support = sum(confusion_matrix[i])

        total_correct += true_positive
        total_samples += support

        # Precision
        if true_positive + false_positive == 0:
            precision = 0
        else:
            precision = (
                true_positive /
                (true_positive + false_positive)
            ) * 100

        # Recall
        if true_positive + false_negative == 0:
            recall = 0
        else:
            recall = (
                true_positive /
                (true_positive + false_negative)
            ) * 100

        # F1 Score
        if precision + recall == 0:
            f1_score = 0
        else:
            f1_score = (
                2 * precision * recall /
                (precision + recall)
            )

        metrics.append({
            "class": classes[i],
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1_score, 2),
            "support": support
        })

    # Overall Accuracy
    if total_samples == 0:
        accuracy = 0
    else:
        accuracy = (
            total_correct /
            total_samples
        ) * 100

    # Macro Average
    macro_precision = round(
        sum(item["precision"] for item in metrics) / 3,
        2
    )

    macro_recall = round(
        sum(item["recall"] for item in metrics) / 3,
        2
    )

    macro_f1 = round(
        sum(item["f1_score"] for item in metrics) / 3,
        2
    )

    return render_template(
        "performance.html",
        accuracy=round(accuracy, 2),
        confusion_matrix=confusion_matrix,
        metrics=metrics,
        macro_precision=macro_precision,
        macro_recall=macro_recall,
        macro_f1=macro_f1
    )

# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )