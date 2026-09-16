import sqlite3


# =========================
# CREATE DATABASE
# =========================

def create_database():

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            score INTEGER,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


# =========================
# SAVE SCAN
# =========================

def save_scan(url, result, score):

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (url, result, score)
        VALUES (?, ?, ?)
    """, (url, result, score))

    conn.commit()
    conn.close()


# =========================
# GET SCAN HISTORY
# =========================

def get_history():

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, url, result, score, scan_date
        FROM scan_history
        ORDER BY id ASC
    """)

    data = cursor.fetchall()

    conn.close()

    return data


# =========================
# GET DASHBOARD STATISTICS
# =========================

def get_statistics():

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()


    # Total Scans
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
    """)

    total = cursor.fetchone()[0]


    # Phishing URLs
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'PHISHING'
    """)

    phishing = cursor.fetchone()[0]


    # Suspicious URLs
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'SUSPICIOUS'
    """)

    suspicious = cursor.fetchone()[0]


    # Legitimate URLs
    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'LEGITIMATE'
    """)

    legitimate = cursor.fetchone()[0]


    conn.close()


    return total, phishing, suspicious, legitimate
def clear_history():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scan_history")

    conn.commit()
    conn.close()