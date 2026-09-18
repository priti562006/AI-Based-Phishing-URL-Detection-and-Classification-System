import sqlite3


# =========================
# CREATE DATABASE
# =========================

def create_database():

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    # Scan History Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            score INTEGER,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================
# REGISTER USER
# =========================

def register_user(username, password):

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO users (username, password)
            VALUES (?, ?)
        """, (username, password))

        conn.commit()
        success = True

    except sqlite3.IntegrityError:
        success = False

    conn.close()

    return success


# =========================
# CHECK LOGIN
# =========================

def check_user(username, password):

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM users
        WHERE username = ? AND password = ?
    """, (username, password))

    user = cursor.fetchone()

    conn.close()

    return user


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

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
    """)

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'PHISHING'
    """)

    phishing = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'SUSPICIOUS'
    """)

    suspicious = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scan_history
        WHERE result = 'LEGITIMATE'
    """)

    legitimate = cursor.fetchone()[0]

    conn.close()

    return total, phishing, suspicious, legitimate


# =========================
# CLEAR HISTORY
# =========================

def clear_history():

    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scan_history")

    conn.commit()
    conn.close()
