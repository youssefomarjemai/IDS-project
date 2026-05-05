import subprocess
import smtplib
import sqlite3
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from plyer import notification
from fpdf import FPDF
from datetime import datetime

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────
EMAIL_SENDER = "youremail@gmail.com"
EMAIL_PASSWORD = "your_16_char_app_password"
EMAIL_RECEIVER = "youremail@gmail.com"
MAX_ALERTS_BEFORE_BLOCK = 10     # block after 10 detections
MIN_ALERTS_BEFORE_EMAIL = 5      # only email after 5 alerts from same IP
EMAIL_COOLDOWN_MINUTES = 10      # wait 10 min before sending another email
MIN_BYTES_TO_ALERT = 500         # ignore packets smaller than 500 bytes
# ─────────────────────────────────────────

blocked_ips = set()
ip_alert_count = {}
last_email_time = {}             # tracks when last email was sent per IP
# ─────────────────────────────────────────
# 1. DESKTOP NOTIFICATION
# ─────────────────────────────────────────
def send_desktop_notification(src_ip, protocol, src_bytes):
    try:
        notification.notify(
            title="⚠️ IDS ALERT — Attack Detected!",
            message=f"Source: {src_ip}\nProtocol: {protocol}\nBytes: {src_bytes}",
            app_name="IDS System",
            timeout=5
        )
        print(f"[NOTIFICATION] Desktop alert sent for {src_ip}")
    except Exception as e:
        print(f"[NOTIFICATION ERROR] {e}")

# ─────────────────────────────────────────
# 2. EMAIL ALERT
# ─────────────────────────────────────────
def send_email_alert(src_ip, dst_ip, protocol, src_bytes, timestamp):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = f"🚨 IDS Alert — Attack from {src_ip}"

        body = f"""
        ⚠️ ATTACK DETECTED — IDS System Alert

        Time:           {timestamp}
        Source IP:      {src_ip}
        Destination IP: {dst_ip}
        Protocol:       {protocol}
        Bytes:          {src_bytes}

        Please review your dashboard immediately.
        http://127.0.0.1:8050

        — IDS Automated Response System
        """

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()

        print(f"[EMAIL] Alert sent for {src_ip}")
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

# ─────────────────────────────────────────
# 3. IP BLOCKING (Windows Firewall)
# ─────────────────────────────────────────
def block_ip(ip):
    if ip in blocked_ips:
        return

    if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('127.'):
        print(f"[BLOCK] Skipping local IP: {ip}")
        return

    try:
        rule_name = f"IDS_BLOCK_{ip}"
        command = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            'dir=in',
            'action=block',
            f'remoteip={ip}'
        ]
        subprocess.run(command, capture_output=True, check=True)
        blocked_ips.add(ip)
        print(f"[FIREWALL] ⛔ Blocked IP: {ip}")

        # Log the block to database
        log_block(ip)

    except subprocess.CalledProcessError as e:
        print(f"[FIREWALL ERROR] Could not block {ip}: {e}")
    except Exception as e:
        print(f"[FIREWALL ERROR] {e}")

def log_block(ip):
    try:
        conn = sqlite3.connect('logs/alerts.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                blocked_at TEXT
            )
        ''')
        cursor.execute(
            'INSERT INTO blocked_ips (ip, blocked_at) VALUES (?, ?)',
            (ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] {e}")

# ─────────────────────────────────────────
# 4. INCIDENT REPORT (PDF)
# ─────────────────────────────────────────
def generate_report(src_ip, dst_ip, protocol, src_bytes, timestamp):
    try:
        pdf = FPDF()
        pdf.add_page()

        # Header
        pdf.set_font("Arial", 'B', 20)
        pdf.set_text_color(220, 50, 50)
        pdf.cell(0, 15, "INCIDENT REPORT", ln=True, align='C')

        pdf.set_font("Arial", size=11)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, "Network Intrusion Detection System", ln=True, align='C')
        pdf.ln(10)

        # Divider
        pdf.set_draw_color(220, 50, 50)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)

        # Incident details
        pdf.set_font("Arial", 'B', 13)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "Incident Details", ln=True)
        pdf.ln(3)

        details = [
            ("Date & Time", timestamp),
            ("Source IP", src_ip),
            ("Destination IP", dst_ip),
            ("Protocol", protocol),
            ("Bytes Transferred", str(src_bytes)),
            ("Status", "ATTACK DETECTED"),
            ("Action Taken", "IP Blocked + Email Alert Sent"),
        ]

        pdf.set_font("Arial", size=11)
        for label, value in details:
            pdf.set_font("Arial", 'B', 11)
            pdf.cell(60, 9, f"{label}:", border=0)
            pdf.set_font("Arial", size=11)
            pdf.cell(0, 9, value, ln=True)

        pdf.ln(10)

        # Recommendation
        pdf.set_font("Arial", 'B', 13)
        pdf.cell(0, 10, "Recommendations", ln=True)
        pdf.ln(3)
        pdf.set_font("Arial", size=11)
        recommendations = [
            "1. Review firewall logs for additional suspicious activity",
            "2. Check if the source IP appears in threat intelligence feeds",
            "3. Monitor destination IP for signs of compromise",
            "4. Consider updating IDS rules based on this incident",
        ]
        for rec in recommendations:
            pdf.cell(0, 8, rec, ln=True)

        pdf.ln(10)

        # Footer
        pdf.set_font("Arial", 'I', 9)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 8, f"Report generated automatically by IDS System — {timestamp}", ln=True, align='C')

        # Save report
        filename = f"logs/incident_{src_ip.replace('.', '_')}_{datetime.now().strftime('%H%M%S')}.pdf"
        pdf.output(filename)
        print(f"[REPORT] PDF saved: {filename}")

    except Exception as e:
        print(f"[REPORT ERROR] {e}")

# ─────────────────────────────────────────
# MAIN RESPONSE HANDLER
# called from detect.py for every attack
# ─────────────────────────────────────────
def handle_attack(src_ip, dst_ip, protocol, src_bytes, timestamp):

    # ── Filter 1: ignore small packets (games, background apps)
    if src_bytes < MIN_BYTES_TO_ALERT:
        print(f"[FILTER] Packet too small ({src_bytes} bytes) — skipping response")
        return

    # ── Filter 2: ignore local network IPs
    if src_ip.startswith('192.168') or src_ip.startswith('10.') or src_ip.startswith('127.'):
        print(f"[FILTER] Local IP {src_ip} — skipping response")
        return

    # ── Count alerts per IP
    ip_alert_count[src_ip] = ip_alert_count.get(src_ip, 0) + 1
    count = ip_alert_count[src_ip]

    print(f"\n[RESPONSE] Attack from {src_ip} — flagged {count} times")

    # ── Always send desktop notification (but only every 5 detections)
    if count % 5 == 1:
        send_desktop_notification(src_ip, protocol, src_bytes)

    # ── Send email only after MIN_ALERTS_BEFORE_EMAIL and respect cooldown
    now = datetime.now()
    last_sent = last_email_time.get(src_ip)
    cooldown_passed = (
        last_sent is None or
        (now - last_sent).seconds / 60 >= EMAIL_COOLDOWN_MINUTES
    )

    if count >= MIN_ALERTS_BEFORE_EMAIL and cooldown_passed:
        send_email_alert(src_ip, dst_ip, protocol, src_bytes, timestamp)
        generate_report(src_ip, dst_ip, protocol, src_bytes, timestamp)
        last_email_time[src_ip] = now

    # ── Block IP only after MAX_ALERTS_BEFORE_BLOCK
    if count >= MAX_ALERTS_BEFORE_BLOCK:
        print(f"[RESPONSE] Blocking {src_ip} after {count} detections")
        block_ip(src_ip)