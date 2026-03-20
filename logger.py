# Handles all logging to console and file
# Handles sending email alerts
# Every other file imports from here when it needs to log something 

import logging
import smtplib
from email.mime.text import MIMEText

from config import LOG_FILE, EMAIL_ENABLED, EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECEIVER

# Set up the logging system
# This runs once when logger.py is first imported
# It configures WHERE logs go (the file) and WHAT FORMAT they use.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_info (message):
    """Log a normal informal message to console and file."""
    print(f"[INFO] {message}")
    logging.info(message)
    
def log_alert(message):
    """Log a security alert to console and file. Sends email if enabled."""
    print(f"[ALERT] {message}")
    logging.warning(message)
    if EMAIL_ENABLED:
        send_email(message)
        
def send_email(message):
    """send an email alert via Gmail."""
    try:
        msg = MIMEText(message)
        msg["Subject"] = "NIDS Alert - Suspicious Activity Detected"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print("[INFO] Email alert sent successfully")
        
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")