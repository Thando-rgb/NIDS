# All the NIDS settings are here
# The only file that will be used to tune the system

# --- The detection threshold ---
PORT_SCAN_THRESHOLD = 5
TIME_WINDOW = 10

SYN_FLOOD_THRESHOLD = 100

PING_SWEEP_THRESHOLD = 3

# --- Email alerts ---
EMAIL_ENABLED = False
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_password"
EMAIL_RECEIVER = "your_email@gmail.com"

# --- Log File ---
LOG_FILE = "nids_log.txt"

# --- Dashboard ---
DASHBOARD_PORT = 5000

# Network interface to listen on
# Set to None for auto-detection
# Set to full path for manual override
# Example: "\\Device\\NPF_{0A29B44E-1175-4DDF-83E7-215B350A4D2A}"
INTERFACE = None