# ---------------------------
# Feeds RSS y JSON de ciberseguridad
# ---------------------------

FEEDS = [
    {"url": "https://clintgibler.com/feed.xml", "name": "Clint Gibler"},
    {"url": "https://therecord.media/feed", "name": "The Record"},
    {"url": "https://www.bleepingcomputer.com/feed/", "name": "Bleeping Computer"},
    {"url": "https://thehackernews.com/feeds/posts/default", "name": "The Hacker News"},
    {"url": "https://www.securityweek.com/feed/", "name": "Security Week"},
    {"url": "https://www.darkreading.com/rss.xml", "name": "Dark Reading"},
    {"url": "https://krebsonsecurity.com/feed/", "name": "Krebs on Security"},
    {"url": "https://www.schneier.com/feed/", "name": "Schneier on Security"},
    {"url": "https://threatpost.com/feed/", "name": "Threat Post"},
    {
      "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={}&pubEndDate={}&resultsPerPage=20",
      "name": "NVD",
      "type": "json"
   }
]

# ---------------------------
# Clasificación de incidentes
# ---------------------------
INCIDENT_TYPES = {
    "ransomware": "Ransomware",
    "breach": "Breach",
    "cve-": "Vulnerability",
    "apt": "APT",
    "malware": "Malware",
    "ddos": "DDoS",
    "phishing": "Phishing"
}

# ---------------------------
# Severidad
# ---------------------------
SEVERITY_RULES = {
    "critical": ["critical", "emergency", "urgent", "active exploitation", "ransomware", "breach"],
    "high": ["high", "severe", "important", "warning", "patch now", "update"],
    "medium": ["informative", "info"]
}

# ---------------------------
# Archivos de historial/logs
# ---------------------------
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

HISTORY_FILE = os.path.join(BASE_DIR, "data", "history.json")

LOG_FILE = os.path.join(BASE_DIR, "logs", "app.log")

# ---------------------------
# Telegram (si quieres usarlo después)
# ---------------------------
TELEGRAM_TOKEN = "7468276720:AAHdgjkwPThpX31amMB9Fah1f2mxpHg4xsw"
TELEGRAM_CHAT_ID = "1433344545"
