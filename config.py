#Loading the neccessary libraries
import os
from pathlib import Path 
from dotenv import load_dotenv

#API Key 
load_dotenv()

def _get_secret(key):
    """
    Reads secrets from Streamlit Cloud or local .env file.
    Streamlit secrets take priority over environment variables.
    """
    try:
        import streamlit as st
        if hasattr(st, 'secrets') and key in st.secrets:
            return st.secrets[key]
        return os.getenv(key, "")
    except Exception:
        return os.getenv(key, "")

OTX_API_KEY     = _get_secret("OTX_API_KEY")
VT_API_KEY      = _get_secret("VT_API_KEY")
ABUSECH_API_KEY = _get_secret("ABUSECH_API_KEY")


#Directory Paths and Creation
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
ENRICHED_DIR = DATA_DIR / "enriched"
REPORTS_DIR = DATA_DIR / "reports"

for _dir in [RAW_DIR, ENRICHED_DIR, REPORTS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)


#API URLS
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

OTX_ENDPOINTS = {
    "ip": "/indicators/IPv4/{ioc}/general",
    "domain": "/indicators/domain/{ioc}/general",
    "hash": "/indicators/file/{ioc}/general",
    "url": "/indicators/url/{ioc}/general"
}

#abuse.ch Feed URLS/Directories 
ABUSECH_FEEDS = {
    "malwarebazaar": "https://mb-api.abuse.ch/api/v1/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
}

#VirusTotal API URL
VT_BASE_URL = "https://www.virustotal.com/api/v3"

VT_ENDPOINTS = {
    "ip": "/ip_addresses/{ioc}",
    "domain": "/domains/{ioc}",
    "hash": "/files/{ioc}",
    "url": "/urls/{ioc}",
}

VT_RATE_LIMIT_DELAY = 3 # seconds between requests

#Scoring settings 
IOC_TYPE_MULTIPLIERS = {
    "ip": 1.0,
    "domain": 1.1,
    "hash": 1.3,
    "url": 1.05,
}

#Weights
SOURCE_WEIGHTS = {
    "otx": 0.85,
    "malwarebazaar": 0.90,
    "urlhaus": 0.80,
    "feodo": 0.95,
    "virustotal": 0.92,
}

#Severity thresholds
SEVERITY_THRESHOLDS = {
    "critical": 85,
    "high": 65,
    "medium": 40,
    "low": 0,
}

SEVERITY_COLORS = {
    "critical": "#FF2D2D",
    "high": "#FF8C00",
    "medium": "#FFD700",
    "low": "#00C851",
    
}

# ── Allowlist ──────────────────────────────────────────────────────────────────
# Known legitimate domains and IPs that should never score high
# regardless of pulse count (brand abuse protection)
ALLOWLIST_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "cloudflare.com", "github.com", "linkedin.com", "twitter.com",
    "wikipedia.org", "facebook.com", "youtube.com", "instagram.com",
}

ALLOWLIST_IPS = {
    "8.8.8.8", "8.8.4.4",        # Google DNS
    "1.1.1.1", "1.0.0.1",        # Cloudflare DNS
    "208.67.222.222",             # OpenDNS
    "9.9.9.9",                    # Quad9
    "94.140.14.14",               # AdGuard
}

#The last lines are Recency Decay, Machine Learning & Request Settings 

#RECENCY DECAY SETTINGS
RECENCY_DECAY_FACTORS = {
    "fresh": 1.00,  # last seen within 30 days
    "stale": 0.75,  # last seen 30-180 days ago
    "aged": 0.50,  # last seen 180-365 days
    "expired": 0.25,  #last seen 365+ days
}

#RECENCY SETTINGS
RECENCY_THRESHOLDS = {
    "fresh_days": 30,
    "stale_days": 180,
    "aged_days": 365,
}

#ML SETTINGS
ISOLATION_FOREST_CONTAMINATION = 0.05
ISOLATION_FOREST_RANDOM_STATE = 42

KMEANS_N_CLUSTERS = 6
KMEANS_RANDOM_STATE = 42

RF_N_ESTIMATORS = 200
RF_MAX_DEPTH = 10
RF_RANDOM_STATE = 42
RF_TEST_SIZE = 0.2

REQUEST_TIMEOUT = 15
REQUEST_RETRIES = 3
RETRY_BACKOFF = 2.0

LOG_LEVEL = "INFO"
LOG_FILE = BASE_DIR / "ioc_scorer.log"
