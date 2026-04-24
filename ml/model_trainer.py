# ml/model_trainer.py
#Pre-trains all three ML models on a batch of IOCs and saves  them to disk.
#Run this **once** before using the CLI for single IOC queries.
#Usage: python -m ml.model_trainer 

import logging
from pathlib import Path
from feeds.feed_aggregator import aggregate_ioc
from scoring.reputation_scorer import score_ioc
from ml.anomaly_detector import AnomalyDetector
from ml.clusterer import IOCClusterer
from ml.campaign_classifier import CampaignClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#Path to save models 
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

ANOMALY_MODEL_PATH = MODELS_DIR / "anomaly_detector.joblib"
CLUSTERER_MODEL_PATH = MODELS_DIR / "clusterer.joblib"
CAMPAIGN_MODEL_PATH = MODELS_DIR / "campaign_classifier.joblib"

#Training IOCs - mix of types for diverse feature coverage 
TRAINING_IOCS = [
    # ── Tor Exit Nodes / Scanning IPs (medium confidence) ─────────────────────
    ("185.220.101.45", "ip"),
    ("185.220.101.46", "ip"),
    ("185.220.101.47", "ip"),
    ("185.220.101.34", "ip"),
    ("185.220.101.35", "ip"),

    # ── Known Botnet C2 IPs (high confidence) ─────────────────────────────────
    ("91.92.251.103", "ip"),
    ("194.165.16.11", "ip"),
    ("45.142.212.100", "ip"),
    ("185.234.218.57", "ip"),
    ("194.147.78.155", "ip"),

    # ── Known Benign IPs (should score low) ───────────────────────────────────
    ("8.8.8.8", "ip"),
    ("1.1.1.1", "ip"),
    ("208.67.222.222", "ip"),

    # ── Ransomware Hashes (high confidence) ───────────────────────────────────
    ("d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e", "hash"),  # REvil
    ("ee14d4bac5dfda479a81d91b682ecc42794163b233685741e0be0df5fe29e57d", "hash"),   # XWorm
    ("9001567e2025f83c936b8746fd3b01e44572f70d8ddec39b75b9459f7e5089c8", "hash"),  # FormBook
    ("c881b775bf291491c50ee8d6aca59282633775829726062a1bb0086a69b4f80a", "hash"),  # FormBook

    # ── Known Malicious Domains (high confidence) ──────────────────────────────
    ("malware.com", "domain"),
    ("emotet-c2.com", "domain"),
    ("qakbot-drop.net", "domain"),

    # ── Known Benign Domains (should score low) ────────────────────────────────
    ("google.com", "domain"),
    ("microsoft.com", "domain"),
    ("github.com", "domain"),
    ("amazon.com", "domain"),

    # ── Phishing Domains (medium-high confidence) ──────────────────────────────
    ("secure-paypal-login.com", "domain"),
    ("amazon-security-alert.net", "domain"),
    ("microsoft-update-center.com", "domain"),
    ("apple-id-verify.net", "domain"),

    # ── Known Malicious URLs ───────────────────────────────────────────────────
    ("http://malware.com/payload.exe", "url"),
    ("http://emotet-c2.com/gate.php", "url"),

    # ── Emotet Infrastructure (from OTX pulse) ─────────────────────────────────
    ("162.243.103.246", "ip"),
    ("203.130.0.69", "ip"),
    ("50.35.17.13", "ip"),
    ("168.197.45.36", "ip"),
    ("49.205.182.134", "ip"),
    ("51.159.23.217", "ip"),
    ("115.79.195.246", "ip"),
    ("51.75.33.127", "ip"),
    ("51.89.36.180", "ip"),
    ("5.196.108.185", "ip"),

    # ── Emotet Hashes (from OTX pulse) ────────────────────────────────────────
    ("ea48e310224317a3a93d7679dbb50ae967383d973cf7713613d8a240224ff454", "hash"),
    ("8251b384d68e9359fa26c9494ffdd5acf2af7dc31ad44444f8ecdc88201567b1", "hash"),
    ("6d25958284d54f9c8f4faf74f4227ad4fa916f5620ada5662c86f62dc0834a37", "hash"),

    # ── RedLine Stealer Infrastructure (from OTX pulse) ───────────────────────
    ("185.222.58.36", "ip"),
    ("77.73.133.19", "ip"),
    ("91.215.85.155", "ip"),
    ("37.220.87.70", "ip"),
    ("91.240.118.65", "ip"),
    ("77.73.134.24", "ip"),
    ("45.15.157.131", "ip"),

    # ── RedLine Stealer Hash (from OTX pulse) ─────────────────────────────────
    ("829c8a42d65b1587d2067127d22ed243d75c50e3b0830344dd5d64ac6ce390de", "hash"),

    # ── Cobalt Strike Infrastructure (from OTX pulse) ─────────────────────────
    ("152.42.226.164", "ip"),
    ("115.191.18.57", "ip"),
    ("156.224.28.186", "ip"),
    ("59.110.40.60", "ip"),
    ("47.120.20.86", "ip"),
    ("47.94.165.50", "ip"),
    ("85.239.151.38", "ip"),

    # ── Cobalt Strike Domains (from OTX pulse) ────────────────────────────────
    ("lokjosbn.xyz", "domain"),
    ("9niang.cloud", "domain"),

    # ── Additional Benign IPs ──────────────────────────────────────────────────
    ("9.9.9.9", "ip"),        # Quad9 DNS
    ("94.140.14.14", "ip"),   # AdGuard DNS
    ("185.228.168.9", "ip"),  # CleanBrowsing DNS
    ("76.76.19.19", "ip"),    # Alternate DNS
    ("8.26.56.26", "ip"),     # Comodo Secure DNS

    # ── Additional Benign Domains ──────────────────────────────────────────────
    ("cloudflare.com", "domain"),
    ("apple.com", "domain"),
    ("twitter.com", "domain"),
    ("linkedin.com", "domain"),
    ("wikipedia.org", "domain"),
]

def collect_training_data():
    """
    Ingests and scores all training IOCs.
    Returns a list of scored records ready for ML training.
    """

    logger.info(f"Collecting training data for {len(TRAINING_IOCS)} IOCs...")
    scored_records = []

    for ioc, ioc_type in TRAINING_IOCS:
        logger.info(f"Processing {ioc_type}: {ioc}")
        record = aggregate_ioc(ioc, ioc_type)
        if record:
            scored = score_ioc(record)
            if scored:
                scored_records.append(scored)

    logger.info(f"Collected {len(scored_records)} scored records.")
    return scored_records

def train_and_save_models(scored_records):
    """
    Trains all three ML models and saves them to disk.
    """
    if not scored_records:
        logger.error("No scored records available for training!")
        return False
    
    #Train anomaly detector
    logger.info("Training anomaly detector...")
    anomaly_detector = AnomalyDetector()
    if anomaly_detector.fit(scored_records):
        anomaly_detector.save(ANOMALY_MODEL_PATH)
        logger.info(f"Anomaly detector saved to {ANOMALY_MODEL_PATH}")
    else:
        logger.warning("Anomaly detector training failed!")

    #Train clusterer
    logger.info("Training clusterer...")
    clusterer = IOCClusterer()
    if clusterer.fit(scored_records):
        clusterer.save(CLUSTERER_MODEL_PATH)
        logger.info(f"Clusterer saved to {CLUSTERER_MODEL_PATH}")
    else:
        logger.warning("Clusterer training failed!")

    #Train campaign classifier
    logger.info("Training campaign classifier...")
    campaign_classifier = CampaignClassifier()
    if campaign_classifier.fit(scored_records):
        campaign_classifier.save(CAMPAIGN_MODEL_PATH)
        logger.info(f"Campaign classifier saved to {CAMPAIGN_MODEL_PATH}")
    else:
        logger.warning("Campaign classifier training failed!")
    return True

if __name__ == "__main__":
    logger.info("=== IOC Model Trainer ===")
    scored_records = collect_training_data()
    train_and_save_models(scored_records)
    logger.info("=== Training Complete ===")
