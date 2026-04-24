
#test_feeds.py

#Testing the full pipeline: ingestion -> scoring -> Machine Learning. 

import logging
import json
from feeds.feed_aggregator import aggregate_ioc
from scoring.reputation_scorer import score_ioc
from ml.anomaly_detector import detect_anomalies
from ml.clusterer import cluster_iocs
from ml.campaign_classifier import classify_campaigns

logging.basicConfig(level=logging.INFO)

# Test IOCs - mix of IPs, domains, hashes

TEST_IOCS = [
    ("185.220.101.45", "ip"),
    ("185.220.101.46", "ip"),
    ("185.220.101.47", "ip"),
    ("185.220.101.48", "ip"),
    ("185.220.101.49", "ip"),
    ("185.220.101.50", "ip"),
    ("185.220.101.51", "ip"),
    ("185.220.101.52", "ip"),
    ("185.220.101.53", "ip"),
    ("185.220.101.54", "ip"),
    ("44d88612fea8a8f36de82e1278abb02f", "hash"),
    ("malware.com", "domain"),
    ("evil-phishing.net", "domain"),
    ("phishing-site.net", "domain"),
    ("badactor.ru", "domain"),
    ("malicious-payload.com", "domain"),
    ("trojan-host.cn", "domain"),
    ("botnet-c2.org", "domain"),
    ("ransomware-drop.net", "domain"),
    ("exploit-kit.xyz", "domain"),
]

print("=== IOC Ingestion and Scoring ===")
scored_records = []
for ioc, ioc_type in TEST_IOCS:
    print(f"Processing {ioc_type}: {ioc}")
    record = aggregate_ioc(ioc, ioc_type)
    if record:
        scored = score_ioc(record)
        if scored:
            scored_records.append(scored)
            
print(f"\nSuccessfully scored {len(scored_records)} IOCs.")

if scored_records:
    print("\n=== Running Anomaly Detection ===")
    anomalies = detect_anomalies(scored_records)
    for ioc, result in anomalies.items():
        print(f"{ioc}: anomaly={result['is_anomaly']}, score={result['anomaly_score']}")
    
    print("\n=== Running Clustering ===")
    clusters = cluster_iocs(scored_records)
    for ioc, cluster_info in clusters.items():
        print(f"{ioc}: {cluster_info['cluster_label']}")

    print("\n=== Running Campaign Classification ===")
    campaigns = classify_campaigns(scored_records)
    for ioc, result in campaigns.items():
        print(f"{ioc}: campaign = {result['is_campaign']} confidence={result['campaign_confidence']}")


print(f"Campaign results: {campaigns}")
