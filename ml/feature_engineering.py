#Machine Learning (ML) : ml/feature_engineering.py
#Converts unified IOC records into a numerical feature matrix for ML models. 
#Every ML model in this project reads from the output of this file. 

import logging 
import numpy as np 
import pandas as pd
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

#Maximum values for normalizations -- Same logic as scoring system
MAX_PULSE_COUNT = 100
MAX_TAG_COUNT = 20
MAX_MALWARE_FAMILIES = 5

IOC_TYPE_ENCODING = {
    "ip": 0,
    "domain": 1,
    "hash": 2,
    "url": 3,
}

def extract_features(ioc_record):
    """
    Converts a single unified IOC record into a numerical feature vector.
    Returns a dictionary of named features ready for a pandas DataFrame.
    """
    #Recency features 
    def days_since(date_str):
        if not date_str:
            return 180 #Default to stale if unknown 
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            return (now - dt).days
        except (ValueError, TypeError):
            return 180 #Treat unparseable dates as stale

    days_since_first = days_since(ioc_record.get("first_seen"))
    days_since_last  = days_since(ioc_record.get("last_seen"))

    #Normalize count features 
    pulse_count = min(ioc_record.get("pulse_count", 0) / MAX_PULSE_COUNT, 1.0)
    source_count = min(ioc_record.get("source_count", 0) / 4, 1.0)
    tag_count = min(len(ioc_record.get("tags", [])) / MAX_TAG_COUNT, 1.0)
    malware_count = min(len(ioc_record.get("malware_families", [])) / MAX_MALWARE_FAMILIES, 1.0)
    threat_actor_count = min(len(ioc_record.get("threat_actors", [])) / 5, 1.0)

    #Binary flags 
    has_country = 1 if ioc_record.get("country") else 0
    has_asn = 1 if ioc_record.get("asn") else 0
    has_campaign = 1 if ioc_record.get("threat_actors") else 0

    #IOC type encoding
    ioc_type_encoded = IOC_TYPE_ENCODING.get(ioc_record.get("ioc_type", "ip"), 0)

    #Reputation score if it already has been calculated 
    reputation_score = ioc_record.get("reputation_score", 0.0) / 100

    return {
        "pulse_count": pulse_count,
        "source_count": source_count,
        "tag_count": tag_count,
        "malware_count": malware_count,
        "threat_actor_count": threat_actor_count,
        "days_since_first": days_since_first,
        "days_since_last": days_since_last,
        "has_country": has_country,
        "has_asn": has_asn,
        "has_campaign": has_campaign,
        "ioc_type_encoded": ioc_type_encoded,
        "reputation_score": reputation_score,

    }

def build_feature_matrix(ioc_records):
    """
    Takes a list of IOC records and builds a pandas DataFrame.
    Each row is one IOC, each column is one feature.
    This returns the DataFrame and the list of IOC identifiers. 
    """
    if not ioc_records:
        logger.warning("No IOC records provided to build feature matrix!")
        return None, [] 
    
    features = []
    ioc_ids = []

    for record in ioc_records:
        try:
            feature_vector = extract_features(record)
            features.append(feature_vector)
            ioc_ids.append(record.get("ioc", "unknown"))
        except Exception as e:
            logger.error(f"Failed to extract features for {record.get('ioc')}: {e}")
            continue 

    if not features:
        logger.error("Feature extraction failed for all records!")
        return None, []
    
    df = pd.DataFrame(features)
    df.fillna(0, inplace=True) #Fill any missing values with 0

    logger.info(f"Built feature matrix: {df.shape[0]} IOCs x {df.shape[1]} features")
    return df, ioc_ids


    
