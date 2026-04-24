#Scoring/reputation_scorer.py
#Confidence-weighted reputation scoring engine. 
#Takes a unified IOC record and produces a score from 0-100 plus a severity label. 

import logging 
import yaml
from datetime import datetime, timezone 
from pathlib import Path 
from config import (
    IOC_TYPE_MULTIPLIERS,
    SOURCE_WEIGHTS,
    SEVERITY_THRESHOLDS,
    RECENCY_THRESHOLDS,
    RECENCY_DECAY_FACTORS
)

logger = logging.getLogger(__name__)

#Load YAML config 
_config_path = Path(__file__).parent / "score_config.yaml"
with open(_config_path, "r") as f:
    _config = yaml.safe_load(f)

SIGNAL_WEIGHTS = _config["signal_weights"]

def _get_recency_decay(last_seen_str):
    """
    Calculates a decay factor based on how recently the IOC was seen.
    Returns a float between 0.25 & 1.0.
    """
    if not last_seen_str:
        return RECENCY_DECAY_FACTORS["stale"] # Unknown = treat as stale 
    
    try:
        last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        days_ago = (now - last_seen).days
    
    except (ValueError, TypeError):
        logger.warning(f"Could not parse date: {last_seen_str}")
        return RECENCY_DECAY_FACTORS["stale"]
    
    if days_ago <= RECENCY_THRESHOLDS["fresh_days"]:
        return RECENCY_DECAY_FACTORS["fresh"]
    elif days_ago <= RECENCY_THRESHOLDS["stale_days"]:
        return RECENCY_DECAY_FACTORS["stale"]
    elif days_ago <= RECENCY_THRESHOLDS["aged_days"]:
        return RECENCY_DECAY_FACTORS["aged"]
    else:
        return RECENCY_DECAY_FACTORS["expired"]


#Calculate base score 
def _calculate_base_score(ioc_record):
    """
    Calculating a base score from 0 - 100 using signal weights. 
    Normalizes pulse count, source count, tag count, and malware families 
    """
    #Normalize signals to 0-1 range
    pulse_score = min(ioc_record.get("pulse_count", 0) / 100, 1.0)
    source_score = min(ioc_record.get("source_count", 0) / 4, 1.0)
    tag_score    = min(len(ioc_record.get("tags",[])) / 20, 1.0)
    malware_score = min(len(ioc_record.get("malware_families", []))/ 5, 1.0)

    #Weighted sum of signals
    base_score = (
        pulse_score * SIGNAL_WEIGHTS["pulse_count"] +
        source_score * SIGNAL_WEIGHTS["source_count"] +
        tag_score * SIGNAL_WEIGHTS["tag_count"] +
        malware_score * SIGNAL_WEIGHTS["malware_family"]
    )

    #Scale to 0-100
    return base_score * 100
   
def _get_source_confidence(ioc_record):
    """
    Calculates a confidence multiplier based on which sources reported the IOC.
    Returns a weighted average of source weights for all sources that hit. 
    """
    sources = ioc_record.get("sources", [])
    if not sources:
        return 0.5 # No sources = low confidence
    
    weights = [SOURCE_WEIGHTS.get(source, 0.5) for source in sources]
    return sum(weights) / len(weights)

def score_ioc(ioc_record):
    """
    Main scoring function.
    Takes a unified IOC record, and returns the same record with reputation score & severity label added. 
    """

    if not ioc_record:
        return None 
    
    from config import ALLOWLIST_DOMAINS, ALLOWLIST_IPS
    ioc       = ioc_record.get("ioc", "")
    ioc_type  = ioc_record.get("ioc_type", "ip")
    last_seen = ioc_record.get("last_seen", None)

    # Allowlist check — known legitimate infrastructure scores low regardless
    if ioc_type == "domain" and ioc in ALLOWLIST_DOMAINS:
        ioc_record["reputation_score"] = 5.0
        ioc_record["severity"]         = "low"
        ioc_record["score_components"] = {"allowlisted": True}
        logger.info(f"Allowlisted domain: {ioc} -> 5.0 (low)")
        return ioc_record

    if ioc_type == "ip" and ioc in ALLOWLIST_IPS:
        ioc_record["reputation_score"] = 5.0
        ioc_record["severity"]         = "low"
        ioc_record["score_components"] = {"allowlisted": True}
        logger.info(f"Allowlisted IP: {ioc} -> 5.0 (low)")
        return ioc_record

    # Get each component 
    base_score     = _calculate_base_score(ioc_record)
    source_confidence = _get_source_confidence(ioc_record)
    type_multiplier = IOC_TYPE_MULTIPLIERS.get(ioc_type, 1.0)
    recency_decay   = _get_recency_decay(last_seen)

    #Applying the full formula 
    raw_score = base_score * source_confidence * type_multiplier * recency_decay

    #Cap at 100
    final_score = min(round(raw_score, 2), 100.0)

    #Determine severity label based on thresholds
    if final_score >= SEVERITY_THRESHOLDS["critical"]:
        severity = "critical"
    elif final_score >= SEVERITY_THRESHOLDS["high"]:
        severity = "high"
    elif final_score >= SEVERITY_THRESHOLDS["medium"]:
        severity = "medium"
    else:
        severity = "low"

    #Add results back to record & return 
    ioc_record["reputation_score"] = final_score
    ioc_record["severity"] = severity
    ioc_record["score_components"] = {
        "base_score": round(base_score, 2),
        "source_confidence": round(source_confidence, 2),
        "type_multiplier": type_multiplier,
        "recency_decay": recency_decay,
    }

    logger.info(f"Scored {ioc_record['ioc']} -> {final_score} ({severity})")
    return ioc_record
