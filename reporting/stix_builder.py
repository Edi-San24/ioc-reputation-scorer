# Reporting /stix builder.py
# Converts scored IOCs to a STIX format
# Outputs a STIX-friendly Bundle that can be ingested by any STIX-compatible system. (Example: SIEMs and Splunk)

import logging 
import uuid 
from datetime import datetime, timezone
from pathlib import Path 
from config import REPORTS_DIR

logger = logging.getLogger(__name__)

try:
    from stix2 import(
        Bundle,
        Indicator,
        Malware,
        Relationship, 
        ThreatActor,
        Identity,
    )
    STIX_AVAILABLE = True 
except ImportError:
    STIX_AVAILABLE = False 
    logger.warning("stix package not installed! STIX export unavailable")

# [Tool Identity]: - attributes exported intelligence to your tool
TOOL_IDENTITY = None 

def _get_identity():
    """
    Returns a STIX Identity object representing this tool.
    Created once and reused across exports 
    """
    global TOOL_IDENTITY
    if TOOL_IDENTITY is None and STIX_AVAILABLE:
        TOOL_IDENTITY = Identity(
            name = "IOC Reputation Scoring System",
            identity_class = "system",
            description = "Automated IOC enrichment and triage pipeline.",
    )
    return TOOL_IDENTITY

def _build_indicator_pattern(ioc, ioc_type):
    """
    Converts an IOC value and type into a STIX pattern string. 
    """

    patterns = {
        "ip": f"[ipv4-addr:value = '{ioc}']",
        "domain": f"[domain-name:value = '{ioc}']",
        "hash": f"[file:hashes.'SHA-256' = '{ioc}']",
        "url": f"[url:value = '{ioc}']",
    }
    return patterns.get(ioc_type)

def _get_indicator_type(ioc_type, tags):
    """
    Maps IOC type and tags to a STIX indicator type. 
    """
    tag_str = " ".join(tags).lower()

    if ioc_type == "hash":
        return "malicious-activity"
    if any(t in tag_str for t in ["phish", "credential", "login"]):
        return "malicious-activity"
    if any(t in tag_str for t in ["c2", "botnet", "command"]):
        return "malicious-activity"
    return "malicious-activity"

def build_stix_bundle(scored_records, anomaly_results=None, cluster_results=None, campaign_results=None):
    """
    Converts a list of scored IOC records into a STIX Bundle.
    Returns a STIX Bundle object or None if stix2 is not available.
    """
    if not STIX_AVAILABLE:
        logger.warning("STIX 2.1 not available. Cannot build STIX Bundle.")
        return None

    if not scored_records:
        logger.warning("No records provided for STIX export.")
        return None

    identity = _get_identity()
    objects  = [identity]

    for record in scored_records:
        ioc        = record.get("ioc")
        ioc_type   = record.get("ioc_type")
        score      = record.get("reputation_score", 0)
        severity   = record.get("severity", "low")
        tags       = record.get("tags", [])
        families   = record.get("malware_families", [])
        first_seen = record.get("first_seen")

        pattern = _build_indicator_pattern(ioc, ioc_type)
        if not pattern:
            continue

        valid_from = datetime.now(timezone.utc)
        if first_seen:
            try:
                valid_from = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        indicator = Indicator(
            name=f"{ioc_type.upper()} - {ioc}",
            description=f"Reputation score: {score} | Severity: {severity.upper()}",
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            labels=[severity, ioc_type] + tags[:5],
            created_by_ref=identity.id,
        )
        objects.append(indicator)

        for family in families:
            if not family or family.startswith("http"):
                continue
            malware_obj = Malware(
                name=family,
                is_family=True,
                created_by_ref=identity.id,
            )
            objects.append(malware_obj)

            # Relationship: indicator indicates malware
            rel = Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware_obj.id,
                created_by_ref=identity.id,
            )
            objects.append(rel)

    return Bundle(objects=objects)

def write_stix_report(scored_records, anomaly_results = None, cluster_results = None, campaign_results = None, filename = None):
    """
    Builds a STIX bundle and writes it to a JSON file in data/reports/.
    Returns the path of the written file or None on failure.
    """

    if not STIX_AVAILABLE:
        logger.warning("Stix2 not available... Skipping Exports")
        return None
    
    bundle = build_stix_bundle(scored_records, anomaly_results, cluster_results, campaign_results)
    if not bundle:
        return None
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioc_stix_{timestamp}.json"

    output_path = Path(REPORTS_DIR) / filename

    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty = True))

    logger.info(f"STIX report written to {output_path}")
    return output_path