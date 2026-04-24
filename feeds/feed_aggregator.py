# feeds/feed_aggregator.py
# Aggregates IOC data from all sources into a single unified record.
# This is the main entry point for all feed queries.

import logging
from datetime import datetime
from feeds.otx_client import OTXClient
from feeds.abusech_client import AbuseCHClient
from feeds.vt_client import VirusTotalClient

logger = logging.getLogger(__name__)

otx     = OTXClient()
abusech = AbuseCHClient()
vt      = VirusTotalClient()

def aggregate_ioc(ioc, ioc_type):
    """
    Queries all relevant sources for a single IOC and merges the results.
    Returns one unified dictionary representing the full threat picture.
    """
    logger.info(f"Aggregating data for {ioc_type}: {ioc}")

    results = []

    # Query OTX for all IOC types
    otx_result = otx.query_ioc(ioc, ioc_type)
    if otx_result:
        results.append(otx_result)

     # Query VirusTotal for all IOC types
    vt_result = vt.query_ioc(ioc, ioc_type)
    if vt_result:
        results.append(vt_result)

    # Query abuse.ch based on IOC type
    if ioc_type == "hash":
        abusech_result = abusech.query_hash(ioc)
        if abusech_result:
            results.append(abusech_result)

    elif ioc_type in ("url", "domain"):
        abusech_result = abusech.query_url(ioc)
        if abusech_result:
            results.append(abusech_result)

    elif ioc_type == "ip":
        abusech_result = abusech.query_ip(ioc)
        if abusech_result:
            results.append(abusech_result)



    if not results:
        logger.warning(f"No data found for {ioc_type}: {ioc}")
        return None

    return _merge_results(ioc, ioc_type, results)


def _merge_results(ioc, ioc_type, results):
    """
    Merges multiple source results into a single unified record.
    Deduplicates tags, malware families, and threat actors.
    """
    # Collect all tags, malware families, and threat actors across sources
    all_tags             = []
    all_malware_families = []
    all_threat_actors    = []
    sources_hit          = []

    for result in results:
        all_tags             += result.get("tags", [])
        all_malware_families += result.get("malware_families", [])
        all_threat_actors    += result.get("threat_actors", [])
        sources_hit.append(result.get("source", "unknown"))

    # Use the first result that has a value for these fields
    country    = next((r.get("country")    for r in results if r.get("country")),    None)
    asn        = next((r.get("asn")        for r in results if r.get("asn")),        None)
    first_seen = next((r.get("first_seen") for r in results if r.get("first_seen")), None)
    last_seen  = next((r.get("last_seen")  for r in results if r.get("last_seen")),  None)
    file_type  = next((r.get("file_type")  for r in results if r.get("file_type")),  None)

    # Sum pulse counts across all sources
    total_pulse_count = sum(r.get("pulse_count", 0) for r in results)

    return {
        "ioc":              ioc,
        "ioc_type":         ioc_type,
        "sources":          sources_hit,
        "source_count":     len(sources_hit),
        "pulse_count":      total_pulse_count,
        "tags":             list(set(all_tags)),
        "malware_families": list(set(all_malware_families)),
        "threat_actors":    list(set(all_threat_actors)),
        "country":          country,
        "asn":              asn,
        "first_seen":       first_seen,
        "last_seen":        last_seen,
        "file_type":        file_type,
        "queried_at":       datetime.now().isoformat(),
        "raw_results":      results,
    }
