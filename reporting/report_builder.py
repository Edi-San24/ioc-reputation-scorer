# reporting/report_builder.py
# Generates structured intelligence reports from scored IOC records. 
# Outputs JSON & CSV formats to the data/reports directory. 

import json
import csv
import logging 
from datetime import datetime
from pathlib import Path
from config import REPORTS_DIR, SEVERITY_COLORS

logger = logging.getLogger(__name__)


def _sanitize_record(record):
    """
    Sanitizes a scored IOC record for reporting.
    Ensures all expected fields are present and formats them appropriately.
    """
   
    sanitized = {k: v for k, v in record.items() if k not in ("raw_data","raw_results")}
    return sanitized

def _get_severity_color(severity):
    """
    Returns a hex color code based on severity level.
    """
    return SEVERITY_COLORS.get(severity, "#FFFFFF") # Default to white if unknown

def build_report(scored_records, anomaly_results = None, cluster_results = None, campaign_results = None):
    """
    Builds a unified intelligence report from all pipelines.
    Merges scores, ML results & meta data into one record per IOC.
    """
    report_records = []

    for record in scored_records:
        ioc = record.get("ioc")
        sanitized = _sanitize_record(record)

        #Merge ML results if available
        if anomaly_results and ioc in anomaly_results:
            sanitized["anomaly"] = anomaly_results[ioc]

        if cluster_results and ioc in cluster_results:
            sanitized["cluster"] = cluster_results[ioc]

        if campaign_results and ioc in campaign_results:
            sanitized["campaign"] = campaign_results[ioc]

        #Severity color for dashboard
        sanitized["severity_color"] = _get_severity_color(
            sanitized.get("severity", "low")
        )

        report_records.append(sanitized)

    return report_records

def write_json_report(report_records, filename = None):
    """
    Writes the report to a JSON file in data/reports/.
    Returns the file path of the saved report.
    """

    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioc_report_{timestamp}.json"
    
    output_path = Path(REPORTS_DIR) / filename

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_iocs": len(report_records),
        "severity_summary": _get_severity_summary(report_records),
        "records": report_records, 
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default =str)

    logger.info(f"JSON report written to {output_path}")
    return output_path

def write_csv_report(report_records, filename = None):
    """
    Writes the report to a CSV file in data/reports/.
    Flattens nested ML fields into columns 
    Returns the file path of the saved report.
    """

    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ioc_report_{timestamp}.csv"
    
    output_path = Path(REPORTS_DIR) / filename

    # Flatten records for CSV output

    flat_records = []
    for record in report_records:
        flat = {
            "ioc": record.get("ioc"),
            "ioc_type": record.get("ioc_type"),
            "reputation_score": record.get("reputation_score"),
            "severity": record.get("severity"),
            "pulse_count": record.get("pulse_count"),
            "source_count": record.get("source_count"),
            "sources": ",".join(record.get("sources", [])),
            "country": record.get("country"),
            "asn": record.get("asn"),
            "first_seen": record.get("first_seen"),
            "last_seen": record.get("last_seen"),
            "malware_families": ",".join(record.get("malware_families", [])),
            "threat_actors": ",".join(record.get("threat_actors", [])),
            "is_anomaly":  record.get("anomaly", {}).get("is_anomaly", False),
            "anomaly_score": record.get("anomaly", {}).get("anomaly_score", None),
            "cluster_label": record.get("cluster", {}).get("cluster_label", None),
            "is_campaign": record.get("campaign", {}).get("is_campaign", False),
            "campaign_confidence": record.get("campaign", {}).get("campaign_confidence", None),
        }
        flat_records.append(flat)

    if flat_records:
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=flat_records[0].keys())
            writer.writeheader()
            writer.writerows(flat_records)

    logger.info(f"CSV report written to {output_path}")
    return output_path    

def _get_severity_summary(report_records):
    """
    Counts IOCs by severity level.
    Returns a dictionary with counts for each severity category.
    """
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for record in report_records:
        severity = record.get("severity", "low")
        if severity in summary:
            summary[severity] += 1
    return summary


