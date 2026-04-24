# cli.py
# Command line interface for the IOC Reputation Scoring System.
# Run: python cli.py --ioc <indicator> --type <ip|domain|hash|url>

import argparse
import logging
import sys
import json
from rich.console import Console
from rich.table import Table
from rich import box
from feeds.feed_aggregator import aggregate_ioc
from scoring.reputation_scorer import score_ioc
from ml.anomaly_detector import detect_anomalies
from ml.clusterer import cluster_iocs
from ml.campaign_classifier import classify_campaigns
from reporting.report_builder import build_report, write_json_report, write_csv_report
from config import LOG_LEVEL, LOG_FILE, SEVERITY_COLORS

console = Console()

def parse_args():
    """
    Defines and parses command line arguments.
    Returns the parsed argument object.
    """
    parser = argparse.ArgumentParser(
        description= "IOC Reputation Scoring System -- Query and score threat indicators.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    #Single IOC query
    parser.add_argument(
        "--ioc",
        type=str,
        help="Single IOC to query (e.g. 185.220.101.45)",
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["ip", "domain", "hash", "url"],
        help="Type of IOC: ip, domain, hash, or url",
    )

    #Batch query from file
    parser.add_argument(
        "--file",
        type=str,
        help="Path to a text file with one IOC per line (Format: ioc,type)",
    )

    #options for output
    parser.add_argument(
        "--output",
        type=str,
        choices=["json", "csv", "both", "none"],
        default="none",
        help="Report output format: json, csv, both, or none",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output including score components",
    )

    return parser.parse_args()

def run_pipeline(ioc_list):
    """
    Runs the full pipeline on a list of (ioc, ioc_type) tuples.
    Returns scored records and all ML results.
    """
    if not ioc_list:
        console.print("[red]No IOCs provided.[/red]")
        return None, None, None, None

    # Step 1 — Ingest and score
    console.print(f"\n[cyan]Querying {len(ioc_list)} IOC(s)...[/cyan]")
    scored_records = []
    for ioc, ioc_type in ioc_list:
        with console.status(f"[dim]Fetching {ioc_type}: {ioc}[/dim]"):
            record = aggregate_ioc(ioc, ioc_type)
        if record:
            scored = score_ioc(record)
            if scored:
                scored_records.append(scored)

    if not scored_records:
        console.print("[red]No data returned from any source.[/red]")
        return None, None, None, None

    console.print(f"[green]Successfully scored {len(scored_records)} IOC(s).[/green]")

    # Step 2 — ML
    from pathlib import Path
    # Step 2 — ML using pre-trained models
    from pathlib import Path
    console.print("\n[cyan]Running ML analysis...[/cyan]")
    anomaly_results  = detect_anomalies(scored_records,  model_path=Path("models/anomaly_detector.joblib"))
    cluster_results  = cluster_iocs(scored_records,      model_path=Path("models/clusterer.joblib"))
    campaign_results = classify_campaigns(scored_records, model_path=Path("models/campaign_classifier.joblib"))

    return scored_records, anomaly_results, cluster_results, campaign_results

def print_results(scored_records, anomaly_results, cluster_results, campaign_results, verbose=False):
    """
    Prints a formatted results table to the terminal using Rich.
    """
    table = Table(
        title="IOC Reputation Scores",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )

    # Define columns
    table.add_column("IOC",            style="white",  no_wrap=True)
    table.add_column("Type",           style="dim",    width=8)
    table.add_column("Score",          style="white",  width=8)
    table.add_column("Severity",       style="white",  width=10)
    table.add_column("Anomaly",        style="white",  width=9)
    table.add_column("Cluster",        style="white",  width=30)
    table.add_column("Campaign",       style="white",  width=10)
    table.add_column("Sources",        style="dim",    width=15)

    for record in scored_records:
        ioc        = record.get("ioc", "")
        ioc_type   = record.get("ioc_type", "")
        score      = record.get("reputation_score", 0)
        severity   = record.get("severity", "low")

        # Severity color
        color = SEVERITY_COLORS.get(severity, "#FFFFFF")
        severity_str = f"[{color}]{severity.upper()}[/{color}]"
        score_str    = f"[{color}]{score}[/{color}]"

        # ML fields
        anomaly  = anomaly_results.get(ioc, {})
        cluster  = cluster_results.get(ioc, {})
        campaign = campaign_results.get(ioc, {})

        is_anomaly    = "YES" if anomaly.get("is_anomaly") else "no"
        cluster_label = cluster.get("cluster_label", "N/A")
        is_campaign   = "YES" if campaign.get("is_campaign") else "no"
        sources       = ", ".join(record.get("sources", []))

        anomaly_str  = f"[red]YES[/red]" if anomaly.get("is_anomaly") else "no"
        campaign_str = f"[yellow]YES[/yellow]" if campaign.get("is_campaign") else "no"

        table.add_row(
            ioc,
            ioc_type,
            score_str,
            severity_str,
            anomaly_str,
            cluster_label,
            campaign_str,
            sources,
        )

        if verbose:
            components = record.get("score_components", {})
            console.print(
                f"  [dim]└ base={components.get('base_score')} "
                f"confidence={components.get('source_confidence')} "
                f"decay={components.get('recency_decay')}[/dim]"
            )

    console.print(table)

def main():
    """
    Main entry point for the CLI.
    Parses arguments, runs the pipeline, prints results, and writes reports.
    """
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        filename=str(LOG_FILE),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    args = parse_args()

    # Build IOC list from arguments
    ioc_list = []

    if args.ioc and args.type:
        ioc_list.append((args.ioc, args.type))

    elif args.file:
        try:
            with open(args.file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and "," in line:
                        parts = line.split(",")
                        ioc_list.append((parts[0].strip(), parts[1].strip()))
        except FileNotFoundError:
            console.print(f"[red]File not found: {args.file}[/red]")
            sys.exit(1)

    else:
        console.print("[red]Please provide --ioc and --type, or --file.[/red]")
        console.print("Run [cyan]python cli.py --help[/cyan] for usage.")
        sys.exit(1)

    # Run the full pipeline
    scored_records, anomaly_results, cluster_results, campaign_results = run_pipeline(ioc_list)

    if not scored_records:
        sys.exit(1)

    # Print results table
    print_results(
        scored_records,
        anomaly_results  or {},
        cluster_results  or {},
        campaign_results or {},
        verbose=args.verbose,
    )

    # Write reports if requested
    if args.output in ("json", "both"):
        report = build_report(scored_records, anomaly_results, cluster_results, campaign_results)
        path   = write_json_report(report)
        console.print(f"\n[green]JSON report saved to:[/green] {path}")

    if args.output in ("csv", "both"):
        report = build_report(scored_records, anomaly_results, cluster_results, campaign_results)
        path   = write_csv_report(report)
        console.print(f"[green]CSV report saved to:[/green] {path}")


if __name__ == "__main__":
    main()