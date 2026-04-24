# IOC Reputation Scoring System

![Python](https://img.shields.io/badge/Python-3.13-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A multi-source IOC enrichment and triage pipeline that automates threat indicator 
analysis across AlienVault OTX, VirusTotal, and abuse.ch. Built for CTI analysts, 
SOC teams, and security researchers who need fast, confidence-weighted reputation 
scoring with ML-augmented behavioral profiling.

## What It Does

Query any IP, domain, file hash, or URL and get back a confidence-weighted 
reputation score in seconds — powered by three live threat intelligence sources 
and a three-model ML pipeline.

## Core Capabilities

**Threat Feed Aggregation**
Queries AlienVault OTX, VirusTotal, and abuse.ch simultaneously. Results are 
normalized into a unified schema and merged across sources — the more sources 
that flag an indicator, the higher the confidence.

**Confidence-Weighted Scoring**
Each IOC receives a score from 0–100 based on source reliability weights, 
IOC type multipliers, and recency decay. An IP flagged yesterday by three 
sources scores higher than one flagged six months ago by one.

**ML-Augmented Triage**
Three models run on every query:
- Isolation Forest — flags statistically anomalous indicators
- K-Means clustering — assigns a behavioral profile (Botnet C2, Phishing, APT Indicator, etc.)
- Random Forest — predicts campaign association with a confidence score

**Structured Reporting**
Every query can export a JSON or CSV intelligence report to `data/reports/`.

**Allowlist Protection**
Known legitimate infrastructure (Google, Cloudflare, Apple, GitHub) is never 
falsely flagged regardless of pulse count — addressing the brand abuse bias 
common in pulse-count-based scorers.

## Architecture

```
ioc-reputation-scorer/
│
├── feeds/                  # Threat feed clients
│   ├── otx_client.py       # AlienVault OTX API
│   ├── abusech_client.py   # MalwareBazaar, URLhaus, Feodo Tracker
│   ├── vt_client.py        # VirusTotal API
│   └── feed_aggregator.py  # Normalizes all sources into unified schema
│
├── scoring/                # Reputation scoring engine
│   ├── reputation_scorer.py
│   └── score_config.yaml   # Tunable weights (no code changes needed)
│
├── ml/                     # Machine learning pipeline
│   ├── feature_engineering.py
│   ├── anomaly_detector.py
│   ├── clusterer.py
│   ├── campaign_classifier.py
│   └── model_trainer.py
│
├── reporting/              # Structured report generation
│   └── report_builder.py
│
├── dashboard/              # Streamlit visual interface
│   └── app.py
│
├── models/                 # Pre-trained ML models
├── data/reports/           # Generated intelligence reports
├── cli.py                  # Command line interface
└── config.py               # Global settings and API keys
```

## Installation

**Prerequisites:** Python 3.10+

```bash
# Clone the repository
git clone https://github.com/Edi-San24/ioc-reputation-scorer.git
cd ioc-reputation-scorer

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

**API Keys Required**

Copy `.env.example` to `.env` and add your keys:

```bash
cp .env.example .env
```

**Pre-train the ML models** (required before first use):

```bash
python -m ml.model_trainer
```

This queries your training IOC list and saves three fitted models to `models/`.
Takes 15–20 minutes due to API rate limiting.

## Usage

**Single IOC query:**
```bash
python cli.py --ioc 185.220.101.45 --type ip
```

**Query with report output:**
```bash
python cli.py --ioc 185.220.101.45 --type ip --output json
```

**Verbose mode (shows score breakdown):**
```bash
python cli.py --ioc 185.220.101.45 --type ip --verbose
```

**Batch query from file:**
```bash
python cli.py --file iocs.txt --output csv
```

File format (`iocs.txt`):

**Launch the dashboard:**
```bash
streamlit run dashboard/app.py
```

**Supported IOC types:** `ip` `domain` `hash` `url`

## Scoring Methodology

Each IOC receives a reputation score from 0–100 calculated as:

| Component | Description |
|---|---|
| `base_score` | Weighted sum of pulse count, source count, tag diversity, and malware family associations |
| `source_confidence` | Weighted average of reliability scores for each source that returned data |
| `type_multiplier` | IOC-type adjustment — hashes (1.3×) weighted higher than IPs (1.0×) due to lower false-positive rate |
| `recency_decay` | Time-based penalty — IOCs last seen 180–365 days ago score at 50%, beyond 365 days at 25% |

**Severity Labels**

| Score | Severity |
|---|---|
| 85–100 | 🔴 Critical |
| 65–84 | 🟠 High |
| 40–64 | 🟡 Medium |
| 0–39 | 🟢 Low |

Source weights are tunable in `scoring/score_config.yaml` without modifying any Python code.

## ML Pipeline

Three models run on every query when pre-trained models are available.

**Isolation Forest — Anomaly Detection**
Flags IOCs that are statistically unusual relative to the training corpus.
An IP with an extreme pulse count and no country attribution will isolate
faster than normal data points — surfaced as `is_anomaly: true`.

**K-Means Clustering — Behavioral Profiling**
Groups IOCs into six behavioral profiles based on their feature vectors:

| Cluster | Profile |
|---|---|
| 0 | Botnet C2 Infrastructure |
| 1 | Phishing / Credential Harvesting |
| 2 | Commodity Malware Distribution |
| 3 | Scanner / Probe Activity |
| 4 | High Confidence APT Indicator |
| 5 | Low Signal / Unknown |

**Random Forest — Campaign Classification**
Predicts whether an IOC is associated with a known threat actor campaign
versus generic opportunistic activity. Returns a binary prediction and a
confidence score between 0 and 1.

Trained on 70 IOCs sourced from OTX pulses covering Emotet, RedLine Stealer,
Cobalt Strike, and known benign infrastructure. Cross-validation mean F1: 0.954
(+/- 0.063).

## Known Limitations

**Dataset size** — the campaign classifier is trained on 70 IOCs with synthetic
labels derived from enrichment signals. Production deployment would require
analyst-verified ground truth labels at scale. The architecture is designed
for that extension.

**Brand abuse bias** — major legitimate domains (Apple, Google, Microsoft) appear
frequently in threat feeds because attackers impersonate them. An allowlist
addresses this for known infrastructure but novel legitimate domains may still
score higher than expected.

**API dependency** — scoring quality depends on API availability at query time.
OTX rate limiting and occasional timeouts are handled gracefully with retry
logic, but scores will vary if sources are unavailable.

**Synthetic labels** — `_generate_labels()` uses pulse count and source count
as proxies for campaign association. This introduces circularity since these
signals are also features in the model. A production system would replace
synthetic labels with analyst-verified annotations.

## Data Sources

| Source | Coverage | Auth Required |
|---|---|---|
| AlienVault OTX | IPs, domains, hashes, URLs | Yes (free) |
| VirusTotal | IPs, domains, hashes, URLs | Yes (free) |
| MalwareBazaar | File hashes | Yes (free) |
| URLhaus | URLs, domains | Yes (free) |
| Feodo Tracker | IPs (botnet C2) | No |

## Credits

- [AlienVault OTX](https://otx.alienvault.com)
- [VirusTotal](https://virustotal.com)
- [abuse.ch](https://abuse.ch)

## License

MIT License — free to use, modify, and distribute with attribution.

