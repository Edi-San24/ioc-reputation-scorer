# IOC Reputation Scoring System

![Python](https://img.shields.io/badge/Python-3.13-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A multi-source IOC enrichment and triage pipeline that automates threat indicator analysis across AlienVault OTX, VirusTotal, and abuse.ch. Built for CTI analysts, SOC teams, and security researchers who need fast, confidence-weighted reputation scoring with ML-augmented behavioral profiling.

**Live Demo:** https://ioc-reputation-scorer.streamlit.app/

---

## What It Does

Query any IP, domain, file hash, or URL and get back a confidence-weighted reputation score in seconds — powered by four live threat intelligence sources and a three-model ML pipeline.

- Multi-source feed aggregation — OTX, VirusTotal, MalwareBazaar, URLhaus, Feodo Tracker
- WHOIS enrichment — newly registered and privacy-protected domains carry additional scoring weight
- ML triage — anomaly detection, behavioral clustering, and campaign classification
- STIX 2.1 export — valid Bundles ready for MISP, OpenCTI, Splunk, or any SIEM
- Allowlist protection — known legitimate infrastructure is never falsely flagged
- CLI and Streamlit dashboard included

---

## Installation

```bash
git clone https://github.com/Edi-San24/ioc-reputation-scorer.git
cd ioc-reputation-scorer
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Add your API keys
python -m ml.model_trainer  # Pre-train ML models (~15 min)
```

**API keys needed** (all free):
```
OTX_API_KEY        # otx.alienvault.com
VT_API_KEY         # virustotal.com
ABUSECH_API_KEY    # auth.abuse.ch
WHOIS_API_KEY      # whoisxmlapi.com
```

---

## Usage

```bash
# Single IOC
python cli.py --ioc 185.220.101.45 --type ip

# With report output (JSON + STIX)
python cli.py --ioc 185.220.101.45 --type ip --output json

# Batch from file
python cli.py --file iocs.txt --output csv

# Dashboard
streamlit run dashboard/app.py
```

---

## Scoring Formula

```
Score = base_score × source_confidence × type_multiplier × recency_decay × whois_multiplier
```

| Component | Description |
|---|---|
| `base_score` | Pulse count, source count, tag diversity, malware families |
| `source_confidence` | Weighted average of source reliability scores |
| `type_multiplier` | Hashes (1.3×) weighted higher than IPs (1.0×) |
| `recency_decay` | Stale IOCs penalized — 365+ days scores at 25% |
| `whois_multiplier` | New domains (1.3×), privacy-protected registrations (1.1×) |

| Score | Severity |
|---|---|
| 85–100 | 🔴 Critical |
| 65–84 | 🟠 High |
| 40–64 | 🟡 Medium |
| 0–39 | 🟢 Low |

---

## ML Pipeline

Three models run on every query using pre-trained models saved to `models/`.

- **Isolation Forest** — flags statistically anomalous IOCs
- **K-Means** — assigns behavioral profiles (Botnet C2, Phishing, APT Indicator, etc.)
- **Random Forest** — predicts campaign association with confidence score

Trained on 70 IOCs from OTX pulses covering Emotet, RedLine Stealer, and Cobalt Strike. Cross-validation mean F1: 0.954 (+/- 0.063).

---

## Known Limitations

- Classifier trained on 70 IOCs with synthetic labels — analyst-verified ground truth would improve performance at scale
- Brand abuse bias addressed via allowlist but novel legitimate domains may still score elevated
- Scores vary with API availability — retry logic handles timeouts gracefully

---

## Data Sources

| Source | Coverage | Auth |
|---|---|---|
| AlienVault OTX | IPs, domains, hashes, URLs | Free |
| VirusTotal | IPs, domains, hashes, URLs | Free |
| MalwareBazaar | File hashes | Free |
| URLhaus | URLs, domains | Free |
| Feodo Tracker | IPs (botnet C2) | None |
| WhoisXML API | Domain registration data | Free |

---

## License

MIT — free to use, modify, and distribute with attribution.
