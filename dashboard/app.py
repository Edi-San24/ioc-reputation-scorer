# dashboard/app.py
# Streamlit dashboard for the IOC Reputation Scoring System.
# Run: streamlit run dashboard/app.py

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import json
from pathlib import Path
import sys

# Add project root to path so imports work
sys.path.append(str(Path(__file__).parent.parent))

from feeds.feed_aggregator import aggregate_ioc
from scoring.reputation_scorer import score_ioc
from ml.anomaly_detector import detect_anomalies
from ml.clusterer import cluster_iocs
from ml.campaign_classifier import classify_campaigns
from reporting.report_builder import build_report, write_json_report, write_csv_report
from config import SEVERITY_COLORS

# ── Page Configuration ─────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IOC Reputation Scorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp {
        background-color: #0d0d1a;
        color: #e0e0e0;
    }
    [data-testid="stSidebar"] {
        background-color: #12122a;
        border-right: 1px solid #00d4ff33;
    }
    .metric-card {
        background-color: #12122a;
        border: 1px solid #00d4ff33;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .score-display {
        font-size: 64px;
        font-weight: 700;
        text-align: center;
        margin: 10px 0;
    }
    .severity-badge {
        font-size: 18px;
        font-weight: 600;
        padding: 6px 16px;
        border-radius: 20px;
        text-align: center;
        display: inline-block;
    }
    .section-header {
        font-size: 14px;
        font-weight: 600;
        color: #00d4ff;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
    }
    .stTextInput input {
        background-color: #12122a;
        border: 1px solid #00d4ff33;
        color: #e0e0e0;
        border-radius: 8px;
    }
    .stButton button {
        background-color: #00d4ff;
        color: #0d0d1a;
        border: none;
        border-radius: 8px;
        font-weight: 700;
        width: 100%;
    }
    .stButton button:hover {
        background-color: #00b8d9;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ── Load Pre-trained Models ────────────────────────────────────────────────────
MODELS_DIR = Path(__file__).parent.parent / "models"

ANOMALY_MODEL_PATH  = MODELS_DIR / "anomaly_detector.joblib"
CLUSTER_MODEL_PATH  = MODELS_DIR / "clusterer.joblib"
CAMPAIGN_MODEL_PATH = MODELS_DIR / "campaign_classifier.joblib"

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ IOC Reputation Scorer")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["IOC Lookup", "Batch Analysis", "Visualizations", "Methodology"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("### Data Sources")
    st.markdown("✅ AlienVault OTX")
    st.markdown("✅ VirusTotal")
    st.markdown("✅ MalwareBazaar")
    st.markdown("✅ URLhaus")
    st.markdown("✅ Feodo Tracker")

    st.markdown("---")
    st.markdown("### ML Models")

    anomaly_ready  = ANOMALY_MODEL_PATH.exists()
    cluster_ready  = CLUSTER_MODEL_PATH.exists()
    campaign_ready = CAMPAIGN_MODEL_PATH.exists()

    st.markdown(f"{'✅' if anomaly_ready  else '❌'} Anomaly Detector")
    st.markdown(f"{'✅' if cluster_ready  else '❌'} Clusterer")
    st.markdown(f"{'✅' if campaign_ready else '❌'} Campaign Classifier")

    if not all([anomaly_ready, cluster_ready, campaign_ready]):
        st.warning("Run `python -m ml.model_trainer` to train models.")

# ── Helper Functions ───────────────────────────────────────────────────────────
def get_severity_color(severity):
    return SEVERITY_COLORS.get(severity, "#FFFFFF")

def severity_badge(severity, score):
    color = get_severity_color(severity)
    return f"""
    <div style="text-align: center;">
        <div class="score-display" style="color: {color};">{score}</div>
        <span class="severity-badge" style="background-color: {color}22;
              color: {color}; border: 1px solid {color};">
            {severity.upper()}
        </span>
    </div>
    """

@st.cache_data(show_spinner=False, ttl=300)
def run_pipeline(ioc, ioc_type):
    """
    Runs the full pipeline for a single IOC.
    Cached so re-renders don't re-query the APIs.
    """
    record = aggregate_ioc(ioc, ioc_type)
    if not record:
        return None, None, None, None

    scored = score_ioc(record)
    if not scored:
        return None, None, None, None

    records = [scored]

    anomaly_results  = detect_anomalies(records,  model_path=ANOMALY_MODEL_PATH)
    cluster_results  = cluster_iocs(records,      model_path=CLUSTER_MODEL_PATH)
    campaign_results = classify_campaigns(records, model_path=CAMPAIGN_MODEL_PATH)

    return scored, anomaly_results, cluster_results, campaign_results

# ── Page: IOC Lookup ───────────────────────────────────────────────────────────
if page == "IOC Lookup":
    st.markdown("## IOC Lookup")
    st.markdown("Query a single indicator across all threat intelligence sources.")
    st.markdown("---")

    col1, col2 = st.columns([3, 1])
    with col1:
        ioc_input = st.text_input(
            "Enter IOC",
            placeholder="IP, domain, hash, or URL...",
            label_visibility="collapsed",
        )
    with col2:
        ioc_type = st.selectbox(
            "Type",
            ["ip", "domain", "hash", "url"],
            label_visibility="collapsed",
        )

    query_btn = st.button("🔍 Analyze", use_container_width=True)

    if query_btn and ioc_input:
        with st.spinner("Querying threat intelligence sources..."):
            scored, anomaly_results, cluster_results, campaign_results = run_pipeline(
                ioc_input.strip(), ioc_type
            )

        if not scored:
            st.error("No data returned for this IOC. Check your API keys or try a different indicator.")
        else:
            score    = scored.get("reputation_score", 0)
            severity = scored.get("severity", "low")
            sources  = scored.get("sources", [])

            st.markdown("---")

            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown('<p class="section-header">Reputation Score</p>', unsafe_allow_html=True)
                st.markdown(severity_badge(severity, score), unsafe_allow_html=True)
            with c2:
                st.markdown('<p class="section-header">Sources</p>', unsafe_allow_html=True)
                for source in sources:
                    st.markdown(f"✅ `{source}`")
            with c3:
                st.markdown('<p class="section-header">IOC Details</p>', unsafe_allow_html=True)
                st.markdown(f"**Type:** `{scored.get('ioc_type')}`")
                st.markdown(f"**Country:** `{scored.get('country', 'N/A')}`")
                st.markdown(f"**ASN:** `{scored.get('asn', 'N/A')}`")
                st.markdown(f"**First Seen:** `{scored.get('first_seen', 'N/A')}`")
                st.markdown(f"**Last Seen:** `{scored.get('last_seen', 'N/A')}`")

            st.markdown("---")

            c4, c5, c6 = st.columns(3)
            anomaly  = anomaly_results.get(ioc_input.strip(), {})
            cluster  = cluster_results.get(ioc_input.strip(), {})
            campaign = campaign_results.get(ioc_input.strip(), {})

            with c4:
                st.markdown('<p class="section-header">Anomaly Detection</p>', unsafe_allow_html=True)
                is_anomaly = anomaly.get("is_anomaly", False)
                st.markdown(f"**Status:** {'🔴 Anomalous' if is_anomaly else '🟢 Normal'}")
                st.markdown(f"**Score:** `{round(float(anomaly.get('anomaly_score', 0)), 4)}`")
            with c5:
                st.markdown('<p class="section-header">Behavioral Cluster</p>', unsafe_allow_html=True)
                st.markdown(f"**Profile:** `{cluster.get('cluster_label', 'N/A')}`")
                st.markdown(f"**Cluster ID:** `{cluster.get('cluster_id', 'N/A')}`")
            with c6:
                st.markdown('<p class="section-header">Campaign Association</p>', unsafe_allow_html=True)
                is_campaign = campaign.get("is_campaign", False)
                confidence  = campaign.get("campaign_confidence", 0)
                st.markdown(f"**Status:** {'🔴 Campaign' if is_campaign else '🟢 Generic'}")
                st.markdown(f"**Confidence:** `{confidence}`")

            st.markdown("---")

            st.markdown('<p class="section-header">Score Breakdown</p>', unsafe_allow_html=True)
            components = scored.get("score_components", {})
            bc1, bc2, bc3, bc4 = st.columns(4)
            bc1.metric("Base Score",        components.get("base_score", "N/A"))
            bc2.metric("Source Confidence", components.get("source_confidence", "N/A"))
            bc3.metric("Type Multiplier",   components.get("type_multiplier", "N/A"))
            bc4.metric("Recency Decay",     components.get("recency_decay", "N/A"))

            st.markdown("---")

            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown('<p class="section-header">Tags</p>', unsafe_allow_html=True)
                tags = scored.get("tags", [])
                if tags:
                    st.write(", ".join(tags[:15]))
                else:
                    st.write("None")
            with col_b:
                st.markdown('<p class="section-header">Malware Families</p>', unsafe_allow_html=True)
                families = [
                    f for f in scored.get("malware_families", [])
                    if not f.startswith("http")
                ]
                if families:
                    st.code(", ".join(families[:10]))
                else:
                    st.write("None")

            st.markdown("---")

            st.markdown('<p class="section-header">Export Report</p>', unsafe_allow_html=True)
            ex1, ex2 = st.columns(2)
            with ex1:
                if st.button("📄 Export JSON"):
                    report = build_report([scored], anomaly_results, cluster_results, campaign_results)
                    path   = write_json_report(report)
                    st.success(f"Saved to {path}")
            with ex2:
                if st.button("📊 Export CSV"):
                    report = build_report([scored], anomaly_results, cluster_results, campaign_results)
                    path   = write_csv_report(report)
                    st.success(f"Saved to {path}")

# ── Page: Batch Analysis ───────────────────────────────────────────────────────
elif page == "Batch Analysis":
    st.markdown("## Batch Analysis")
    st.markdown("Upload a file with multiple IOCs and analyze them all at once.")
    st.markdown("---")

    st.markdown("""
    **File format** — one IOC per line, comma separated:
    ```
    185.220.101.45,ip
    malware.com,domain
    d55f983c994caa...,hash
    ```
    """)

    uploaded_file = st.file_uploader("Upload IOC list", type=["txt", "csv"])

    if uploaded_file:
        lines    = uploaded_file.read().decode("utf-8").strip().split("\n")
        ioc_list = []
        for line in lines:
            line = line.strip()
            if "," in line:
                parts = line.split(",")
                ioc_list.append((parts[0].strip(), parts[1].strip()))

        st.info(f"Found {len(ioc_list)} IOCs. Click Analyze to begin.")

        if st.button("🔍 Analyze Batch", use_container_width=True):
            scored_records = []
            progress = st.progress(0)
            status   = st.empty()

            for i, (ioc, ioc_type) in enumerate(ioc_list):
                status.text(f"Processing {ioc_type}: {ioc}")
                record = aggregate_ioc(ioc, ioc_type)
                if record:
                    scored = score_ioc(record)
                    if scored:
                        scored_records.append(scored)
                progress.progress((i + 1) / len(ioc_list))

            status.text(f"Running ML analysis on {len(scored_records)} IOCs...")
            anomaly_results  = detect_anomalies(scored_records,  model_path=ANOMALY_MODEL_PATH)
            cluster_results  = cluster_iocs(scored_records,      model_path=CLUSTER_MODEL_PATH)
            campaign_results = classify_campaigns(scored_records, model_path=CAMPAIGN_MODEL_PATH)

            rows = []
            for record in scored_records:
                ioc = record.get("ioc")
                rows.append({
                    "IOC":        ioc,
                    "Type":       record.get("ioc_type"),
                    "Score":      record.get("reputation_score"),
                    "Severity":   record.get("severity", "").upper(),
                    "Anomaly":    anomaly_results.get(ioc, {}).get("is_anomaly", False),
                    "Cluster":    cluster_results.get(ioc, {}).get("cluster_label", "N/A"),
                    "Campaign":   campaign_results.get(ioc, {}).get("is_campaign", False),
                    "Confidence": campaign_results.get(ioc, {}).get("campaign_confidence", 0),
                    "Sources":    ", ".join(record.get("sources", [])),
                })

            df = pd.DataFrame(rows).sort_values("Score", ascending=False)
            st.session_state["batch_df"]       = df
            st.session_state["batch_scored"]   = scored_records
            st.session_state["batch_anomaly"]  = anomaly_results
            st.session_state["batch_cluster"]  = cluster_results
            st.session_state["batch_campaign"] = campaign_results

    if "batch_df" in st.session_state:
        df = st.session_state["batch_df"]
        st.markdown("---")
        st.markdown(f'<p class="section-header">Results — {len(df)} IOCs</p>', unsafe_allow_html=True)
        st.dataframe(df, use_container_width=True)

        ex1, ex2 = st.columns(2)
        with ex1:
            if st.button("📄 Export JSON"):
                report = build_report(
                    st.session_state["batch_scored"],
                    st.session_state["batch_anomaly"],
                    st.session_state["batch_cluster"],
                    st.session_state["batch_campaign"],
                )
                path = write_json_report(report)
                st.success(f"Saved to {path}")
        with ex2:
            if st.button("📊 Export CSV"):
                report = build_report(
                    st.session_state["batch_scored"],
                    st.session_state["batch_anomaly"],
                    st.session_state["batch_cluster"],
                    st.session_state["batch_campaign"],
                )
                path = write_csv_report(report)
                st.success(f"Saved to {path}")

# ── Page: Visualizations ───────────────────────────────────────────────────────
elif page == "Visualizations":
    st.markdown("## Visualizations")
    st.markdown("Visual analysis of batch results. Run a batch query first to populate these charts.")
    st.markdown("---")

    if "batch_df" not in st.session_state:
        st.info("No batch data available. Go to Batch Analysis and run a query first.")
    else:
        df = st.session_state["batch_df"]

        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<p class="section-header">Severity Distribution</p>', unsafe_allow_html=True)
            severity_counts = df["Severity"].value_counts().reset_index()
            severity_counts.columns = ["Severity", "Count"]
            color_map = {
                "CRITICAL": "#FF2D2D",
                "HIGH":     "#FF8C00",
                "MEDIUM":   "#FFD700",
                "LOW":      "#00C851",
            }
            fig = px.bar(
                severity_counts,
                x="Severity", y="Count",
                color="Severity",
                color_discrete_map=color_map,
                template="plotly_dark",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            st.markdown('<p class="section-header">IOC Type Breakdown</p>', unsafe_allow_html=True)
            type_counts = df["Type"].value_counts().reset_index()
            type_counts.columns = ["Type", "Count"]
            fig2 = px.pie(
                type_counts,
                names="Type", values="Count",
                color_discrete_sequence=["#00d4ff", "#7c83fd", "#ff6b9d", "#ffd93d"],
                template="plotly_dark",
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig2, use_container_width=True)

        c3, c4 = st.columns(2)
        with c3:
            st.markdown('<p class="section-header">Score Distribution</p>', unsafe_allow_html=True)
            fig3 = px.histogram(
                df, x="Score", nbins=20,
                color_discrete_sequence=["#00d4ff"],
                template="plotly_dark",
            )
            fig3.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig3, use_container_width=True)

        with c4:
            st.markdown('<p class="section-header">Cluster Distribution</p>', unsafe_allow_html=True)
            cluster_counts = df["Cluster"].value_counts().reset_index()
            cluster_counts.columns = ["Cluster", "Count"]
            fig4 = px.bar(
                cluster_counts,
                x="Count", y="Cluster",
                orientation="h",
                color_discrete_sequence=["#7c83fd"],
                template="plotly_dark",
            )
            fig4.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig4, use_container_width=True)

        st.markdown("---")
        st.markdown('<p class="section-header">Threat Summary</p>', unsafe_allow_html=True)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total IOCs",      len(df))
        m2.metric("Anomalous",       int(df["Anomaly"].sum()))
        m3.metric("Campaign-linked", int(df["Campaign"].sum()))
        m4.metric("Critical/High",   int((df["Severity"].isin(["CRITICAL", "HIGH"])).sum()))

# ── Page: Methodology ──────────────────────────────────────────────────────────
elif page == "Methodology":
    st.markdown("## Methodology")
    st.markdown("---")

    st.markdown("""
    ### Scoring Formula

    Each IOC receives a reputation score from 0–100 calculated as:

    ```
    Score = base_score × source_confidence × type_multiplier × recency_decay
    ```

    | Component | Description |
    |---|---|
    | Base Score | Weighted sum of pulse count, source count, tag diversity, and malware family associations |
    | Source Confidence | Weighted average of reliability scores for each source that returned data |
    | Type Multiplier | Hashes (1.3×) weighted higher than IPs (1.0×) due to lower false-positive rate |
    | Recency Decay | IOCs last seen 30–180 days score at 75%, 180–365 days at 50%, 365+ days at 25% |
    """)

    st.markdown("---")

    st.markdown("""
    ### Source Weights

    | Source | Weight | Rationale |
    |---|---|---|
    | Feodo Tracker | 0.95 | Narrow scope, very low false-positive rate |
    | MalwareBazaar | 0.90 | Curated malware repository |
    | AlienVault OTX | 0.85 | Community-vetted, high pulse volume |
    | URLhaus | 0.80 | Active campaign tracking, broader scope |
    """)

    st.markdown("---")

    st.markdown("""
    ### ML Pipeline

    **Isolation Forest** — unsupervised anomaly detection. Flags IOCs that are
    statistically unusual relative to the training corpus. Contamination parameter
    set to 0.05 (expects ~5% anomalous IOCs).

    **K-Means Clustering** — behavioral profiling with 6 clusters. Groups IOCs by
    shared feature patterns including pulse count, source count, tag diversity,
    malware family associations, and temporal features.

    **Random Forest Classifier** — predicts campaign association using synthetic
    labels derived from enrichment signals. Trained on 70 IOCs sourced from OTX
    pulses covering Emotet, RedLine Stealer, and Cobalt Strike infrastructure.
    Cross-validation mean F1: 0.954 (+/- 0.063).
    """)

    st.markdown("---")

    st.markdown("""
    ### Known Limitations

    - **Dataset size** — classifier trained on 70 IOCs with synthetic labels.
      Production deployment requires analyst-verified ground truth at scale.

    - **Brand abuse bias** — major legitimate domains appear frequently in threat
      feeds because attackers impersonate them. Allowlist protection covers known
      infrastructure but novel legitimate domains may still score higher than expected.

    - **API dependency** — scoring quality depends on API availability at query time.
      OTX rate limiting and occasional timeouts are handled with retry logic but
      scores will vary if sources are unavailable.

    - **Synthetic labels** — campaign labels are derived from pulse count and source
      count signals, introducing circularity since these are also model features.
      A production system would replace synthetic labels with analyst annotations.
    """)

    st.markdown("---")

    st.markdown("""
    ### Data Sources

    | Source | Coverage | Auth |
    |---|---|---|
    | AlienVault OTX | IPs, domains, hashes, URLs | Free API key |
    | VirusTotal | IPs, domains, hashes, URLs | Free API key |
    | MalwareBazaar | File hashes | Free API key |
    | URLhaus | URLs, domains | Free API key |
    | Feodo Tracker | IPs (botnet C2) | None required |
    """)

   