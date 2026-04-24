# ml/clusterer.py
# K-Means clustering will be utilized for behavioral profiling of IOCs. 
# Groups IOCs into clusters based on their feature vectors.

import joblib
from pathlib import Path
import logging
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from ml.feature_engineering import build_feature_matrix
from config import (
    KMEANS_N_CLUSTERS,
    KMEANS_RANDOM_STATE,
)

logger = logging.getLogger(__name__)


class IOCClusterer:
    """
    K-Means clustering model for behavioral profiling of IOCs.
    Groups IOCs into clusters based on shared feature patterns. 
    """

    # Readable labels for each cluster
    # These get updated after you see real data
    CLUSTER_LABELS = {
        0: "Botnet C2 Infrastructure",
        1: "Phishing / Credential Harvesting",
        2: "Commodity Malware Distribution",
        3: "Scanner / Probe Activity",
        4: "High Confidence APT Indicator:",
        5: "Low signal / Unknown",
    }

    def __init__(self):
        self.model = KMeans(
            n_clusters = KMEANS_N_CLUSTERS,
            random_state = KMEANS_RANDOM_STATE,
            n_init = 10,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def fit(self, ioc_records):
        """
        Trains K-Means on a list of IOC records.
        Needs at least as many records as clusters. 
        """

        if len(ioc_records) < KMEANS_N_CLUSTERS:
            logger.warning(f"Need at least {KMEANS_N_CLUSTERS} IOC records to fit clusterer.")
            return False
        
        df, _ = build_feature_matrix(ioc_records)
        if df is None:
            return False
        
        X = self.scaler.fit_transform(df.values)
        self.model.fit(X)
        self.is_fitted = True
        logger.info(f"Clusterer fitted on {len(ioc_records)} IOCs into {KMEANS_N_CLUSTERS} clusters.")
        return True
    
    def predict(self, ioc_records):
        """
        Assigns a cluster labels to a list of IOC records.
        Returns a dictionary mapping each IOC to its cluster.
        """

        if not self.is_fitted:
            logger.warning("Clusterer not fitted yet. Call fit() first.")
            return {}
        
        df, ioc_ids = build_feature_matrix(ioc_records)
        if df is None:
            return {}
        
        X = self.scaler.transform(df.values)
        cluster_ids = self.model.predict(X)

        results = {}
        for i, ioc in enumerate(ioc_ids):
            cluster_id = int(cluster_ids[i])
            results[ioc] = {
                "cluster_id": cluster_id,
                "cluster_label": self.CLUSTER_LABELS.get(cluster_id, "Unknown"),
            }
        return results
    
    def save(self, path):
        """
        Saves the fitted model and scaler to disk using joblib.
        """
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "is_fitted": self.is_fitted,
        }, path)
        logger.info(f"Clusterer model saved to {path}")

    
    def load(self, path):
        """
        Loads a fitted model and scaler from disk.
        """
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_fitted = data["is_fitted"]
        logger.info(f"Clusterer model loaded from {path}")
        return self
    
        
def cluster_iocs(ioc_records, model_path=None):
    """
    Convenience function that fits & predicts in one step.
    Returns a dictionary mapping each IOC to its cluster assignment.
    """
    if not ioc_records:
        logger.warning("No IOC records provided for clustering!")
        return {}
    
    clusterer = IOCClusterer()
    
    if model_path and Path(model_path).exists():
        clusterer.load(model_path)
    else:
        fitted = clusterer.fit(ioc_records)
        if not fitted:
            logger.warning("Clusterer failed to fit!")
            return {}
        
    results = clusterer.predict(ioc_records)
    logger.info(f"Clustering complete: {len(results)} IOCs assigned to clusters.")
    return results

