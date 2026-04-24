#ml/anomaly_detector.py
#Here we will implement an Isolation Forest model for detecting anomalous IOCs. 
#Anomalous IOCs get a score boost in the final reputation score. 

import joblib
from pathlib import Path
import logging 
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from ml.feature_engineering import build_feature_matrix
from config import (
    ISOLATION_FOREST_CONTAMINATION,
    ISOLATION_FOREST_RANDOM_STATE,
)

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Isolation Forest model for detecting anomalous IOCs. 
    Flags IOCs that are statistically unusual compared to the corpus. 
    """
    
    def __init__(self):
        self.model = IsolationForest(
            contamination = ISOLATION_FOREST_CONTAMINATION,
            random_state = ISOLATION_FOREST_RANDOM_STATE,
            n_estimators = 100,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, ioc_records):
        """
        Trains the Isolation Forest on a list of IOC records.
        Needs *at least* 10 records to be meaningful.
        """
        if len(ioc_records) < 10:
            logger.warning("Not enough data to fit Isolation Forest. Need at least 10 records.")
            return False
        
        df, _ = build_feature_matrix(ioc_records)
        if df is None:
            return False
        
        X = self.scaler.fit_transform(df.values)
        self.model.fit(X)
        self.is_fitted = True
        logger.info(f"Anomaly detector fitted on {len(ioc_records)} IOCs.")
        return True
    
    def predict(self, ioc_records):
        """
        Predicts anomaly scores for a list of IOC records.
        Returns a dictionary mapping each IOC to its anomaly flag and score.
        """

        if not self.is_fitted:
            logger.warning("Anomaly detector not fitted yet. Call fit() first.")
            return {}
        
        df, ioc_records = build_feature_matrix(ioc_records)
        if df is None:
            return {}
        
        X = self.scaler.transform(df.values)

        #Isolation Forest returns -1 for anomalies, 1 for normal. 
        predictions = self.model.predict(X)
        scores = self.model.score_samples(X) #Higher scores = more normal, lower scores = more anomalous

        results = {}
        for i, ioc in enumerate(ioc_records):
            results[ioc] = {
                "is_anomaly": bool(predictions[i]== -1),
                "anomaly_score": scores[i],
            }

        return results

    def save(self, path):
        """
        Saves the fitted model and scaler to disk.
        """
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "is_fitted": self.is_fitted
        }, path)
        logger.info(f"Anomaly detector model saved to {path}")
        
    def load(self, path):
        """
        Loads a fitted model and scaler from disk.
        """
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_fitted = data["is_fitted"]
        logger.info(f"Anomaly detector model loaded from {path}")
        return self
        
def detect_anomalies(ioc_records, model_path=None):
    """
    Convenience method that fits & predicts in one step.
    Use this when you have a batch of IOCs and want anomaly scores immediately.
    Returns a dictionary mapping each IOC to its anomaly results. 
    """
    if not ioc_records:
        logger.warning("No IOC records provided for anomaly detection!")
        return {}
        
    detector = AnomalyDetector()

    if model_path and Path(model_path).exists():
        detector.load(model_path)
    else:
        fitted = detector.fit(ioc_records)
        if not fitted:
            logger.warning("Anomaly detector failed to fit!")
            return {}
        
    results = detector.predict(ioc_records)
    anomaly_count = sum(1 for r in results.values() if r["is_anomaly"])
    logger.info(f"Anomaly detection complete: {anomaly_count} / {len(results)} IOCs flagged as anomalous.")
    return results