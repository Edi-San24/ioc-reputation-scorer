# ml/campaign_classifier.py
# Utilizing Random Forest classifier for campaign association prediction.
# Predicts whether an IOC is linked to a known threat actor campaign. 

import joblib
from pathlib import Path
import logging 
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report
from ml.feature_engineering import build_feature_matrix
from config import (
    RF_N_ESTIMATORS,
    RF_MAX_DEPTH,
    RF_RANDOM_STATE,
    RF_TEST_SIZE,
)

logger = logging.getLogger(__name__)

def _generate_labels(ioc_records):
    """
    Generates synthetic campaign association labels from enrichment data.
    Returns a list of binary labels: 1 = campaign-associated, 0 = Generic.
    """

    labels = []
    for record in ioc_records:
        has_threat_actors = len(record.get("threat_actors", [])) > 0
        has_malware_families = len(record.get("malware_families", [])) > 0
        high_pulse_count = record.get("pulse_count", 0) >= 10
        multi_source = record.get("source_count", 0) >= 2

        # Label as campaign-associated if multiple signals agree
        is_campaign = int(
            has_threat_actors or
            (has_malware_families and high_pulse_count) or
            (multi_source and high_pulse_count)
        )
        labels.append(is_campaign)
    return labels

class CampaignClassifier:
    """
    Random Forest classifier for campaign association prediction.
    This will be trained on synthetic labels derived from IOC enrichment data.
    """

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators = RF_N_ESTIMATORS,
            max_depth = RF_MAX_DEPTH,
            random_state = RF_RANDOM_STATE,
            class_weight= "balanced",
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, ioc_records):
        """
        Trains the Random Forest on a list of IOC records.
        Needs *at least* 15 records for a meaningful train/test split.
        """

        if len(ioc_records) < 15:
            logger.warning("Not enough data! Needs at least 15 IOC records to train classifier")
            return False
        
        df, _ = build_feature_matrix(ioc_records)
        if df is None:
            return False
        
        labels = _generate_labels(ioc_records)
        X = self.scaler.fit_transform(df.values)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size = RF_TEST_SIZE,
            random_state = RF_RANDOM_STATE,
        )
        self.model.fit(X_train, y_train)
        self.is_fitted = True

        #Cross-validation on full dataset for honest performance estimate
        cv_scores = cross_val_score(self.model, X, y, cv=5, scoring="f1_weighted")
        logger.info(f"Cross-validation F1 scores: {cv_scores.round(3)}")
        logger.info(f"Mean CV F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")


        #Evaluate on test set 
        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred, target_names=["Generic", "Campaign"], zero_division=0, labels=[0, 1])
        logger.info(f"Campaign classifier trained. \n {report}")
        return True
    
    def predict(self, ioc_records):
        """
        Predicts a campaign association for a list of IOC records.
        Returns a dictionary mapping each IOC to its prediction assignment
        """

        if not self.is_fitted:
            logger.warning("Campaign classifier not fitted yet. Call fit() first.")
            return {}
        
        df, ioc_ids = build_feature_matrix(ioc_records)
        if df is None:
            return {}
        
        X = self.scaler.transform(df.values)
        predictions = self.model.predict(X)
        probas = self.model.predict_proba(X)

        results = {}
        for i, ioc in enumerate(ioc_ids):
            results[ioc] = {
                "is_campaign": bool(predictions[i] == 1),
                "campaign_confidence": round(float(probas[i][1]), 4), #Probability of being campaign-associated
            }
        return results
    
    def save(self, path):
        """
        Saves the trained model and scaler to disk using joblib.
        """
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "is_fitted": self.is_fitted,
        }, path)
        logger.info(f"Campaign classifier model saved to {path}")

    
    def load(self, path):
        """
        Loads a trained model and scaler from disk.
        """
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_fitted = data["is_fitted"]
        logger.info(f"Campaign classifier model loaded from {path}")
        return self


def classify_campaigns(ioc_records, model_path=None):
    """
    Convenience function that fits & predicts in one step.
    Returns a dictionary mapping each IOC to its campaign prediction.
    """

    if not ioc_records:
        logger.warning("No IOC records provided for campaign classification!")
        return {}
    
    classifier = CampaignClassifier()
    
    if model_path and Path(model_path).exists():
        classifier.load(model_path)
    else:
        fitted = classifier.fit(ioc_records)
        if not fitted:
            logger.warning("Campaign classifier failed to fit!")
            return {}
        
    results = classifier.predict(ioc_records)
    campaign_count = sum(1 for r in results.values() if r["is_campaign"])
    logger.info(f"Classification complete: {campaign_count}/{len(results)} IOCs flagged as campaign-associated.")
    return results


