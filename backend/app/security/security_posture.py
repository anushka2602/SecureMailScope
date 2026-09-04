from pathlib import Path

import joblib
import pandas as pd

from app.security.risk_engine import calculate_security_score


# -------------------------------------------------------------------
# MODEL PATHS
# -------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "models"

RISK_MODEL_PATH = MODEL_DIR / "risk_classifier.pkl"
RISK_PREPROCESSOR_PATH = MODEL_DIR / "risk_preprocessor.pkl"
RISK_LABEL_ENCODER_PATH = MODEL_DIR / "risk_label_encoder.pkl"

ANOMALY_MODEL_PATH = MODEL_DIR / "tls_anomaly_detector.pkl"
ANOMALY_PREPROCESSOR_PATH = MODEL_DIR / "anomaly_preprocessor.pkl"


# -------------------------------------------------------------------
# LOAD MODELS
# -------------------------------------------------------------------

risk_model = joblib.load(RISK_MODEL_PATH)
risk_preprocessor = joblib.load(RISK_PREPROCESSOR_PATH)
risk_label_encoder = joblib.load(RISK_LABEL_ENCODER_PATH)

anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
anomaly_preprocessor = joblib.load(ANOMALY_PREPROCESSOR_PATH)


# -------------------------------------------------------------------
# FEATURE PREPARATION
# -------------------------------------------------------------------

FEATURE_COLUMNS = [
    "protocol",
    "tls_version",
    "cipher",
    "key_size",
    "cert_expired",
    "cert_not_yet_valid",
    "signature_algorithm",
    "starttls",
    "forward_secrecy",
]


def prepare_features(data):
    """
    Convert one security-session dictionary into a DataFrame
    with the exact feature structure expected by the ML models.
    """

    row = {
        column: data.get(column)
        for column in FEATURE_COLUMNS
    }

    return pd.DataFrame([row])


# -------------------------------------------------------------------
# RISK CLASSIFIER
# -------------------------------------------------------------------

def predict_risk(data):
    """
    Predict the ML-based security risk category.
    """

    dataframe = prepare_features(data)

    transformed = risk_preprocessor.transform(dataframe)

    prediction = risk_model.predict(transformed)[0]

    probabilities = risk_model.predict_proba(transformed)[0]

    label = risk_label_encoder.inverse_transform([prediction])[0]

    probability_map = {
        risk_label_encoder.inverse_transform([index])[0]: float(probability)
        for index, probability in enumerate(probabilities)
    }

    confidence = float(max(probabilities))

    return {
        "label": str(label),
        "confidence": round(confidence, 4),
        "probabilities": {
            key: round(value, 4)
            for key, value in probability_map.items()
        },
    }


# -------------------------------------------------------------------
# ANOMALY DETECTION
# -------------------------------------------------------------------

def detect_anomaly(data):
    """
    Determine whether the observed TLS/security configuration
    is unusual compared with the training data.
    """

    dataframe = prepare_features(data)

    transformed = anomaly_preprocessor.transform(dataframe)

    prediction = anomaly_model.predict(transformed)[0]

    anomaly_score = anomaly_model.decision_function(transformed)[0]

    return {
        "is_anomaly": bool(prediction == -1),
        "anomaly_score": round(float(anomaly_score), 4),
    }


# -------------------------------------------------------------------
# UNIFIED SECURITY POSTURE
# -------------------------------------------------------------------

def analyze_security_posture(data):
    """
    Run all three security-analysis layers:

    1. Deterministic rule engine
    2. ML risk classifier
    3. ML anomaly detector
    """

    rule_result = calculate_security_score(data)

    ml_risk = predict_risk(data)

    anomaly = detect_anomaly(data)

    return {
        "protocol": data.get("protocol"),
        "risk": ml_risk,
        "anomaly": anomaly,
        "security": {
            "score": rule_result["security_score"],
            "severity": rule_result["severity"],
        },
        "findings": rule_result["findings"],
        "recommendations": rule_result["recommendations"],
    }