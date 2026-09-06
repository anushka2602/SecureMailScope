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

# Lazy model loading – handle missing model files gracefully.
# The models are loaded on first use; if files are absent, placeholders are set.
_risk_model = None
_risk_preprocessor = None
_risk_label_encoder = None
_anomaly_model = None
_anomaly_preprocessor = None




# -------------------------------------------------------------------

def _load_risk_models():
    """Load risk classification models if they exist; otherwise keep as None."""
    global _risk_model, _risk_preprocessor, _risk_label_encoder
    if _risk_model is None:
        if RISK_MODEL_PATH.exists():
            _risk_model = joblib.load(RISK_MODEL_PATH)
        else:
            _risk_model = None
    if _risk_preprocessor is None:
        if RISK_PREPROCESSOR_PATH.exists():
            _risk_preprocessor = joblib.load(RISK_PREPROCESSOR_PATH)
        else:
            _risk_preprocessor = None
    if _risk_label_encoder is None:
        if RISK_LABEL_ENCODER_PATH.exists():
            _risk_label_encoder = joblib.load(RISK_LABEL_ENCODER_PATH)
        else:
            _risk_label_encoder = None

def _load_anomaly_models():
    """Load anomaly detection models if they exist; otherwise keep as None."""
    global _anomaly_model, _anomaly_preprocessor
    if _anomaly_model is None:
        if ANOMALY_MODEL_PATH.exists():
            _anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
        else:
            _anomaly_model = None
    if _anomaly_preprocessor is None:
        if ANOMALY_PREPROCESSOR_PATH.exists():
            _anomaly_preprocessor = joblib.load(ANOMALY_PREPROCESSOR_PATH)
        else:
            _anomaly_preprocessor = None
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
    "tls_detected",
    "key_exchange",
    "key_exchange_group",
    "public_key_algorithm",
    "starttls_supported",
    "starttls_requested",
    "starttls_accepted",
    "tls_handshake_observed",
    "encrypted_after_starttls",
    "direct_tls",
    "certificate_present",
    "certificate_count",
    "certificate_chain_valid",
]


def prepare_features(data):
    """Convert one security‑session dict into a DataFrame matching the ML feature schema.

    Missing keys are explicitly set to ``None`` so the preprocessing step receives a
    consistent column set. This mirrors the original behaviour but guarantees that the
    DataFrame always contains every column listed in ``FEATURE_COLUMNS``.
    """

    row = {column: data.get(column, None) for column in FEATURE_COLUMNS}
    return pd.DataFrame([row])


# -------------------------------------------------------------------
# RISK CLASSIFIER
# -------------------------------------------------------------------

def predict_risk(data):
    """
    Predict the ML-based security risk category.
    """

    # Ensure models are loaded
    _load_risk_models()
    if _risk_model is None or _risk_preprocessor is None or _risk_label_encoder is None:
        raise RuntimeError("Risk classification model files are missing; cannot predict risk.")

    dataframe = prepare_features(data)

    transformed = _risk_preprocessor.transform(dataframe)

    prediction = _risk_model.predict(transformed)[0]

    probabilities = _risk_model.predict_proba(transformed)[0]

    label = _risk_label_encoder.inverse_transform([prediction])[0]

    probability_map = {
        _risk_label_encoder.inverse_transform([index])[0]: float(probability)
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

    # Ensure anomaly model is loaded
    _load_anomaly_models()
    if _anomaly_model is None or _anomaly_preprocessor is None:
        raise RuntimeError("Anomaly detection model files are missing; cannot detect anomalies.")

    dataframe = prepare_features(data)

    transformed = _anomaly_preprocessor.transform(dataframe)

    prediction = _anomaly_model.predict(transformed)[0]

    anomaly_score = _anomaly_model.decision_function(transformed)[0]

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