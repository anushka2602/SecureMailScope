from pathlib import Path

import joblib
import pandas as pd


# --------------------------------------------------
# Paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "backend" / "models"

RISK_MODEL_PATH = MODEL_DIR / "risk_classifier.pkl"
RISK_PREPROCESSOR_PATH = MODEL_DIR / "risk_preprocessor.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "risk_label_encoder.pkl"

ANOMALY_MODEL_PATH = MODEL_DIR / "tls_anomaly_detector.pkl"
ANOMALY_PREPROCESSOR_PATH = MODEL_DIR / "anomaly_preprocessor.pkl"


# --------------------------------------------------
# Load models
# --------------------------------------------------

print("=" * 70)
print("SecureMailScope - ML Model Testing")
print("=" * 70)

print("\nLoading trained models...")

risk_model = joblib.load(RISK_MODEL_PATH)
risk_preprocessor = joblib.load(RISK_PREPROCESSOR_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
anomaly_preprocessor = joblib.load(
    ANOMALY_PREPROCESSOR_PATH
)

print("All models loaded successfully.")


# --------------------------------------------------
# Test scenarios
# --------------------------------------------------

test_cases = [
    {
        "name": "Secure SMTP",
        "protocol": "SMTP",
        "tls_version": "TLS1.3",
        "cipher": "AES_256_GCM",
        "key_size": 2048,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA256",
        "starttls": 1,
        "forward_secrecy": 1,
    },
    {
        "name": "Legacy TLS Configuration",
        "protocol": "SMTP",
        "tls_version": "TLS1.0",
        "cipher": "3DES",
        "key_size": 1024,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA1",
        "starttls": 1,
        "forward_secrecy": 0,
    },
    {
        "name": "Expired Certificate",
        "protocol": "IMAP",
        "tls_version": "TLS1.2",
        "cipher": "AES_256_GCM",
        "key_size": 2048,
        "cert_expired": 1,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA256",
        "starttls": 1,
        "forward_secrecy": 1,
    },
    {
        "name": "No STARTTLS",
        "protocol": "POP3",
        "tls_version": "TLS1.2",
        "cipher": "AES_128_CBC",
        "key_size": 2048,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA256",
        "starttls": 0,
        "forward_secrecy": 0,
    },
    {
        "name": "Strong IMAP",
        "protocol": "IMAP",
        "tls_version": "TLS1.3",
        "cipher": "CHACHA20_POLY1305",
        "key_size": 3072,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "signature_algorithm": "SHA384",
        "starttls": 1,
        "forward_secrecy": 1,
    },
]


# --------------------------------------------------
# Feature definitions
# --------------------------------------------------

features = [
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


# --------------------------------------------------
# Test models
# --------------------------------------------------

for test_case in test_cases:

    name = test_case["name"]

    data = pd.DataFrame(
        [
            {
                feature: test_case[feature]
                for feature in features
            }
        ]
    )

    # ------------------------------
    # Risk classification
    # ------------------------------

    risk_input = risk_preprocessor.transform(data)

    risk_prediction = risk_model.predict(
        risk_input
    )[0]

    risk_label = label_encoder.inverse_transform(
        [risk_prediction]
    )[0]

    risk_probabilities = risk_model.predict_proba(
        risk_input
    )[0]

    class_probabilities = {
        label_encoder.inverse_transform([index])[0]:
        round(float(probability) * 100, 2)
        for index, probability
        in enumerate(risk_probabilities)
    }

    # ------------------------------
    # Anomaly detection
    # ------------------------------

    anomaly_input = anomaly_preprocessor.transform(
        data
    )

    anomaly_prediction = anomaly_model.predict(
        anomaly_input
    )[0]

    anomaly_score = anomaly_model.decision_function(
        anomaly_input
    )[0]

    if anomaly_prediction == -1:
        anomaly_status = "ANOMALOUS"
    else:
        anomaly_status = "NORMAL"

    # ------------------------------
    # Display
    # ------------------------------

    print("\n" + "-" * 70)
    print(f"TEST CASE: {name}")
    print("-" * 70)

    print(f"Protocol:              {test_case['protocol']}")
    print(f"TLS version:           {test_case['tls_version']}")
    print(f"Cipher:                {test_case['cipher']}")
    print(f"Key size:              {test_case['key_size']}")
    print(f"Certificate expired:   {test_case['cert_expired']}")
    print(f"STARTTLS:              {test_case['starttls']}")
    print(f"Forward secrecy:       {test_case['forward_secrecy']}")

    print("\nML RESULTS")

    print(
        f"Risk prediction:       {risk_label}"
    )

    print(
        f"Risk probabilities:    {class_probabilities}"
    )

    print(
        f"Anomaly status:        {anomaly_status}"
    )

    print(
        f"Anomaly score:         {anomaly_score:.4f}"
    )


print("\n" + "=" * 70)
print("ML MODEL TESTING COMPLETED")
print("=" * 70)