from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import IsolationForest


# --------------------------------------------------
# Paths
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    PROJECT_ROOT
    / "backend"
    / "data"
    / "dataset"
    / "email_crypto_dataset.csv"
)

MODEL_DIR = (
    PROJECT_ROOT
    / "backend"
    / "models"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

MODEL_PATH = (
    MODEL_DIR
    / "tls_anomaly_detector.pkl"
)

PREPROCESSOR_PATH = (
    MODEL_DIR
    / "anomaly_preprocessor.pkl"
)


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("=" * 70)
print("SecureMailScope - TLS Anomaly Detection Training")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(
    f"Dataset shape: {df.shape}"
)


# --------------------------------------------------
# Features
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

X = df[features]


# --------------------------------------------------
# Feature types
# --------------------------------------------------

categorical_features = [
    "protocol",
    "tls_version",
    "cipher",
    "signature_algorithm",
]

numeric_features = [
    "key_size",
    "cert_expired",
    "cert_not_yet_valid",
    "starttls",
    "forward_secrecy",
]


# --------------------------------------------------
# Preprocessing
# --------------------------------------------------

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore"
            ),
            categorical_features,
        ),
        (
            "numeric",
            "passthrough",
            numeric_features,
        ),
    ]
)


X_processed = preprocessor.fit_transform(X)

print(
    f"Processed feature shape: "
    f"{X_processed.shape}"
)


# --------------------------------------------------
# Isolation Forest
# --------------------------------------------------

print("\nTraining Isolation Forest...")

model = IsolationForest(
    n_estimators=200,
    contamination=0.10,
    random_state=42,
)


model.fit(
    X_processed
)


# --------------------------------------------------
# Save
# --------------------------------------------------

joblib.dump(
    model,
    MODEL_PATH
)

joblib.dump(
    preprocessor,
    PREPROCESSOR_PATH
)


print("\n" + "=" * 70)
print("ANOMALY MODEL SAVED")
print("=" * 70)

print(
    f"\nModel: {MODEL_PATH}"
)

print(
    f"Preprocessor: {PREPROCESSOR_PATH}"
)

print("\nTraining completed successfully.")