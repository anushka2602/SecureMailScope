from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, LabelEncoder

from xgboost import XGBClassifier


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

MODEL_PATH = MODEL_DIR / "risk_classifier.pkl"
PREPROCESSOR_PATH = MODEL_DIR / "risk_preprocessor.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "risk_label_encoder.pkl"


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("=" * 70)
print("SecureMailScope - ML Risk Classifier Training")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Dataset shape: {df.shape}")

print("\nColumns:")
print(list(df.columns))


# --------------------------------------------------
# Separate features and target
# --------------------------------------------------

X = df.drop(
    columns=["risk_label"]
)

y = df["risk_label"]


# --------------------------------------------------
# Encode target labels
# --------------------------------------------------

label_encoder = LabelEncoder()

y_encoded = label_encoder.fit_transform(y)

print("\nRisk classes:")

for index, label in enumerate(label_encoder.classes_):
    print(f"{index} -> {label}")


# --------------------------------------------------
# Train / test split
# --------------------------------------------------
#
# IMPORTANT:
# We split the raw data BEFORE fitting the preprocessor.
# This prevents information from the test set leaking
# into the preprocessing stage.
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.20,
    random_state=42,
    stratify=y_encoded,
)


print("\nTraining samples:", X_train.shape[0])
print("Testing samples:", X_test.shape[0])


# --------------------------------------------------
# Feature definitions
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
            Pipeline(
                steps=[
                    (
                        "imputer",
                        SimpleImputer(
                            strategy="constant",
                            fill_value="UNKNOWN",
                        ),
                    ),
                    (
                        "encoder",
                        OneHotEncoder(
                            handle_unknown="ignore"
                        ),
                    ),
                ]
            ),
            categorical_features,
        ),
        (
            "numeric",
            Pipeline(
                steps=[
                    (
                        "imputer",
                        SimpleImputer(
                            strategy="median"
                        ),
                    ),
                ]
            ),
            numeric_features,
        ),
    ]
)


# --------------------------------------------------
# Fit preprocessor ONLY on training data
# --------------------------------------------------

X_train_processed = preprocessor.fit_transform(
    X_train
)

X_test_processed = preprocessor.transform(
    X_test
)


print(
    f"\nProcessed training feature shape: "
    f"{X_train_processed.shape}"
)

print(
    f"Processed testing feature shape: "
    f"{X_test_processed.shape}"
)


# --------------------------------------------------
# XGBoost model
# --------------------------------------------------

print("\nTraining XGBoost model...")

model = XGBClassifier(
    n_estimators=400,
    max_depth=5,
    learning_rate=0.05,
    subsample=0.85,
    colsample_bytree=0.85,
    objective="multi:softprob",
    num_class=len(label_encoder.classes_),
    eval_metric="mlogloss",
    random_state=42,
)


model.fit(
    X_train_processed,
    y_train,
)


# --------------------------------------------------
# Predictions
# --------------------------------------------------

y_pred = model.predict(
    X_test_processed
)


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n" + "=" * 70)
print("MODEL EVALUATION")
print("=" * 70)

print(
    f"\nAccuracy: {accuracy * 100:.2f}%"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0,
    )
)

print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred,
    )
)


# --------------------------------------------------
# Save model components
# --------------------------------------------------

joblib.dump(
    model,
    MODEL_PATH,
)

joblib.dump(
    preprocessor,
    PREPROCESSOR_PATH,
)

joblib.dump(
    label_encoder,
    LABEL_ENCODER_PATH,
)


print("\n" + "=" * 70)
print("MODEL SAVED")
print("=" * 70)

print(f"\nModel: {MODEL_PATH}")
print(f"Preprocessor: {PREPROCESSOR_PATH}")
print(f"Label encoder: {LABEL_ENCODER_PATH}")

print("\nTraining completed successfully.")