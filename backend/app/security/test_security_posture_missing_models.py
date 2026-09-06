import importlib
import os
from pathlib import Path
import pytest

# Helper fixture to reload module fresh
@pytest.fixture
def reload_security_posture():
    if 'app.security.security_posture' in importlib.sys.modules:
        del importlib.sys.modules['app.security.security_posture']
    import app.security.security_posture as sp
    return sp

def test_prepare_features_contains_all_columns(reload_security_posture):
    sp = reload_security_posture
    sample = {"protocol": "SMTP", "tls_version": "TLS1.3", "cipher": "AES_256_GCM"}
    df = sp.prepare_features(sample)
    assert set(df.columns) == set(sp.FEATURE_COLUMNS)
    for col in sp.FEATURE_COLUMNS:
        if col not in sample:
            assert df.at[0, col] is None

def test_predict_risk_missing_model_files(monkeypatch, reload_security_posture):
    sp = reload_security_posture
    fake = Path(os.getenv('TMP', '/tmp')) / 'nonexistent.pkl'
    monkeypatch.setattr(sp, 'RISK_MODEL_PATH', fake)
    monkeypatch.setattr(sp, 'RISK_PREPROCESSOR_PATH', fake)
    monkeypatch.setattr(sp, 'RISK_LABEL_ENCODER_PATH', fake)
    with pytest.raises(RuntimeError, match='Risk classification model files are missing'):
        sp.predict_risk({})

def test_detect_anomaly_missing_model_files(monkeypatch, reload_security_posture):
    sp = reload_security_posture
    fake = Path(os.getenv('TMP', '/tmp')) / 'nonexistent_anomaly.pkl'
    monkeypatch.setattr(sp, 'ANOMALY_MODEL_PATH', fake)
    monkeypatch.setattr(sp, 'ANOMALY_PREPROCESSOR_PATH', fake)
    with pytest.raises(RuntimeError, match='Anomaly detection model files are missing'):
        sp.detect_anomaly({})
