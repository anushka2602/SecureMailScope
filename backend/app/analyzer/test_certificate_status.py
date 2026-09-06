from pathlib import Path

import pytest

from app.analyzer import feature_extractor
from app.reports.report_generator import _get_certificate_status


PCAP_PATH = (
    Path(__file__).resolve().parents[3]
    / "pcaps"
    / "smtp_starttls_test.pcapng"
)


@pytest.mark.parametrize(
    ("tls_version", "expected_status", "expected_display"),
    [
        ("TLS 1.3", "unavailable_tls13", "Unavailable (TLS 1.3)"),
        ("TLS 1.2", "not_observed", "Not observed"),
    ],
)
def test_no_certificate_status_uses_negotiated_tls_version(
    monkeypatch,
    tls_version,
    expected_status,
    expected_display,
):
    monkeypatch.setattr(
        feature_extractor,
        "reconstruct_tcp_streams",
        lambda _: {
            "1": {
                "packets": [
                    {
                        "source_port": 50000,
                        "destination_port": 465,
                    }
                ]
            }
        },
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_tls_packets",
        lambda *_args, **_kwargs: {
            "tls_detected": True,
            "negotiated_tls_version": tls_version,
        },
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_starttls",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        feature_extractor,
        "extract_certificates_from_pcap",
        lambda *_args, **_kwargs: [],
    )

    certificate = feature_extractor.extract_features_from_pcap(
        PCAP_PATH
    )[0]["certificate"]

    assert certificate["certificate_status"] == expected_status
    assert _get_certificate_status({"certificate": certificate}) == expected_display


def test_extracted_certificate_status(monkeypatch):
    monkeypatch.setattr(
        feature_extractor,
        "extract_certificates_from_pcap",
        lambda *_args, **_kwargs: [b"certificate"],
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_certificate",
        lambda _: {"certificate_present": True},
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_certificate_chain",
        lambda _: {},
    )

    certificate = feature_extractor.extract_certificate_from_pcap("capture")

    assert certificate["certificate_status"] == "extracted"
    assert _get_certificate_status({"certificate": certificate}) == "Extracted"


def test_certificate_parse_failure_status(monkeypatch):
    monkeypatch.setattr(
        feature_extractor,
        "extract_certificates_from_pcap",
        lambda *_args, **_kwargs: [b"invalid-certificate"],
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_certificate",
        lambda _: (_ for _ in ()).throw(ValueError("invalid DER")),
    )

    certificate = feature_extractor.extract_certificate_from_pcap("capture")

    assert certificate["certificate_status"] == "parse_failed"
    assert "Certificate parsing failed: invalid DER" == certificate["error"]
    assert _get_certificate_status({"certificate": certificate}) == "Parse failed"
