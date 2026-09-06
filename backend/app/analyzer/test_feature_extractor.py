import sys
from pathlib import Path

import pytest

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2])
)

import app.analyzer.feature_extractor as feature_extractor

from app.analyzer.feature_extractor import (
    extract_features_from_pcap
)


PCAP_PATH = r".\pcaps\smtp_starttls_test.pcapng"


@pytest.mark.parametrize(
    ("destination_port", "expected_direct_tls"),
    [
        (465, 1),
        (993, 1),
        (995, 1),
        (25, 0),
        (143, 0),
        (110, 0),
        (587, 0),
        (2525, 0),
    ],
)
def test_feature_extraction_preserves_direct_tls_protocol(
    monkeypatch,
    destination_port,
    expected_direct_tls,
):
    monkeypatch.setattr(
        feature_extractor,
        "reconstruct_tcp_streams",
        lambda _: {
            "1": {
                "packets": [
                    {
                        "source_port": 50000,
                        "destination_port": destination_port,
                    }
                ]
            }
        },
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_tls_packets",
        lambda *_args, **_kwargs: {"tls_detected": False},
    )
    monkeypatch.setattr(
        feature_extractor,
        "analyze_starttls",
        lambda *_args, **_kwargs: {},
    )

    pcap_path = Path(__file__).resolve().parents[3] / "pcaps" / "smtp_starttls_test.pcapng"
    sessions = extract_features_from_pcap(pcap_path)

    assert sessions[0]["features"]["direct_tls"] == expected_direct_tls


def main():
    print("=" * 70)
    print("SecureMailScope - Unified Feature Extractor Test")
    print("=" * 70)

    print("\nReading PCAP:")
    print(f"  {PCAP_PATH}")

    sessions = extract_features_from_pcap(
        PCAP_PATH
    )

    print("\nDetected email sessions:")
    print("-" * 70)

    if not sessions:
        print("No email sessions detected.")
        return

    for session in sessions:

        stream_id = session.get(
            "stream_id",
            "Unknown"
        )

        protocol = session.get(
            "protocol",
            "Unknown"
        )

        features = session.get(
            "features",
            {}
        )

        tls = session.get(
            "tls",
            {}
        )

        starttls = session.get(
            "starttls",
            {}
        )

        certificate = session.get(
            "certificate",
            {}
        )

        print(f"\nTCP Stream: {stream_id}")
        print(f"Protocol: {protocol}")

        print("\nSecurity Features:")
        for key, value in features.items():
            print(f"  {key}: {value}")

        print("\nTLS:")
        print(
            f"  Detected: "
            f"{tls.get('tls_detected')}"
        )

        print(
            f"  Negotiated version: "
            f"{tls.get('negotiated_tls_version')}"
        )

        print(
            f"  Negotiated cipher suite: "
            f"{tls.get('negotiated_cipher_suite')}"
        )

        print(
            f"  Key exchange: "
            f"{tls.get('key_exchange')}"
        )

        print(
            f"  Key exchange group: "
            f"{tls.get('key_exchange_group')}"
        )

        print(
            f"  Forward secrecy: "
            f"{tls.get('forward_secrecy')}"
        )

        print("\nSTARTTLS:")

        print(
            f"  Supported: "
            f"{starttls.get('starttls_supported')}"
        )

        print(
            f"  Requested: "
            f"{starttls.get('starttls_requested')}"
        )

        print(
            f"  Accepted: "
            f"{starttls.get('starttls_accepted')}"
        )

        print(
            f"  TLS handshake observed: "
            f"{starttls.get('tls_handshake_observed')}"
        )

        print(
            f"  Encrypted after STARTTLS: "
            f"{starttls.get('encrypted_after_starttls')}"
        )

        print("\nCertificate:")

        print(
            f"  Present: "
            f"{certificate.get('certificate_present')}"
        )

        print(
            f"  Subject: "
            f"{certificate.get('subject')}"
        )

        print(
            f"  Issuer: "
            f"{certificate.get('issuer')}"
        )

        print(
            f"  Public key algorithm: "
            f"{certificate.get('public_key_algorithm')}"
        )

        print(
            f"  Public key length: "
            f"{certificate.get('public_key_length')}"
        )

        print(
            f"  Signature algorithm: "
            f"{certificate.get('signature_algorithm')}"
        )

        print(
            f"  Expired: "
            f"{certificate.get('expired')}"
        )

        print(
            f"  Not yet valid: "
            f"{certificate.get('not_yet_valid')}"
        )

        chain = certificate.get(
            "chain",
            {}
        )

        if chain:
            print("\nCertificate Chain:")

            for key, value in chain.items():
                print(f"  {key}: {value}")

    print("\n" + "=" * 70)
    print("Unified feature extraction completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
