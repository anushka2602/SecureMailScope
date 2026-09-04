from app.analyzer.feature_extractor import extract_features_from_pcap


PCAP_PATH = r".\pcaps\smtp_starttls_test.pcapng"


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

        print(f"\nTCP Stream: {session['stream_id']}")
        print(f"Protocol: {session['protocol']}")

        print("\nSecurity Features:")

        for key, value in session["features"].items():
            print(f"  {key}: {value}")

        print("\nSTARTTLS:")
        for key, value in session["starttls"].items():
            print(f"  {key}: {value}")

    print("\n")
    print("=" * 70)
    print("Unified feature extraction completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()