import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2])
)

from app.analyzer.tls_analyzer import analyze_tls_packets

PCAP_PATH = r".\pcaps\smtp_starttls_test.pcapng"


def main():

    print("=" * 70)
    print("SecureMailScope - TLS Analyzer Test")
    print("=" * 70)

    print("\nReading PCAP:")
    print(f"  {PCAP_PATH}")

    # Stream 4 is the SMTP STARTTLS lab session.
    stream_id = 4

    print(f"\nAnalyzing TCP stream: {stream_id}")

    result = analyze_tls_packets(
        PCAP_PATH,
        tcp_stream=stream_id
    )

    print("\nTLS Analysis")
    print("-" * 70)

    print("TLS detected:")
    print(f"  {result['tls_detected']}")

    print("\nTLS packet count:")
    print(f"  {result['tls_packet_count']}")

    print("\nNegotiated TLS version:")
    print(f"  {result['negotiated_tls_version']}")

    print("\nNegotiated cipher suite:")
    print(f"  {result['negotiated_cipher_suite']}")

    print("\nKey exchange:")
    print(f"  {result['key_exchange']}")

    print("\nKey exchange group:")
    print(f"  {result['key_exchange_group']}")

    print("\nForward secrecy:")
    print(f"  {result['forward_secrecy']}")

    print("\nObserved TLS versions:")

    for item in result["tls_versions"]:
        print(f"  {item}")

    print("\nObserved cipher suites:")

    for item in result["cipher_suites"]:
        print(f"  {item}")

    print("\nHandshake types:")

    for item in result["handshake_types"]:
        print(f"  {item}")

    print("\nSupported groups:")

    for item in result["supported_groups"]:
        print(f"  {item}")

    print("\nObserved key exchange groups:")

    for item in result["key_exchange_groups"]:
        print(f"  {item}")

    print("\n" + "=" * 70)
    print("TLS analyzer testing completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()