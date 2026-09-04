from app.analyzer.pcap_parser import parse_pcap
from app.analyzer.protocol_detector import (
    detect_protocols,
    detect_email_protocols,
)
from app.analyzer.email_sessions import extract_email_sessions
from app.analyzer.tls_analyzer import analyze_tls_packets


PCAP_PATH = "../pcaps/test.pcapng"


def main():

    print("=" * 60)
    print("SecureMailScope - PCAP Analyzer")
    print("=" * 60)

    # ---------------------------------------------------------
    # STEP 1: Read PCAP
    # ---------------------------------------------------------

    print("\n[1] Reading PCAP...")

    packets = parse_pcap(PCAP_PATH)

    print(f"Packets captured: {len(packets)}")

    # ---------------------------------------------------------
    # STEP 2: Detect all protocols
    # ---------------------------------------------------------

    print("\n[2] All protocols detected:")

    protocols = detect_protocols(packets)

    for protocol in protocols:
        print(f"  - {protocol}")

    # ---------------------------------------------------------
    # STEP 3: Detect email protocols
    # ---------------------------------------------------------

    print("\n[3] Email protocols detected:")

    email_protocols = detect_email_protocols(packets)

    if email_protocols:
        for protocol in email_protocols:
            print(f"  - {protocol}")
    else:
        print("  None detected")

    # ---------------------------------------------------------
    # STEP 4: Extract email sessions
    # ---------------------------------------------------------

    print("\n[4] Email sessions:")

    sessions = extract_email_sessions(packets)

    if not sessions:
        print("  No email sessions detected.")
    else:

        for index, session in enumerate(sessions, start=1):

            print(f"\n  Session {index}")
            print(f"    Protocol: {session['protocol']}")
            print(
                f"    Source: "
                f"{session['source_ip']}:{session['source_port']}"
            )
            print(
                f"    Destination: "
                f"{session['destination_ip']}:"
                f"{session['destination_port']}"
            )
            print(
                f"    Packets: "
                f"{session['packet_count']}"
            )

    # ---------------------------------------------------------
    # STEP 5: TLS analysis
    # ---------------------------------------------------------

    print("\n[5] TLS analysis:")

    tls_result = analyze_tls_packets(packets)

    print(
        f"  TLS detected: "
        f"{tls_result['tls_detected']}"
    )

    print(
        f"  TLS packets: "
        f"{tls_result['tls_packet_count']}"
    )

    print("\n  TLS versions:")

    if tls_result["tls_versions"]:
        for item in tls_result["tls_versions"]:
            print(
                f"    - {item['value']} "
                f"({item['packet_count']} packets)"
            )
    else:
        print("    None")

    print("\n  Cipher suites:")

    if tls_result["cipher_suites"]:
        for item in tls_result["cipher_suites"]:
            print(
                f"    - {item['value']} "
                f"({item['packet_count']} packets)"
            )
    else:
        print("    None")

    print("\n  Handshake types:")

    if tls_result["handshake_types"]:
        for item in tls_result["handshake_types"]:
            print(
                f"    - {item['value']} "
                f"({item['packet_count']} packets)"
            )
    else:
        print("    None")

    print("\n  Supported groups:")

    if tls_result["supported_groups"]:
        for item in tls_result["supported_groups"]:
            print(
                f"    - {item['value']} "
                f"({item['packet_count']} packets)"
            )
    else:
        print("    None")

    print("\n  Key exchange groups:")

    if tls_result["key_exchange_groups"]:
        for item in tls_result["key_exchange_groups"]:
            print(
                f"    - {item['value']} "
                f"({item['packet_count']} packets)"
            )
    else:
        print("    None")

    # ---------------------------------------------------------
    # COMPLETE
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("Analysis completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()