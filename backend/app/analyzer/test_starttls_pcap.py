from app.analyzer.tcp_reconstructor import reconstruct_tcp_streams
from app.analyzer.payload_decoder import decode_stream_payloads
from app.analyzer.starttls_analyzer import analyze_starttls


PCAP_PATH = r".\pcaps\smtp_starttls_test.pcapng"


def looks_like_tls_handshake(payload_hex):
    """
    Detect a TLS Handshake record from raw TCP payload bytes.

    TLS record format starts with:
        Content Type = 0x16 (Handshake)
        Version      = 0x03 xx
    """

    try:
        data = bytes.fromhex(payload_hex.replace(":", ""))

        if len(data) < 5:
            return False

        return (
            data[0] == 0x16
            and data[1] == 0x03
            and data[2] in range(0x00, 0x05)
        )

    except (ValueError, TypeError):
        return False


def main():
    print("=" * 70)
    print("SecureMailScope - STARTTLS PCAP Test")
    print("=" * 70)

    print(f"\nReading PCAP:")
    print(f"  {PCAP_PATH}")

    streams = reconstruct_tcp_streams(PCAP_PATH)

    print(f"\nTCP streams containing payloads: {len(streams)}")

    for stream_id, stream in streams.items():

        payloads = decode_stream_payloads(stream)

        tls_handshake_detected = False
        tls_packet_index = None

        for index, packet in enumerate(stream["packets"]):
            payload_hex = packet.get("payload_hex", "")

            if looks_like_tls_handshake(payload_hex):
                tls_handshake_detected = True
                tls_packet_index = index
                break

        # We are specifically interested in SMTP traffic.
        result = analyze_starttls(
            protocol="SMTP",
            payloads=payloads,
            tls_detected=tls_handshake_detected,
        )

        if (
            result["starttls_supported"]
            or result["starttls_requested"]
            or result["tls_upgrade_detected"]
        ):
            print("\n" + "-" * 70)
            print(f"TCP Stream: {stream_id}")

            print(f"\nPayload packets: {len(stream['packets'])}")

            print("\nSTARTTLS Analysis:")
            print(
                f"  STARTTLS supported: "
                f"{result['starttls_supported']}"
            )
            print(
                f"  STARTTLS requested: "
                f"{result['starttls_requested']}"
            )
            print(
                f"  TLS handshake detected: "
                f"{tls_handshake_detected}"
            )
            print(
                f"  TLS upgrade detected: "
                f"{result['tls_upgrade_detected']}"
            )
            print(
                f"  Commands found: "
                f"{result['commands_found']}"
            )

            if tls_packet_index is not None:
                print(
                    f"\nTLS handshake found at payload packet "
                    f"index: {tls_packet_index}"
                )

    print("\n" + "=" * 70)
    print("STARTTLS PCAP testing completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()