from app.analyzer.tcp_reconstructor import (
    reconstruct_tcp_streams
)

from app.analyzer.payload_decoder import (
    decode_stream_payloads
)


PCAP_PATH = "../pcaps/tls_test.pcapng"


def main():

    print("=" * 70)
    print("SecureMailScope - TCP Stream Reconstruction")
    print("=" * 70)

    streams = reconstruct_tcp_streams(
        PCAP_PATH
    )

    print(f"\nTCP streams found: {len(streams)}")

    for stream_id, stream in streams.items():

        print("\n" + "-" * 50)

        print(
            f"TCP Stream: {stream_id}"
        )

        print(
            f"Packets with payload: "
            f"{len(stream['packets'])}"
        )

        payloads = decode_stream_payloads(
            stream
        )

        for payload in payloads[:3]:

            print("\nPayload:")
            print(payload[:500])

    print("\n" + "=" * 70)
    print("TCP reconstruction completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()