import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent)
)

from app.analyzer.tcp_reconstructor import (
    reconstruct_tcp_streams
)

from app.analyzer.payload_decoder import (
    decode_stream_payloads
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_PATH = (
    PROJECT_ROOT
    / "pcaps"
    / "smtp_starttls_test.pcapng"
)


def main():
    print("=" * 70)
    print("SecureMailScope - Payload Decoder Test")
    print("=" * 70)

    print(f"\nPCAP: {PCAP_PATH}")

    if not PCAP_PATH.exists():
        raise FileNotFoundError(
            f"\nPCAP file not found:\n{PCAP_PATH}\n"
        )

    streams = reconstruct_tcp_streams(
        PCAP_PATH
    )

    print(
        f"\nTCP streams found: {len(streams)}"
    )

    for stream_id, stream in streams.items():

        payloads = decode_stream_payloads(
            stream
        )

        if not payloads:
            continue

        print("\n" + "-" * 60)
        print(
            f"TCP Stream: {stream_id}"
        )

        print(
            f"Decoded directions: {len(payloads)}"
        )

        for index, payload in enumerate(
            payloads,
            start=1
        ):

            print(
                "\n" + "  " + "-" * 50
            )

            print(
                f"Direction {index}"
            )

            print(
                f"Return type: {type(payload).__name__}"
            )

            print(
                f"Payload characters: {len(payload)}"
            )

            print("\nFirst 1000 characters:")

            print(
                payload[:1000]
            )

    print("\n" + "=" * 70)
    print("Payload decoder test completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()