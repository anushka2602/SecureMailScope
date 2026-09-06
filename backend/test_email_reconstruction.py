import sys
from pathlib import Path

# Ensure the backend directory is available on Python's import path.
# This allows the script to be run directly from the project root:
# python backend/test_email_reconstruction.py
sys.path.insert(
    0,
    str(Path(__file__).resolve().parent)
)

from app.analyzer.tcp_reconstructor import reconstruct_tcp_streams


# Resolve the project root independently of the current
# working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_PATH = (
    PROJECT_ROOT
    / "pcaps"
    / "smtp_starttls_test.pcapng"
)


def main():
    print("=" * 70)
    print("SecureMailScope - TCP Stream Reconstruction Test")
    print("=" * 70)

    print(f"\nPCAP: {PCAP_PATH}")

    # Check that the PCAP exists before passing it to TShark.
    if not PCAP_PATH.exists():
        raise FileNotFoundError(
            f"\nPCAP file not found:\n{PCAP_PATH}\n"
        )

    streams = reconstruct_tcp_streams(PCAP_PATH)

    print(f"\nTCP streams found: {len(streams)}")

    for stream_id, stream in streams.items():
        print("\n" + "-" * 60)
        print(f"TCP Stream: {stream_id}")

        packets = stream.get("packets", [])
        directions = stream.get("directions", [])

        print(f"Packets with payload: {len(packets)}")
        print(f"Reconstructed directions: {len(directions)}")

        # Display reconstructed directional streams.
        for index, direction in enumerate(directions, start=1):
            print("\n  " + "-" * 50)

            source_ip = direction.get("source_ip", "?")
            source_port = direction.get("source_port", "?")
            destination_ip = direction.get("destination_ip", "?")
            destination_port = direction.get("destination_port", "?")

            print(
                f"Direction {index}: "
                f"{source_ip}:{source_port} "
                f"-> "
                f"{destination_ip}:{destination_port}"
            )

            print(
                f"Reconstructed payload bytes: "
                f"{direction.get('payload_bytes', 0)}"
            )

            print(
                f"Complete: "
                f"{direction.get('complete', False)}"
            )

            gaps = direction.get("gaps", [])

            print(
                f"Gaps detected: "
                f"{len(gaps)}"
            )

            print(
                f"Retransmissions: "
                f"{direction.get('retransmissions', 0)}"
            )

            print(
                f"Overlapping segments: "
                f"{direction.get('overlapping_segments', 0)}"
            )

            # Display detected gaps.
            if gaps:
                print("\nGaps:")

                for gap in gaps[:5]:
                    print(
                        f"  {gap.get('start')} -> "
                        f"{gap.get('end')} "
                        f"({gap.get('length')} bytes)"
                    )

                if len(gaps) > 5:
                    print(
                        f"  ... and {len(gaps) - 5} more"
                    )

            # Display first reconstructed bytes.
            payload_hex = direction.get("payload_hex", "")

            if payload_hex:
                print("\nFirst 200 reconstructed bytes:")

                try:
                    reconstructed_bytes = bytes.fromhex(
                        payload_hex
                    )

                    print(
                        reconstructed_bytes[:200]
                    )

                except (ValueError, TypeError):
                    print(
                        "Could not decode reconstructed "
                        "payload hex."
                    )

    print("\n" + "=" * 70)
    print("TCP reconstruction test completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()