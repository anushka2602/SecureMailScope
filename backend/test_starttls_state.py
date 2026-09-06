import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent)
)

from app.analyzer.tcp_reconstructor import (
    reconstruct_tcp_streams
)

from app.analyzer.starttls_analyzer import (
    analyze_starttls
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PCAP_PATH = (
    PROJECT_ROOT
    / "pcaps"
    / "smtp_starttls_test.pcapng"
)


def main():

    print("=" * 70)
    print("SecureMailScope - STARTTLS State Test")
    print("=" * 70)

    print(
        f"\nPCAP: {PCAP_PATH}"
    )

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

    email_streams = 0

    for stream_id, stream in streams.items():

        result = analyze_starttls(
            stream
        )

        protocol = result.get(
            "protocol"
        )

        if protocol not in {
            "SMTP",
            "IMAP",
            "POP3",
        }:
            continue

        email_streams += 1

        print(
            "\n" + "-" * 60
        )

        print(
            f"TCP Stream: {stream_id}"
        )

        print(
            f"Protocol: "
            f"{result['protocol']}"
        )

        print(
            f"STARTTLS observed: "
            f"{result['starttls']}"
        )

        print(
            f"STARTTLS supported: "
            f"{result['starttls_supported']}"
        )

        print(
            f"STARTTLS requested: "
            f"{result['starttls_requested']}"
        )

        print(
            f"STARTTLS accepted: "
            f"{result['starttls_accepted']}"
        )

        print(
            f"TLS handshake observed: "
            f"{result['tls_handshake_observed']}"
        )

        print(
            f"Encrypted after STARTTLS: "
            f"{result['encrypted_after_starttls']}"
        )

    print(
        "\n" + "=" * 70
    )

    print(
        f"Email protocol streams analyzed: "
        f"{email_streams}"
    )

    print(
        "STARTTLS state test completed."
    )

    print("=" * 70)


if __name__ == "__main__":
    main()