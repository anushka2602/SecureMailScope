import subprocess
from cryptography import x509


PCAP_PATH = "../pcaps/tls_test.pcapng"


def extract_certificates(pcap_path):
    """
    Extract X.509 certificates from TLS handshakes using TShark.
    """

    command = [
        "tshark",
        "-r",
        pcap_path,
        "-Y",
        "tls.handshake.certificate",
        "-T",
        "fields",
        "-e",
        "tls.handshake.certificate",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    certificates = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        # TShark may return multiple certificates separated by commas.
        for certificate_hex in line.split(","):

            certificate_hex = certificate_hex.strip()

            if not certificate_hex:
                continue

            try:
                certificate_bytes = bytes.fromhex(
                    certificate_hex
                )

                certificate = (
                    x509.load_der_x509_certificate(
                        certificate_bytes
                    )
                )

                certificates.append(certificate)

            except Exception as error:
                print(
                    "Could not parse certificate:",
                    error
                )

    return certificates


def main():

    print("=" * 60)
    print("SecureMailScope - X.509 Certificate Analyzer")
    print("=" * 60)

    print("\nExtracting certificates...")

    certificates = extract_certificates(PCAP_PATH)

    print(
        f"\nCertificates found: {len(certificates)}"
    )

    for index, certificate in enumerate(
        certificates,
        start=1
    ):

        print(f"\nCertificate {index}")
        print("-" * 40)

        print(
            "Subject:",
            certificate.subject.rfc4514_string()
        )

        print(
            "Issuer:",
            certificate.issuer.rfc4514_string()
        )

        print(
            "Valid from:",
            certificate.not_valid_before_utc
        )

        print(
            "Valid until:",
            certificate.not_valid_after_utc
        )

        public_key = certificate.public_key()

        print(
            "Public key type:",
            type(public_key).__name__
        )

        if hasattr(public_key, "key_size"):
            print(
                "Public key size:",
                public_key.key_size
            )

        print(
            "Signature hash:",
            certificate.signature_hash_algorithm.name
        )

    print("\n" + "=" * 60)
    print("Certificate analysis completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()