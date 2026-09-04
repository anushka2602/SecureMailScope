from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


BASE_DIR = Path(__file__).resolve().parent

CERT_FILE = BASE_DIR / "server.crt"
KEY_FILE = BASE_DIR / "server.key"


def main():
    print("=" * 60)
    print("SecureMailScope - SMTP Lab Certificate Generator")
    print("=" * 60)

    print("\nGenerating RSA private key...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                "IN",
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "SecureMailScope Lab",
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "localhost",
            ),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.now(timezone.utc) - timedelta(minutes=5)
        )
        .not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=30)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .sign(
            private_key,
            hashes.SHA256(),
        )
    )

    KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    CERT_FILE.write_bytes(
        certificate.public_bytes(
            serialization.Encoding.PEM
        )
    )

    print(f"\nCertificate: {CERT_FILE}")
    print(f"Private key: {KEY_FILE}")

    print("\nCertificate generation completed.")


if __name__ == "__main__":
    main()