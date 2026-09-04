import random
from pathlib import Path

import pandas as pd


random.seed(42)


OUTPUT_FILE = Path(__file__).parent / "email_crypto_dataset.csv"


PROTOCOLS = [
    "SMTP",
    "IMAP",
    "POP3",
]


TLS_VERSIONS = [
    "TLS1.0",
    "TLS1.1",
    "TLS1.2",
    "TLS1.3",
]


CIPHERS = [
    "3DES",
    "AES_128_CBC",
    "AES_256_CBC",
    "AES_128_GCM",
    "AES_256_GCM",
    "CHACHA20_POLY1305",
]


SIGNATURE_ALGORITHMS = [
    "SHA1",
    "SHA256",
    "SHA384",
    "SHA512",
]


KEY_SIZES = [
    1024,
    2048,
    3072,
    4096,
]


def calculate_risk(
    tls_version,
    cipher,
    key_size,
    cert_expired,
    cert_not_yet_valid,
    signature_algorithm,
    starttls,
    forward_secrecy,
):
    """
    Calculate the synthetic ground-truth risk label.

    None means the feature is not observable from the
    passive capture and therefore must not contribute
    positively or negatively to the risk score.
    """

    risk_score = 0

    # ---------------------------------------------------------
    # TLS version
    # ---------------------------------------------------------

    if tls_version == "TLS1.0":
        risk_score += 40

    elif tls_version == "TLS1.1":
        risk_score += 30

    elif tls_version == "TLS1.2":
        risk_score += 5

    elif tls_version == "TLS1.3":
        risk_score += 0

    # ---------------------------------------------------------
    # Cipher
    # ---------------------------------------------------------

    if cipher == "3DES":
        risk_score += 35

    elif cipher == "AES_128_CBC":
        risk_score += 20

    elif cipher == "AES_256_CBC":
        risk_score += 15

    # Modern AEAD ciphers add no risk.

    # ---------------------------------------------------------
    # Key size
    # ---------------------------------------------------------

    if key_size is not None:

        if key_size < 2048:
            risk_score += 30

        elif key_size == 2048:
            risk_score += 5

    # ---------------------------------------------------------
    # Certificate
    # ---------------------------------------------------------

    if cert_expired is True:
        risk_score += 40

    if cert_not_yet_valid is True:
        risk_score += 30

    # ---------------------------------------------------------
    # Signature algorithm
    # ---------------------------------------------------------

    if signature_algorithm == "SHA1":
        risk_score += 30

    # ---------------------------------------------------------
    # STARTTLS
    # ---------------------------------------------------------

    if starttls == 0:
        risk_score += 10

    # ---------------------------------------------------------
    # Forward secrecy
    # ---------------------------------------------------------

    if forward_secrecy == 0:
        risk_score += 20

    # ---------------------------------------------------------
    # Convert score into class
    # ---------------------------------------------------------

    if risk_score >= 70:
        return "High"

    if risk_score >= 30:
        return "Medium"

    return "Low"


def generate_row():

    protocol = random.choice(PROTOCOLS)

    tls_version = random.choices(
        TLS_VERSIONS,
        weights=[8, 10, 45, 37],
        k=1,
    )[0]

    cipher = random.choices(
        CIPHERS,
        weights=[5, 10, 10, 30, 30, 15],
        k=1,
    )[0]

    # ---------------------------------------------------------
    # Certificate observability
    # ---------------------------------------------------------
    #
    # TLS 1.3 encrypts the Certificate message after
    # ServerHello. In a passive PCAP without session keys,
    # certificate information may therefore be unavailable.
    #
    # We explicitly model that state using None.
    # ---------------------------------------------------------

    if tls_version == "TLS1.3":

        key_size = None
        cert_expired = None
        cert_not_yet_valid = None
        signature_algorithm = None

    else:

        key_size = random.choices(
            KEY_SIZES,
            weights=[5, 65, 20, 10],
            k=1,
        )[0]

        cert_expired = random.choices(
            [0, 1],
            weights=[92, 8],
            k=1,
        )[0]

        cert_not_yet_valid = random.choices(
            [0, 1],
            weights=[97, 3],
            k=1,
        )[0]

        signature_algorithm = random.choices(
            SIGNATURE_ALGORITHMS,
            weights=[5, 65, 20, 10],
            k=1,
        )[0]

    # ---------------------------------------------------------
    # STARTTLS
    # ---------------------------------------------------------

    starttls = random.choices(
        [0, 1],
        weights=[20, 80],
        k=1,
    )[0]

    # ---------------------------------------------------------
    # Forward secrecy
    # ---------------------------------------------------------

    forward_secrecy = random.choices(
        [0, 1],
        weights=[25, 75],
        k=1,
    )[0]

    risk_label = calculate_risk(
        tls_version=tls_version,
        cipher=cipher,
        key_size=key_size,
        cert_expired=cert_expired,
        cert_not_yet_valid=cert_not_yet_valid,
        signature_algorithm=signature_algorithm,
        starttls=starttls,
        forward_secrecy=forward_secrecy,
    )

    return {
        "protocol": protocol,
        "tls_version": tls_version,
        "cipher": cipher,
        "key_size": key_size,
        "cert_expired": cert_expired,
        "cert_not_yet_valid": cert_not_yet_valid,
        "signature_algorithm": signature_algorithm,
        "starttls": starttls,
        "forward_secrecy": forward_secrecy,
        "risk_label": risk_label,
    }


def main():

    print("=" * 60)
    print("SecureMailScope - Synthetic ML Dataset Generator")
    print("=" * 60)

    rows = []

    for _ in range(2000):
        rows.append(generate_row())

    dataframe = pd.DataFrame(rows)

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print()
    print(f"Dataset created: {OUTPUT_FILE}")
    print(f"Rows: {len(dataframe)}")
    print(f"Columns: {len(dataframe.columns)}")

    print("\nRisk distribution:")
    print(dataframe["risk_label"].value_counts())

    print("\nCertificate observability:")
    print(
        dataframe[
            ["tls_version", "key_size", "cert_expired",
             "cert_not_yet_valid", "signature_algorithm"]
        ]
        .isna()
        .groupby(dataframe["tls_version"])
        .mean()
    )

    print("\nFirst 5 rows:")
    print(dataframe.head())

    print("\nDataset generation completed.")


if __name__ == "__main__":
    main()