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
    Generate the synthetic ground-truth risk label.

    This represents the deterministic security policy used
    to create the synthetic training labels.
    """

    risk_score = 0

    # TLS version
    if tls_version == "TLS1.0":
        risk_score += 40
    elif tls_version == "TLS1.1":
        risk_score += 30
    elif tls_version == "TLS1.2":
        risk_score += 5

    # Cipher
    if cipher == "3DES":
        risk_score += 35
    elif cipher == "AES_128_CBC":
        risk_score += 20
    elif cipher == "AES_256_CBC":
        risk_score += 15

    # Key size
    if key_size is not None:
        if key_size < 2048:
            risk_score += 30
        elif key_size == 2048:
            risk_score += 5

    # Certificate
    if cert_expired is True:
        risk_score += 40

    if cert_not_yet_valid is True:
        risk_score += 30

    # Signature algorithm
    if signature_algorithm == "SHA1":
        risk_score += 30

    # STARTTLS
    if starttls == 0:
        risk_score += 10

    # Forward secrecy
    if forward_secrecy == 0:
        risk_score += 20

    # Risk class
    if risk_score >= 70:
        return "High"

    if risk_score >= 30:
        return "Medium"

    return "Low"


def generate_row():
    """
    Generate one realistic synthetic email-security observation.
    """

    protocol = random.choice(PROTOCOLS)

    # Keep the overall distribution reasonably realistic,
    # while still generating all TLS versions frequently enough.
    tls_version = random.choices(
        TLS_VERSIONS,
        weights=[10, 10, 45, 35],
        k=1,
    )[0]

    # Generate a broad range of cipher combinations.
    cipher = random.choices(
        CIPHERS,
        weights=[8, 12, 12, 28, 28, 12],
        k=1,
    )[0]

    # ---------------------------------------------------------
    # Certificate observability
    # ---------------------------------------------------------
    #
    # In passive TLS 1.3 traffic without session keys,
    # certificate information may not be observable.
    #
    # Therefore these values are represented as None.
    # ---------------------------------------------------------

    if tls_version == "TLS1.3":

        key_size = None
        cert_expired = None
        cert_not_yet_valid = None
        signature_algorithm = None

    else:

        key_size = random.choices(
            KEY_SIZES,
            weights=[8, 57, 23, 12],
            k=1,
        )[0]

        cert_expired = random.choices(
            [0, 1],
            weights=[90, 10],
            k=1,
        )[0]

        cert_not_yet_valid = random.choices(
            [0, 1],
            weights=[96, 4],
            k=1,
        )[0]

        signature_algorithm = random.choices(
            SIGNATURE_ALGORITHMS,
            weights=[10, 60, 20, 10],
            k=1,
        )[0]

    # STARTTLS
    starttls = random.choices(
        [0, 1],
        weights=[20, 80],
        k=1,
    )[0]

    # Forward secrecy
    forward_secrecy = random.choices(
        [0, 1],
        weights=[30, 70],
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


def generate_balanced_dataset(
    samples_per_class=4000,
):
    """
    Generate an approximately balanced dataset.

    Rows are generated randomly and retained until each
    risk class reaches the requested number of samples.
    """

    target_counts = {
        "Low": samples_per_class,
        "Medium": samples_per_class,
        "High": samples_per_class,
    }

    collected = {
        "Low": [],
        "Medium": [],
        "High": [],
    }

    total_target = samples_per_class * 3

    attempts = 0
    max_attempts = total_target * 20

    while sum(len(rows) for rows in collected.values()) < total_target:

        row = generate_row()
        label = row["risk_label"]

        if len(collected[label]) < target_counts[label]:
            collected[label].append(row)

        attempts += 1

        if attempts >= max_attempts:
            raise RuntimeError(
                "Unable to generate a balanced dataset within "
                "the maximum number of attempts."
            )

    rows = (
        collected["Low"]
        + collected["Medium"]
        + collected["High"]
    )

    # Shuffle so classes aren't grouped together in the CSV.
    random.shuffle(rows)

    return rows


def main():

    print("=" * 70)
    print("SecureMailScope - Balanced Synthetic ML Dataset Generator")
    print("=" * 70)

    print("\nGenerating dataset...")

    rows = generate_balanced_dataset(
        samples_per_class=4000
    )

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
    print(
        dataframe["risk_label"]
        .value_counts()
        .sort_index()
    )

    print("\nRisk distribution percentages:")
    print(
        (
            dataframe["risk_label"]
            .value_counts(normalize=True)
            .sort_index()
            * 100
        ).round(2)
    )

    print("\nTLS version distribution:")
    print(
        dataframe["tls_version"]
        .value_counts()
        .sort_index()
    )

    print("\nCertificate observability:")
    print(
        dataframe[
            [
                "tls_version",
                "key_size",
                "cert_expired",
                "cert_not_yet_valid",
                "signature_algorithm",
            ]
        ]
        .isna()
        .groupby(dataframe["tls_version"])
        .mean()
        .round(3)
    )

    print("\nFirst 5 rows:")
    print(dataframe.head())

    print("\nDataset generation completed successfully.")


if __name__ == "__main__":
    main()