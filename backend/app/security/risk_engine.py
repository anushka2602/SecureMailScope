def calculate_security_score(data):
    """
    Calculate a deterministic cryptographic security score.

    Score:
        0   = best
        100 = worst
    """

    score = 0
    findings = []
    recommendations = []

    # --------------------------------------------------
    # TLS VERSION
    # --------------------------------------------------

    tls_version = data.get("tls_version")

    if tls_version == "TLS1.0":
        score += 35

        findings.append(
            "Deprecated TLS 1.0 is in use."
        )

        recommendations.append(
            "Disable TLS 1.0 and require TLS 1.2 or TLS 1.3."
        )

    elif tls_version == "TLS1.1":
        score += 25

        findings.append(
            "Deprecated TLS 1.1 is in use."
        )

        recommendations.append(
            "Disable TLS 1.1 and require TLS 1.2 or TLS 1.3."
        )

    elif tls_version == "TLS1.2":
        score += 5

    elif tls_version == "TLS1.3":
        score += 0

    else:
        score += 20

        findings.append(
            "Unknown or unsupported TLS version detected."
        )

        recommendations.append(
            "Verify the TLS configuration and use TLS 1.2 or TLS 1.3."
        )

    # --------------------------------------------------
    # CIPHER
    # --------------------------------------------------

    cipher = data.get("cipher")

    if cipher == "3DES":

        score += 30

        findings.append(
            "3DES is a weak/deprecated cipher."
        )

        recommendations.append(
            "Disable 3DES and use AES-GCM or ChaCha20-Poly1305."
        )

    elif cipher in [
        "AES_128_CBC",
        "AES_256_CBC",
    ]:

        score += 15

        findings.append(
            "CBC-mode cipher suite detected."
        )

        recommendations.append(
            "Prefer modern AEAD cipher suites such as AES-GCM or ChaCha20-Poly1305."
        )

    # --------------------------------------------------
    # KEY SIZE
    # --------------------------------------------------

    key_size = data.get("key_size")

    if key_size is not None:

        if key_size < 2048:

            score += 25

            findings.append(
                f"Weak public key size detected: {key_size} bits."
            )

            recommendations.append(
                "Use at least a 2048-bit RSA key or an appropriately sized modern elliptic-curve key."
            )

        elif key_size == 2048:

            score += 3

    # --------------------------------------------------
    # CERTIFICATE
    # --------------------------------------------------

    if data.get("cert_expired"):

        score += 30

        findings.append(
            "TLS certificate is expired."
        )

        recommendations.append(
            "Renew the certificate and deploy a currently valid certificate."
        )

    if data.get("cert_not_yet_valid"):

        score += 25

        findings.append(
            "TLS certificate is not yet valid."
        )

        recommendations.append(
            "Verify certificate validity dates and system clock configuration."
        )

    # --------------------------------------------------
    # SIGNATURE ALGORITHM
    # --------------------------------------------------

    signature_algorithm = data.get(
        "signature_algorithm"
    )

    if signature_algorithm == "SHA1":

        score += 25

        findings.append(
            "SHA-1 certificate signature detected."
        )

        recommendations.append(
            "Replace SHA-1 certificates with SHA-256 or stronger signatures."
        )

    # --------------------------------------------------
    # STARTTLS
    # --------------------------------------------------

    direct_tls = data.get("direct_tls", 0)

    if (
        data.get("starttls") == 0
        and direct_tls != 1
    ):

        score += 10

        findings.append(
            "STARTTLS was not observed."
        )

        recommendations.append(
            "Require TLS protection for email transport where supported."
        )

    # --------------------------------------------------
    # FORWARD SECRECY
    # --------------------------------------------------

    if data.get("forward_secrecy") == 0:

        score += 15

        findings.append(
            "Forward secrecy was not observed."
        )

        recommendations.append(
            "Prefer ephemeral key exchange mechanisms that provide forward secrecy."
        )

    # --------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------

    score = min(
        score,
        100
    )

    # --------------------------------------------------
    # SEVERITY
    # --------------------------------------------------

    if score >= 80:
        severity = "Critical"

    elif score >= 60:
        severity = "High"

    elif score >= 30:
        severity = "Medium"

    else:
        severity = "Low"

    return {
        "security_score": score,
        "severity": severity,
        "findings": findings,
        "recommendations": recommendations,
    }

