def calculate_security_score(data):
    score = 0
    findings = []
    recommendations = []

    # --------------------------------------------------
    # BASIC TLS STATE
    # --------------------------------------------------

    tls_version = data.get("tls_version")
    tls_detected = data.get("tls_detected")

    # If tls_detected is not explicitly supplied, infer
    # TLS presence from whether a TLS version was detected.
    if tls_detected is None:
        tls_detected = tls_version is not None

    direct_tls = data.get(
        "direct_tls",
        0,
    )

    starttls = data.get(
        "starttls"
    )

    # --------------------------------------------------
    # TLS VERSION
    # --------------------------------------------------

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

    elif tls_detected:
        # TLS was observed, but a negotiated version could
        # not be established from the captured handshake.
        findings.append(
            "TLS traffic was observed, but the negotiated TLS version could not be determined."
        )

        recommendations.append(
            "Capture the complete TLS handshake to verify the negotiated TLS version."
        )

    else:
        # No TLS was observed. This is plaintext / unencrypted
        # email traffic, not an unknown TLS version.
        score += 30

        findings.append(
            "No TLS protection was observed for this email session."
        )

        recommendations.append(
            "Require TLS protection for email communications where supported."
        )

    # --------------------------------------------------
    # CIPHER
    # --------------------------------------------------

    cipher = data.get(
        "cipher"
    )

    if cipher == "3DES":
        score += 30

        findings.append(
            "3DES is a weak/deprecated cipher."
        )

        recommendations.append(
            "Disable 3DES and use AES-GCM or ChaCha20-Poly1305."
        )

    elif cipher in {
        "AES_128_CBC",
        "AES_256_CBC",
    }:
        score += 15

        findings.append(
            "CBC-mode cipher suite detected."
        )

        recommendations.append(
            "Prefer modern AEAD cipher suites such as AES-GCM or ChaCha20-Poly1305."
        )

    # --------------------------------------------------
    # KEY EXCHANGE
    # --------------------------------------------------

    key_exchange = data.get(
        "key_exchange"
    )

    if key_exchange == "RSA":
        score += 15

        findings.append(
            "RSA key exchange is in use and does not provide forward secrecy."
        )

        recommendations.append(
            "Prefer ephemeral key exchange mechanisms such as ECDHE or DHE."
        )

    # --------------------------------------------------
    # PUBLIC KEY SIZE
    # --------------------------------------------------

    key_size = data.get(
        "key_size"
    )

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
            # 2048-bit RSA is acceptable, but a small informational
            # penalty is retained for consistency with the baseline.
            score += 3

    # --------------------------------------------------
    # CERTIFICATE VALIDITY
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
    # CERTIFICATE SIGNATURE
    # --------------------------------------------------

    signature_algorithm = data.get(
        "signature_algorithm"
    )

    if signature_algorithm:

        normalized_signature = (
            signature_algorithm.upper()
        )

        if normalized_signature in {
            "SHA1",
            "SHA-1",
        }:

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

    #
    # Important distinction:
    #
    # 1. No TLS + no STARTTLS
    #    -> plaintext email; already penalized above.
    #
    # 2. STARTTLS requested + TLS detected
    #    -> successful upgrade; no penalty.
    #
    # 3. STARTTLS requested + TLS NOT detected
    #    -> suspicious/incomplete upgrade.
    #
    # 4. TLS already detected
    #    -> don't penalize merely because STARTTLS command
    #       was not visible in the capture.
    #

    if (
        starttls == 1
        and not tls_detected
    ):

        score += 20

        findings.append(
            "STARTTLS was requested, but no TLS traffic was observed after the upgrade request."
        )

        recommendations.append(
            "Verify that the STARTTLS negotiation completes successfully and that subsequent email traffic is encrypted."
        )

    elif (
        starttls == 0
        and not tls_detected
        and direct_tls != 1
    ):

        # Plaintext session.
        #
        # The main TLS absence penalty was already applied
        # in the TLS-version section. Do not add another
        # STARTTLS penalty here.
        pass

    elif (
        starttls == 0
        and tls_detected
    ):

        # TLS is already present. STARTTLS may not appear in
        # the captured portion of the session, especially for
        # direct TLS or captures beginning after the upgrade.
        pass

    # --------------------------------------------------
    # FORWARD SECRECY
    # --------------------------------------------------

    forward_secrecy = data.get(
        "forward_secrecy"
    )

    #
    # True  -> forward secrecy confirmed.
    # False -> explicitly determined to be absent.
    # None  -> insufficient evidence.
    #

    if (
        forward_secrecy is False
        and key_exchange != "RSA"
    ):

        score += 15

        findings.append(
            "Forward secrecy was not observed."
        )

        recommendations.append(
            "Prefer ephemeral key exchange mechanisms that provide forward secrecy."
        )

    # RSA already has its own specific finding above.
    # Do not double-penalize it here.

    # --------------------------------------------------
    # INCOMPLETE TLS HANDSHAKE
    # --------------------------------------------------

    #
    # If TLS is visible but there is no negotiated version
    # and no negotiated cipher, the capture may simply be
    # incomplete.
    #
    # This is a forensic evidence limitation rather than
    # proof of insecure cryptography.
    #

    if (
        tls_detected
        and tls_version is None
        and cipher is None
    ):

        if not any(
            "negotiated TLS version" in finding
            for finding in findings
        ):

            findings.append(
                "TLS traffic was observed, but the handshake is incomplete and cryptographic parameters could not be verified."
            )

            recommendations.append(
                "Capture the complete TLS handshake for reliable cryptographic assessment."
            )

    # --------------------------------------------------
    # SCORE NORMALIZATION
    # --------------------------------------------------

    score = min(
        score,
        100,
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

    # --------------------------------------------------
    # RESULT
    # --------------------------------------------------

    return {
        "security_score": score,
        "severity": severity,
        "findings": findings,
        "recommendations": recommendations,
    }