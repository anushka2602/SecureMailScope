from pathlib import Path
import subprocess

from app.analyzer.tls_analyzer import analyze_tls_packets
from app.analyzer.tcp_reconstructor import reconstruct_tcp_streams
from app.analyzer.starttls_analyzer import analyze_starttls
from app.analyzer.certificate_analyzer import (
    analyze_certificate,
    analyze_certificate_chain,
)


EMAIL_PORTS = {
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP Submission",
    2525: "SMTP",
    143: "IMAP",
    993: "IMAPS",
    110: "POP3",
    995: "POP3S",
}


def detect_email_protocol_from_stream(stream):
    """
    Detect the email protocol associated with a TCP stream.

    Current detection uses known email service ports.
    Application-layer evidence can be added later to improve
    detection on non-standard ports.
    """

    packets = stream.get(
        "packets",
        []
    )

    if not packets:
        return None

    first_packet = packets[0]

    source_port = first_packet.get(
        "source_port"
    )

    destination_port = first_packet.get(
        "destination_port"
    )

    try:
        source_port = int(source_port)
        destination_port = int(destination_port)

    except (
        ValueError,
        TypeError
    ):
        return None

    if destination_port in EMAIL_PORTS:
        return EMAIL_PORTS[destination_port]

    if source_port in EMAIL_PORTS:
        return EMAIL_PORTS[source_port]

    return None


def normalize_protocol(protocol):
    """
    Normalize protocol names into SMTP, IMAP, or POP3.
    """

    if not protocol:
        return None

    protocol_upper = protocol.upper()

    if protocol_upper.startswith("SMTP"):
        return "SMTP"

    if protocol_upper.startswith("IMAP"):
        return "IMAP"

    if protocol_upper.startswith("POP3"):
        return "POP3"

    return protocol_upper


def is_direct_tls_protocol(protocol):
    """
    Determine whether the protocol represents direct TLS
    rather than an explicit STARTTLS/STLS upgrade.
    """

    if not protocol:
        return False

    return protocol.upper() in {
        "SMTPS",
        "IMAPS",
        "POP3S",
    }


def extract_certificates_from_pcap(
    pcap_path,
    tcp_stream=None,
):
    """
    Extract all X.509 certificates observed in a TLS stream.

    TShark exposes tls.handshake.certificate as hexadecimal
    encoded certificate data. Each extracted value is converted
    into DER bytes.

    The first certificate is normally the leaf/server
    certificate. Additional certificates may represent
    intermediate certificates.
    """

    display_filter = "tls.handshake.certificate"

    if tcp_stream is not None:
        display_filter = (
            f"tcp.stream == {tcp_stream} && "
            "tls.handshake.certificate"
        )

    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "occurrence=a",
        "-e",
        "tls.handshake.certificate",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "TShark certificate extraction failed:\n"
            f"{result.stderr}"
        )

    certificate_hex_values = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line:
            continue

        # TShark can expose multiple field occurrences
        # separated by commas depending on the capture.
        values = line.split(",")

        for value in values:

            value = value.strip()

            if value:
                certificate_hex_values.append(
                    value
                )

    if not certificate_hex_values:
        return []

    certificate_bytes_list = []

    for certificate_hex in certificate_hex_values:

        try:
            certificate_bytes = bytes.fromhex(
                certificate_hex
            )

        except (
            ValueError,
            TypeError
        ):
            continue

        if certificate_bytes:
            certificate_bytes_list.append(
                certificate_bytes
            )

    return certificate_bytes_list


def extract_certificate_from_pcap(
    pcap_path,
    tcp_stream=None,
):
    """
    Analyze the certificates observed in a TLS stream.

    The first certificate is treated as the leaf certificate.
    The complete observed certificate list is also passed to
    the certificate-chain analyzer.
    """

    certificate_bytes_list = (
        extract_certificates_from_pcap(
            pcap_path,
            tcp_stream=tcp_stream,
        )
    )

    if not certificate_bytes_list:

        return {
            "certificate_present": False,
            "certificate_count": 0,
            "certificate_status": "not_observed",
        }

    leaf_certificate_bytes = (
        certificate_bytes_list[0]
    )

    try:

        certificate_result = analyze_certificate(
            leaf_certificate_bytes
        )

    except Exception as error:

        return {
            "certificate_present": False,
            "certificate_count": len(
                certificate_bytes_list
            ),
            "certificate_status": "parse_failed",
            "error": (
                "Certificate parsing failed: "
                f"{error}"
            ),
        }

    chain_result = analyze_certificate_chain(
        certificate_bytes_list
    )

    certificate_result["certificate_present"] = True

    certificate_result["certificate_status"] = "extracted"

    certificate_result["certificate_count"] = (
        len(certificate_bytes_list)
    )

    certificate_result["chain"] = chain_result

    return certificate_result


def build_security_features(
    protocol,
    tls_result,
    starttls_result,
    certificate_result=None,
):
    """
    Build the normalized security feature object used by
    the rule engine, ML models, and reporting layer.

    The original ML-compatible fields are retained while
    additional cryptographic and forensic fields are exposed.
    """

    # Preserve original protocol for direct TLS detection before normalization
    original_protocol = protocol
    protocol = normalize_protocol(
        protocol
    )

    tls_result = tls_result or {}
    starttls_result = starttls_result or {}
    certificate_result = certificate_result or {}

    # ---------------------------------------------------------
    # TLS
    # ---------------------------------------------------------

    tls_detected = bool(
        tls_result.get(
            "tls_detected",
            False,
        )
    )

    negotiated_tls_version = (
        tls_result.get(
            "negotiated_tls_version"
        )
    )

    negotiated_cipher = (
        tls_result.get(
            "negotiated_cipher_suite"
        )
    )

    key_exchange = (
        tls_result.get(
            "key_exchange"
        )
    )

    key_exchange_group = (
        tls_result.get(
            "key_exchange_group"
        )
    )

    forward_secrecy = (
        tls_result.get(
            "forward_secrecy"
        )
    )

    tls_version_map = {
        "TLS 1.0": "TLS1.0",
        "TLS 1.1": "TLS1.1",
        "TLS 1.2": "TLS1.2",
        "TLS 1.3": "TLS1.3",
    }

    tls_version = tls_version_map.get(
        negotiated_tls_version,
        negotiated_tls_version,
    )

    # ---------------------------------------------------------
    # Cipher normalization
    #
    # Keep the normalized representation compatible with the
    # current ML dataset/model while retaining the original
    # negotiated cipher in tls_result.
    # ---------------------------------------------------------

    cipher = negotiated_cipher

    if cipher == "TLS_AES_128_GCM_SHA256":
        cipher = "AES_128_GCM"

    elif cipher == "TLS_AES_256_GCM_SHA384":
        cipher = "AES_256_GCM"

    elif cipher == "TLS_CHACHA20_POLY1305_SHA256":
        cipher = "CHACHA20_POLY1305"

    elif cipher == "TLS_AES_128_CCM_SHA256":
        cipher = "AES_128_CCM"

    elif cipher == "TLS_AES_128_CCM_8_SHA256":
        cipher = "AES_128_CCM_8"

    elif cipher == "TLS_RSA_WITH_AES_128_CBC_SHA":
        cipher = "AES_128_CBC"

    elif cipher == "TLS_RSA_WITH_AES_256_CBC_SHA":
        cipher = "AES_256_CBC"

    elif cipher == "TLS_RSA_WITH_AES_128_CBC_SHA256":
        cipher = "AES_128_CBC"

    elif cipher == "TLS_RSA_WITH_AES_256_CBC_SHA256":
        cipher = "AES_256_CBC"

    elif cipher in {
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    }:
        cipher = "AES_128_GCM"

    elif cipher in {
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    }:
        cipher = "AES_256_GCM"

    elif cipher in {
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    }:
        cipher = "AES_128_CBC"

    elif cipher in {
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    }:
        cipher = "AES_256_CBC"

    elif cipher in {
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    }:
        cipher = "CHACHA20_POLY1305"

    elif cipher == (
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    ):
        cipher = "AES_128_GCM"

    elif cipher == (
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    ):
        cipher = "AES_256_GCM"

    elif cipher == (
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    ):
        cipher = "AES_128_CBC"

    elif cipher == (
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    ):
        cipher = "AES_256_CBC"

    # ---------------------------------------------------------
    # STARTTLS / STLS state
    # ---------------------------------------------------------

    starttls_supported = bool(
        starttls_result.get(
            "starttls_supported",
            False,
        )
    )

    starttls_requested = bool(
        starttls_result.get(
            "starttls_requested",
            False,
        )
    )

    starttls_accepted = bool(
        starttls_result.get(
            "starttls_accepted",
            False,
        )
    )

    tls_handshake_observed = bool(
        starttls_result.get(
            "tls_handshake_observed",
            False,
        )
    )

    encrypted_after_starttls = bool(
        starttls_result.get(
            "encrypted_after_starttls",
            False,
        )
    )

    # Backward-compatible binary STARTTLS feature.
    starttls = 1 if (
        starttls_supported
        or starttls_requested
        or starttls_accepted
    ) else 0

    # ---------------------------------------------------------
    # Direct TLS
    # ---------------------------------------------------------

    # Direct TLS detection should consider the original protocol (e.g., SMTPS, IMAPS, POP3S)
    direct_tls = (
        1
        if is_direct_tls_protocol(
            original_protocol
        )
        else 0
    )

    # ---------------------------------------------------------
    # Certificate
    # ---------------------------------------------------------

    certificate_present = bool(
        certificate_result.get(
            "certificate_present",
            False,
        )
    )

    certificate_count = certificate_result.get(
        "certificate_count",
        0,
    )

    public_key_algorithm = (
        certificate_result.get(
            "public_key_algorithm"
        )
    )

    key_size = (
        certificate_result.get(
            "public_key_length"
        )
    )

    cert_expired = (
        certificate_result.get(
            "expired"
        )
    )

    cert_not_yet_valid = (
        certificate_result.get(
            "not_yet_valid"
        )
    )

    signature_algorithm = (
        certificate_result.get(
            "signature_algorithm"
        )
    )

    # ---------------------------------------------------------
    # Certificate chain
    # ---------------------------------------------------------

    chain = certificate_result.get(
        "chain",
        {}
    )

    certificate_chain_valid = None

    if isinstance(chain, dict):

        if "chain_valid" in chain:
            certificate_chain_valid = chain.get(
                "chain_valid"
            )

        elif "valid" in chain:
            certificate_chain_valid = chain.get(
                "valid"
            )

    # ---------------------------------------------------------
    # Final normalized feature object
    # ---------------------------------------------------------

    features = {
        # Core ML-compatible fields.
        "protocol": protocol,

        "tls_version": tls_version,

        "cipher": cipher,

        "key_size": key_size,

        "cert_expired": cert_expired,

        "cert_not_yet_valid": cert_not_yet_valid,

        "signature_algorithm": signature_algorithm,

        "starttls": starttls,

        "forward_secrecy": (
            1
            if forward_secrecy is True
            else 0
            if forward_secrecy is False
            else None
        ),

        # Additional cryptographic evidence.
        "tls_detected": tls_detected,

        "key_exchange": key_exchange,

        "key_exchange_group": key_exchange_group,

        "public_key_algorithm": (
            public_key_algorithm
        ),

        # Detailed STARTTLS state.
        "starttls_supported": (
            starttls_supported
        ),

        "starttls_requested": (
            starttls_requested
        ),

        "starttls_accepted": (
            starttls_accepted
        ),

        "tls_handshake_observed": (
            tls_handshake_observed
        ),

        "encrypted_after_starttls": (
            encrypted_after_starttls
        ),

        # Direct TLS state.
        "direct_tls": direct_tls,

        # Certificate state.
        "certificate_present": (
            certificate_present
        ),

        "certificate_count": (
            certificate_count
        ),

        "certificate_chain_valid": (
            certificate_chain_valid
        ),
    }

    return features


def extract_features_from_pcap(pcap_path):
    """
    Extract normalized security features from all detected
    email-related TCP streams in a PCAP.

    Pipeline:

        PCAP
          ↓
        TCP stream reconstruction
          ↓
        Email protocol detection
          ↓
        TLS analysis
          ↓
        STARTTLS analysis
          ↓
        Certificate extraction
          ↓
        Certificate chain analysis
          ↓
        Normalized security features
    """

    pcap_path = Path(
        pcap_path
    )

    if not pcap_path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    streams = reconstruct_tcp_streams(
        str(pcap_path)
    )

    all_sessions = []

    for stream_id, stream in streams.items():

        # -----------------------------------------------------
        # 1. Identify email protocol
        # -----------------------------------------------------

        protocol = (
            detect_email_protocol_from_stream(
                stream
            )
        )

        if protocol is None:
            continue

        normalized_protocol = normalize_protocol(
            protocol
        )

        # -----------------------------------------------------
        # 2. Analyze TLS
        # -----------------------------------------------------

        tls_result = analyze_tls_packets(
            str(pcap_path),
            tcp_stream=stream_id,
        )

        tls_detected = bool(
            tls_result.get(
                "tls_detected",
                False,
            )
        )

        # -----------------------------------------------------
        # 3. Analyze STARTTLS / STLS
        #
        # The current STARTTLS analyzer expects the complete
        # reconstructed stream, not protocol/payload arguments.
        # -----------------------------------------------------

        starttls_result = analyze_starttls(
            stream
        )

        # -----------------------------------------------------
        # 4. Analyze certificates
        # -----------------------------------------------------

        certificate_result = {
            "certificate_present": False,
            "certificate_count": 0,
            "certificate_status": "not_observed",
        }

        if tls_detected:

            certificate_result = (
                extract_certificate_from_pcap(
                    str(pcap_path),
                    tcp_stream=stream_id,
                )
            )

            if (
                certificate_result.get("certificate_status")
                == "not_observed"
                and tls_result.get("negotiated_tls_version")
                == "TLS 1.3"
            ):
                certificate_result["certificate_status"] = (
                    "unavailable_tls13"
                )

        # -----------------------------------------------------
        # 5. Build normalized feature set
        # -----------------------------------------------------

        features = build_security_features(
            protocol=protocol,
            tls_result=tls_result,
            starttls_result=starttls_result,
            certificate_result=certificate_result,
        )

        # -----------------------------------------------------
        # 6. Store complete session result
        # -----------------------------------------------------

        all_sessions.append(
            {
                "stream_id": stream_id,

                "protocol": normalized_protocol,

                "features": features,

                "tls": tls_result,

                "starttls": starttls_result,

                "certificate": certificate_result,
            }
        )

    return all_sessions
