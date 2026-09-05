from pathlib import Path
import subprocess

from app.analyzer.tls_analyzer import analyze_tls_packets
from app.analyzer.tcp_reconstructor import reconstruct_tcp_streams
from app.analyzer.payload_decoder import decode_stream_payloads
from app.analyzer.starttls_analyzer import analyze_starttls
from app.analyzer.certificate_analyzer import analyze_certificate


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
    packets = stream.get("packets", [])

    if not packets:
        return None

    first_packet = packets[0]

    source_port = first_packet.get("source_port")
    destination_port = first_packet.get("destination_port")

    try:
        source_port = int(source_port)
        destination_port = int(destination_port)
    except (ValueError, TypeError):
        return None

    if destination_port in EMAIL_PORTS:
        return EMAIL_PORTS[destination_port]

    if source_port in EMAIL_PORTS:
        return EMAIL_PORTS[source_port]

    return None


def normalize_protocol(protocol):
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
    if not protocol:
        return False

    return protocol.upper() in {
        "SMTPS",
        "IMAPS",
        "POP3S",
    }


def extract_certificate_from_pcap(pcap_path, tcp_stream=None):
    """
    Extract the first X.509 certificate observed in a TLS stream.

    TShark exposes tls.handshake.certificate as DER-encoded
    hexadecimal data. We convert the hex to bytes and pass it
    to the certificate analyzer.
    """

    display_filter = "tls.handshake.certificate"

    if tcp_stream is not None:
        display_filter = (
            f"tcp.stream == {tcp_stream} && "
            "(tls.handshake.certificate)"
        )

    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
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
            f"TShark certificate extraction failed:\n{result.stderr}"
        )

    certificate_hex_values = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    if not certificate_hex_values:
        return {
            "certificate_present": False,
        }

    # TShark can expose multiple certificates.
    # For the current MVP we analyze the first certificate,
    # which is normally the server certificate.
    certificate_hex = certificate_hex_values[0]

    try:
        certificate_bytes = bytes.fromhex(
            certificate_hex
        )
    except ValueError:
        return {
            "certificate_present": False,
            "error": "Invalid certificate hex data.",
        }

    try:
        return analyze_certificate(
            certificate_bytes
        )
    except Exception as error:
        return {
            "certificate_present": False,
            "error": f"Certificate parsing failed: {error}",
        }


def build_security_features(
    protocol,
    tls_result,
    starttls_result,
    certificate_result=None,
):
    """
    Build the normalized security feature object used by
    the rule engine and ML models.

    The ML feature schema remains compatible with the current
    trained models.

    Additional forensic fields such as tls_detected,
    key_exchange, and key_exchange_group are retained for
    rule-based security analysis and reporting.
    """

    certificate_result = certificate_result or {}
    starttls_result = starttls_result or {}
    tls_result = tls_result or {}

    # --------------------------------------------------
    # TLS STATE
    # --------------------------------------------------

    tls_detected = bool(
        tls_result.get(
            "tls_detected",
            False,
        )
    )

    # --------------------------------------------------
    # TLS NEGOTIATION
    # --------------------------------------------------

    negotiated_tls_version = tls_result.get(
        "negotiated_tls_version"
    )

    negotiated_cipher = tls_result.get(
        "negotiated_cipher_suite"
    )

    key_exchange = tls_result.get(
        "key_exchange"
    )

    key_exchange_group = tls_result.get(
        "key_exchange_group"
    )

    forward_secrecy = tls_result.get(
        "forward_secrecy"
    )

    # --------------------------------------------------
    # NORMALIZE TLS VERSION
    # --------------------------------------------------

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

    # --------------------------------------------------
    # NORMALIZE CIPHER
    # --------------------------------------------------

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

    # ECDHE + AES-GCM
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

    # ECDHE + AES-CBC
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

    # ECDHE + ChaCha20
    elif cipher in {
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    }:
        cipher = "CHACHA20_POLY1305"

    # DHE + AES-GCM
    elif cipher in {
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    }:
        cipher = "AES_128_GCM"

    elif cipher in {
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    }:
        cipher = "AES_256_GCM"

    # DHE + AES-CBC
    elif cipher in {
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    }:
        cipher = "AES_128_CBC"

    elif cipher in {
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    }:
        cipher = "AES_256_CBC"

    # --------------------------------------------------
    # STARTTLS / DIRECT TLS
    # --------------------------------------------------

    starttls = 1 if (
        starttls_result.get("tls_upgrade_detected")
        or starttls_result.get("starttls_requested")
    ) else 0

    direct_tls = (
        1
        if is_direct_tls_protocol(protocol)
        else 0
    )

    # --------------------------------------------------
    # CERTIFICATE FEATURES
    # --------------------------------------------------

    public_key_algorithm = certificate_result.get(
        "public_key_algorithm"
    )

    key_size = certificate_result.get(
        "public_key_length"
    )

    cert_expired = certificate_result.get(
        "expired"
    )

    cert_not_yet_valid = certificate_result.get(
        "not_yet_valid"
    )

    signature_algorithm = certificate_result.get(
        "signature_algorithm"
    )

    # --------------------------------------------------
    # NORMALIZED SECURITY FEATURES
    # --------------------------------------------------

    features = {
        "protocol": normalize_protocol(protocol),

        # TLS state is now explicitly preserved.
        "tls_detected": tls_detected,

        "tls_version": tls_version,

        "cipher": cipher,

        # Forensic/rule-engine features.
        "key_exchange": key_exchange,

        "key_exchange_group": key_exchange_group,

        "public_key_algorithm": public_key_algorithm,

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

        "direct_tls": direct_tls,
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
        Payload decoding
          ↓
        TLS analysis
          ↓
        STARTTLS analysis
          ↓
        Certificate extraction
          ↓
        Normalized security features
    """

    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {pcap_path}"
        )

    # --------------------------------------------------
    # RECONSTRUCT TCP STREAMS
    # --------------------------------------------------

    streams = reconstruct_tcp_streams(
        str(pcap_path)
    )

    all_sessions = []

    # --------------------------------------------------
    # ANALYZE EACH STREAM
    # --------------------------------------------------

    for stream_id, stream in streams.items():

        protocol = detect_email_protocol_from_stream(
            stream
        )

        if protocol is None:
            continue

        normalized_protocol = normalize_protocol(
            protocol
        )

        # --------------------------------------------------
        # DECODE APPLICATION PAYLOAD
        # --------------------------------------------------

        payloads = decode_stream_payloads(
            stream
        )

        # --------------------------------------------------
        # TLS ANALYSIS
        # --------------------------------------------------

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

        # --------------------------------------------------
        # STARTTLS ANALYSIS
        # --------------------------------------------------

        starttls_result = analyze_starttls(
            normalized_protocol,
            payloads,
            tls_detected=tls_detected,
        )

        # --------------------------------------------------
        # CERTIFICATE ANALYSIS
        # --------------------------------------------------

        certificate_result = {}

        if tls_detected:

            certificate_result = (
                extract_certificate_from_pcap(
                    str(pcap_path),
                    tcp_stream=stream_id,
                )
            )

        # --------------------------------------------------
        # NORMALIZED SECURITY FEATURES
        # --------------------------------------------------

        features = build_security_features(
            protocol=protocol,
            tls_result=tls_result,
            starttls_result=starttls_result,
            certificate_result=certificate_result,
        )

        # --------------------------------------------------
        # SESSION OBJECT
        # --------------------------------------------------

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