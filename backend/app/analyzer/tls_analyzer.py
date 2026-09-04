import subprocess
from collections import Counter


TLS_VERSION_MAP = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}


TLS_CIPHER_MAP = {
    # TLS 1.3 AEAD cipher suites
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",

    # TLS 1.2 legacy cipher suites
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0x003c": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "0x003d": "TLS_RSA_WITH_AES_256_CBC_SHA256",
}


TLS_GROUP_MAP = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
}


def _run_tshark(pcap_path, display_filter, fields):
    command = [
        "tshark",
        "-r",
        str(pcap_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
    ]

    for field in fields:
        command.extend(["-e", field])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"TShark failed:\n{result.stderr}"
        )

    rows = []

    for line in result.stdout.splitlines():

        if not line.strip():
            continue

        rows.append(line.split("\t"))

    return rows


def _build_filter(base_filter, tcp_stream):
    """
    Add a TCP stream restriction when requested.

    Example:
        tls
        becomes:
        tcp.stream == 4 && tls
    """

    if tcp_stream is None:
        return base_filter

    return f"tcp.stream == {tcp_stream} && ({base_filter})"


def _split_values(value):
    if value is None:
        return []

    values = []

    for item in str(value).split(","):

        item = item.strip()

        if item:
            values.append(item)

    return values


def _tls_version_name(value):
    value = str(value).strip().lower()

    return TLS_VERSION_MAP.get(
        value,
        value
    )


def _cipher_name(value):
    value = str(value).strip().lower()

    return TLS_CIPHER_MAP.get(
        value,
        value
    )


def _key_exchange_from_cipher(cipher):
    """
    Infer the key-exchange mechanism from the negotiated
    TLS cipher suite.

    For TLS 1.2 and older cipher suites, the cipher suite
    name explicitly contains the key-exchange family.

    For TLS 1.3, the cipher suite no longer identifies the
    key-exchange mechanism, so we return a generic TLS 1.3
    label. The actual TLS 1.3 group is reported separately
    through key_exchange_group.
    """

    if not cipher:
        return None

    cipher_upper = cipher.upper()

    if "_RSA_" in cipher_upper:
        return "RSA"

    if "_ECDHE_" in cipher_upper:
        return "ECDHE"

    if "_DHE_" in cipher_upper:
        return "DHE"

    if cipher_upper.startswith("TLS_AES_"):
        return "TLS 1.3 key exchange"

    if cipher_upper.startswith("TLS_CHACHA20_"):
        return "TLS 1.3 key exchange"

    return None


def _group_name(value):
    value = str(value).strip()

    try:
        group_id = int(value, 0)

    except ValueError:
        return value

    return TLS_GROUP_MAP.get(
        group_id,
        value
    )


def analyze_tls_packets(pcap_path, tcp_stream=None):
    """
    Analyze TLS traffic in a PCAP.

    If tcp_stream is provided, only TLS traffic belonging
    to that TCP stream is analyzed.

    If tcp_stream is None, the entire PCAP is analyzed.
    """

    # --------------------------------------------------
    # TLS PACKETS
    # --------------------------------------------------

    tls_filter = _build_filter(
        "tls",
        tcp_stream
    )

    tls_rows = _run_tshark(
        pcap_path,
        tls_filter,
        [
            "frame.number",
            "tls.record.version",
        ],
    )

    result = {
        "tls_detected": len(tls_rows) > 0,
        "tls_packet_count": len(tls_rows),
        "tls_versions": [],
        "negotiated_tls_version": None,
        "cipher_suites": [],
        "negotiated_cipher_suite": None,
        "key_exchange": None,
        "handshake_types": [],
        "supported_groups": [],
        "key_exchange_groups": [],
        "key_exchange_group": None,
        "forward_secrecy": None,
    }

    if not tls_rows:
        return result

    # --------------------------------------------------
    # OBSERVED TLS VERSIONS
    # --------------------------------------------------

    version_counter = Counter()

    for row in tls_rows:

        if len(row) < 2:
            continue

        raw_value = row[1].strip()

        for version in _split_values(raw_value):

            version_counter[version] += 1

    result["tls_versions"] = [
        {
            "value": _tls_version_name(version),
            "raw_value": version,
            "packet_count": count,
        }
        for version, count in version_counter.items()
    ]

    # --------------------------------------------------
    # CIPHER SUITES
    # --------------------------------------------------

    cipher_filter = _build_filter(
        "tls.handshake.ciphersuite",
        tcp_stream
    )

    cipher_rows = _run_tshark(
        pcap_path,
        cipher_filter,
        [
            "tls.handshake.ciphersuite"
        ],
    )

    cipher_counter = Counter()

    for row in cipher_rows:

        if not row:
            continue

        for value in _split_values(row[0]):

            cipher_counter[value] += 1

    result["cipher_suites"] = [
        {
            "value": _cipher_name(value),
            "raw_value": value,
            "packet_count": count,
        }
        for value, count in cipher_counter.items()
    ]

    # --------------------------------------------------
    # HANDSHAKE TYPES
    # --------------------------------------------------

    handshake_filter = _build_filter(
        "tls.handshake",
        tcp_stream
    )

    handshake_rows = _run_tshark(
        pcap_path,
        handshake_filter,
        [
            "tls.handshake.type"
        ],
    )

    handshake_counter = Counter()

    for row in handshake_rows:

        if not row:
            continue

        for value in _split_values(row[0]):

            handshake_counter[value] += 1

    result["handshake_types"] = [
        {
            "value": value,
            "packet_count": count,
        }
        for value, count in handshake_counter.items()
    ]

    # --------------------------------------------------
    # SERVER HELLO
    # --------------------------------------------------

    server_hello_filter = _build_filter(
        "tls.handshake.type == 2",
        tcp_stream
    )

    server_hello_rows = _run_tshark(
        pcap_path,
        server_hello_filter,
        [
            "frame.number",
            "tls.handshake.version",
            "tls.handshake.ciphersuite",
            "tls.handshake.extensions.supported_version",
            "tls.handshake.extensions_key_share_group",
        ],
    )

    if server_hello_rows:

        row = server_hello_rows[0]

        while len(row) < 5:
            row.append("")

        (
            frame_number,
            handshake_version,
            cipher,
            supported_version,
            key_share_group,
        ) = row[:5]

        # --------------------------------------------------
        # NEGOTIATED TLS VERSION
        # --------------------------------------------------

        if supported_version.strip():

            supported_versions = _split_values(
                supported_version
            )

            if supported_versions:

                result["negotiated_tls_version"] = (
                    _tls_version_name(
                        supported_versions[-1]
                    )
                )

        elif handshake_version.strip():

            handshake_versions = _split_values(
                handshake_version
            )

            if handshake_versions:

                result["negotiated_tls_version"] = (
                    _tls_version_name(
                        handshake_versions[-1]
                    )
                )

        # --------------------------------------------------
        # NEGOTIATED CIPHER
        # --------------------------------------------------

        if cipher.strip():

            ciphers = _split_values(
                cipher
            )

            if ciphers:

                result["negotiated_cipher_suite"] = (
                    _cipher_name(
                        ciphers[-1]
                    )
                )

                # --------------------------------------------------
                # KEY EXCHANGE
                # --------------------------------------------------

                negotiated_cipher = (
                    result["negotiated_cipher_suite"]
                )

                result["key_exchange"] = (
                    _key_exchange_from_cipher(
                        negotiated_cipher
                    )
                )

        # --------------------------------------------------
        # KEY EXCHANGE GROUP
        # --------------------------------------------------

        if key_share_group.strip():

            groups = _split_values(
                key_share_group
            )

            if groups:

                selected_group = groups[-1].strip()

                result["key_exchange_group"] = (
                    _group_name(
                        selected_group
                    )
                )

    # --------------------------------------------------
    # SUPPORTED GROUPS
    # --------------------------------------------------

    supported_group_filter = _build_filter(
        "tls.handshake",
        tcp_stream
    )

    supported_group_rows = _run_tshark(
        pcap_path,
        supported_group_filter,
        [
            "tls.handshake.extensions_supported_group"
        ],
    )

    supported_group_counter = Counter()

    for row in supported_group_rows:

        if not row:
            continue

        for value in _split_values(row[0]):

            supported_group_counter[value] += 1

    result["supported_groups"] = [
        {
            "value": _group_name(value),
            "raw_value": value,
            "packet_count": count,
        }
        for value, count in supported_group_counter.items()
    ]

    # --------------------------------------------------
    # KEY SHARE GROUPS
    # --------------------------------------------------

    key_share_filter = _build_filter(
        "tls.handshake.extensions_key_share_group",
        tcp_stream
    )

    key_share_rows = _run_tshark(
        pcap_path,
        key_share_filter,
        [
            "tls.handshake.extensions_key_share_group"
        ],
    )

    key_share_counter = Counter()

    for row in key_share_rows:

        if not row:
            continue

        for value in _split_values(row[0]):

            key_share_counter[value] += 1

    result["key_exchange_groups"] = [
        {
            "value": _group_name(value),
            "raw_value": value,
            "packet_count": count,
        }
        for value, count in key_share_counter.items()
    ]

    # --------------------------------------------------
    # FALLBACK KEY EXCHANGE GROUP
    # --------------------------------------------------

    if result["key_exchange_group"] is None:

        if key_share_counter:

            selected_group = (
                key_share_counter
                .most_common(1)[0][0]
            )

            result["key_exchange_group"] = (
                _group_name(
                    selected_group.strip()
                )
            )

    # --------------------------------------------------
    # FORWARD SECRECY
    # --------------------------------------------------

    negotiated_version = (
        result["negotiated_tls_version"]
    )

    key_exchange_group = (
        result["key_exchange_group"]
    )

    if negotiated_version == "TLS 1.3":

        result["forward_secrecy"] = True

    elif key_exchange_group in {
        "x25519",
        "x448",
        "secp256r1",
        "secp384r1",
        "secp521r1",
    }:

        result["forward_secrecy"] = True

    elif negotiated_version:

        result["forward_secrecy"] = False

    return result

