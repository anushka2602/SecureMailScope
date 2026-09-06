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
    # TLS 1.3
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0x1304": "TLS_AES_128_CCM_SHA256",
    "0x1305": "TLS_AES_128_CCM_8_SHA256",

    # TLS 1.2 / RSA
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0x003c": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "0x003d": "TLS_RSA_WITH_AES_256_CBC_SHA256",

    # ECDHE + AES-GCM
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",

    # ECDHE + AES-CBC
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0xc009": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "0xc00a": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",

    # ECDHE + ChaCha20
    "0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

    # DHE + AES-GCM
    "0x009e": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "0x009f": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",

    # DHE + AES-CBC
    "0x0033": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "0x0039": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",

    # ECDHE + AES-CBC SHA256
    "0xc027": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "0xc028": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "0xc023": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "0xc024": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
}


TLS_GROUP_MAP = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
}


def _run_tshark(pcap_path, display_filter, fields):
    """
    Execute TShark and return tab-separated rows.

    If TShark fails, raise a clear RuntimeError.
    """

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
        "-E",
        "occurrence=a",
    ]

    for field in fields:
        command.extend([
            "-e",
            field,
        ])

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

        rows.append(
            line.split("\t")
        )

    return rows


def _build_filter(base_filter, tcp_stream):
    """
    Restrict a TLS filter to one TCP stream when supplied.
    """

    if tcp_stream is None:
        return base_filter

    return (
        f"tcp.stream == {tcp_stream} "
        f"&& ({base_filter})"
    )


def _split_values(value):
    """
    Split TShark multi-value fields.

    TShark can represent repeated values as comma-separated
    values when occurrence=a is used.
    """

    if value is None:
        return []

    values = []

    for item in str(value).split(","):

        item = item.strip()

        if item:
            values.append(item)

    return values


def _tls_version_name(value):
    """
    Convert a raw TLS version value into a readable name.
    """

    if not value:
        return None

    value = str(value).strip().lower()

    return TLS_VERSION_MAP.get(
        value,
        value,
    )


def _cipher_name(value):
    """
    Convert a raw cipher-suite identifier into a readable name.
    """

    if not value:
        return None

    value = str(value).strip().lower()

    return TLS_CIPHER_MAP.get(
        value,
        value,
    )


def _key_exchange_from_cipher(cipher):
    """
    Infer TLS 1.0-1.2 key-exchange mechanism from the
    negotiated cipher suite.

    Important:

    ECDHE_RSA contains RSA because RSA is the authentication
    algorithm, not the key-exchange mechanism.

    Therefore ECDHE/DHE checks must occur before RSA.
    """

    if not cipher:
        return None

    cipher_upper = cipher.upper()

    if "_ECDHE_" in cipher_upper:
        return "ECDHE"

    if "_DHE_" in cipher_upper:
        return "DHE"

    if "_RSA_" in cipher_upper:
        return "RSA"

    # TLS 1.3 cipher suites do not encode the key exchange.
    if cipher_upper.startswith("TLS_AES_"):
        return "TLS 1.3 key exchange"

    if cipher_upper.startswith(
        "TLS_CHACHA20_"
    ):
        return "TLS 1.3 key exchange"

    return None


def _group_name(value):
    """
    Convert a TLS supported-group identifier into a readable name.
    """

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    try:

        group_id = int(
            value,
            0
        )

    except ValueError:

        try:
            group_id = int(value)

        except ValueError:
            return value

    return TLS_GROUP_MAP.get(
        group_id,
        value,
    )


def _extract_last_value(value):
    """
    Return the final non-empty value from a TShark field.
    """

    values = _split_values(
        value
    )

    if not values:
        return None

    return values[-1].strip()


def _counter_to_list(counter, mapper=None):
    """
    Convert a Counter into the standard result structure.
    """

    result = []

    for value, count in counter.items():

        mapped_value = (
            mapper(value)
            if mapper
            else value
        )

        result.append(
            {
                "value": mapped_value,
                "raw_value": value,
                "packet_count": count,
            }
        )

    return result


def _is_tls13_cipher(cipher):
    """
    Determine whether a cipher is a TLS 1.3 cipher suite.
    """

    if not cipher:
        return False

    return cipher.upper().startswith(
        (
            "TLS_AES_",
            "TLS_CHACHA20_",
        )
    )


def analyze_tls_packets(
    pcap_path,
    tcp_stream=None,
):
    """
    Analyze TLS traffic in a PCAP.

    If tcp_stream is supplied, analysis is restricted to
    that TCP stream.

    Forward secrecy:

        True
            Sufficient negotiated-handshake evidence indicates
            forward secrecy.

        False
            Sufficient evidence indicates a non-forward-secret
            key exchange.

        None
            TLS was observed, but the available evidence is
            insufficient to determine forward secrecy.
    """

    result = {
        "tls_detected": False,
        "tls_packet_count": 0,

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

    # ==================================================
    # TLS PACKETS
    # ==================================================

    tls_filter = _build_filter(
        "tls",
        tcp_stream,
    )

    tls_rows = _run_tshark(
        pcap_path,
        tls_filter,
        [
            "frame.number",
            "tls.record.version",
        ],
    )

    result["tls_detected"] = (
        len(tls_rows) > 0
    )

    result["tls_packet_count"] = (
        len(tls_rows)
    )

    if not tls_rows:
        return result

    # ==================================================
    # OBSERVED TLS RECORD VERSIONS
    # ==================================================

    version_counter = Counter()

    for row in tls_rows:

        if len(row) < 2:
            continue

        raw_value = row[1].strip()

        for version in _split_values(
            raw_value
        ):

            version_counter[
                version
            ] += 1

    result["tls_versions"] = (
        _counter_to_list(
            version_counter,
            _tls_version_name,
        )
    )

    # ==================================================
    # CIPHER SUITES
    # ==================================================

    cipher_filter = _build_filter(
        "tls.handshake.ciphersuite",
        tcp_stream,
    )

    cipher_rows = _run_tshark(
        pcap_path,
        cipher_filter,
        [
            "tls.handshake.ciphersuite",
        ],
    )

    cipher_counter = Counter()

    for row in cipher_rows:

        if not row:
            continue

        for value in _split_values(
            row[0]
        ):

            cipher_counter[
                value
            ] += 1

    result["cipher_suites"] = (
        _counter_to_list(
            cipher_counter,
            _cipher_name,
        )
    )

    # ==================================================
    # HANDSHAKE TYPES
    # ==================================================

    handshake_filter = _build_filter(
        "tls.handshake",
        tcp_stream,
    )

    handshake_rows = _run_tshark(
        pcap_path,
        handshake_filter,
        [
            "tls.handshake.type",
        ],
    )

    handshake_counter = Counter()

    for row in handshake_rows:

        if not row:
            continue

        for value in _split_values(
            row[0]
        ):

            handshake_counter[
                value
            ] += 1

    result["handshake_types"] = [
        {
            "value": value,
            "packet_count": count,
        }
        for value, count
        in handshake_counter.items()
    ]

    # ==================================================
    # SERVER HELLO
    # ==================================================

    server_hello_filter = _build_filter(
        "tls.handshake.type == 2",
        tcp_stream,
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

        # ----------------------------------------------
        # NEGOTIATED TLS VERSION
        # ----------------------------------------------

        negotiated_version = None

        #
        # TLS 1.3:
        #
        # The ServerHello legacy version may still be
        # 0x0303 (TLS 1.2), while the actual negotiated
        # version is carried in supported_versions.
        #
        if supported_version.strip():

            negotiated_version = (
                _extract_last_value(
                    supported_version
                )
            )

        elif handshake_version.strip():

            negotiated_version = (
                _extract_last_value(
                    handshake_version
                )
            )

        if negotiated_version:

            result[
                "negotiated_tls_version"
            ] = _tls_version_name(
                negotiated_version
            )

        # ----------------------------------------------
        # NEGOTIATED CIPHER
        # ----------------------------------------------

        negotiated_cipher = (
            _extract_last_value(
                cipher
            )
        )

        if negotiated_cipher:

            result[
                "negotiated_cipher_suite"
            ] = _cipher_name(
                negotiated_cipher
            )

            result["key_exchange"] = (
                _key_exchange_from_cipher(
                    result[
                        "negotiated_cipher_suite"
                    ]
                )
            )

        # ----------------------------------------------
        # SELECTED KEY SHARE GROUP
        # ----------------------------------------------

        selected_group = (
            _extract_last_value(
                key_share_group
            )
        )

        if selected_group:

            result[
                "key_exchange_group"
            ] = _group_name(
                selected_group
            )

    # ==================================================
    # SUPPORTED GROUPS
    # ==================================================

    supported_group_filter = _build_filter(
        "tls.handshake",
        tcp_stream,
    )

    supported_group_rows = _run_tshark(
        pcap_path,
        supported_group_filter,
        [
            "tls.handshake.extensions_supported_group",
        ],
    )

    supported_group_counter = Counter()

    for row in supported_group_rows:

        if not row:
            continue

        for value in _split_values(
            row[0]
        ):

            supported_group_counter[
                value
            ] += 1

    result["supported_groups"] = (
        _counter_to_list(
            supported_group_counter,
            _group_name,
        )
    )

    # ==================================================
    # KEY SHARE GROUPS
    # ==================================================

    key_share_filter = _build_filter(
        "tls.handshake.extensions_key_share_group",
        tcp_stream,
    )

    key_share_rows = _run_tshark(
        pcap_path,
        key_share_filter,
        [
            "tls.handshake.extensions_key_share_group",
        ],
    )

    key_share_counter = Counter()

    for row in key_share_rows:

        if not row:
            continue

        for value in _split_values(
            row[0]
        ):

            key_share_counter[
                value
            ] += 1

    result["key_exchange_groups"] = (
        _counter_to_list(
            key_share_counter,
            _group_name,
        )
    )

    # ==================================================
    # FALLBACK KEY EXCHANGE GROUP
    # ==================================================

    #
    # Prefer the explicitly selected group from ServerHello.
    #
    # If it was not available, use the most frequently observed
    # key-share group as supporting evidence.
    #

    if (
        result["key_exchange_group"]
        is None
        and key_share_counter
    ):

        selected_group = (
            key_share_counter
            .most_common(1)[0][0]
        )

        result[
            "key_exchange_group"
        ] = _group_name(
            selected_group
        )

    # ==================================================
    # FORWARD SECRECY
    # ==================================================

    negotiated_version = (
        result[
            "negotiated_tls_version"
        ]
    )

    negotiated_cipher = (
        result[
            "negotiated_cipher_suite"
        ]
    )

    key_exchange = (
        result[
            "key_exchange"
        ]
    )

    key_exchange_group = (
        result[
            "key_exchange_group"
        ]
    )

    # --------------------------------------------------
    # TLS 1.3
    # --------------------------------------------------

    #
    # TLS 1.3 uses ephemeral key exchange.
    #
    # We require both:
    #
    #   1. negotiated TLS 1.3
    #   2. evidence of a selected key-share group
    #
    # before reporting forward secrecy as True.
    #

    if negotiated_version == "TLS 1.3":

        if key_exchange_group:

            result[
                "forward_secrecy"
            ] = True

        else:

            result[
                "forward_secrecy"
            ] = None

    # --------------------------------------------------
    # TLS 1.2 / older: ECDHE or DHE
    # --------------------------------------------------

    elif (
        negotiated_version in {
            "TLS 1.0",
            "TLS 1.1",
            "TLS 1.2",
        }
        and key_exchange in {
            "ECDHE",
            "DHE",
        }
    ):

        result[
            "forward_secrecy"
        ] = True

    # --------------------------------------------------
    # TLS 1.2 / older: RSA key exchange
    # --------------------------------------------------

    elif (
        negotiated_version in {
            "TLS 1.0",
            "TLS 1.1",
            "TLS 1.2",
        }
        and key_exchange == "RSA"
    ):

        result[
            "forward_secrecy"
        ] = False

    # --------------------------------------------------
    # TLS 1.3 cipher but missing version evidence
    # --------------------------------------------------

    elif _is_tls13_cipher(
        negotiated_cipher
    ):

        #
        # Seeing a TLS 1.3 cipher is useful evidence,
        # but without a confirmed negotiated TLS version
        # we avoid overstating the conclusion.
        #

        result[
            "forward_secrecy"
        ] = None

    # --------------------------------------------------
    # Insufficient evidence
    # --------------------------------------------------

    else:

        result[
            "forward_secrecy"
        ] = None

    return result