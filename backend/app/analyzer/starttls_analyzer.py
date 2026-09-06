from app.analyzer.payload_decoder import (
    decode_stream_payloads
)


# Standard SMTP ports plus the custom SMTP laboratory port.
SMTP_PORTS = {
    25,
    465,
    587,
    2525,
}

IMAP_PORTS = {
    143,
    993,
}

POP3_PORTS = {
    110,
    995,
}


def _normalize_text(text):
    """
    Normalize decoded application-layer text.
    """

    if not text:
        return ""

    return text.replace(
        "\x00",
        ""
    )


def _get_protocol(stream):
    """
    Determine the email protocol associated with a TCP stream.

    This is currently based on known service ports.

    Later this can be combined with application-layer protocol
    detection for stronger support of non-standard ports.
    """

    packets = stream.get(
        "packets",
        []
    )

    for packet in packets:

        source_port = packet.get(
            "source_port"
        )

        destination_port = packet.get(
            "destination_port"
        )

        ports = {
            source_port,
            destination_port,
        }

        if ports & SMTP_PORTS:
            return "SMTP"

        if ports & IMAP_PORTS:
            return "IMAP"

        if ports & POP3_PORTS:
            return "POP3"

    return None


def _get_direction_role(direction, protocol):
    """
    Determine whether a reconstructed TCP direction is
    client-to-server or server-to-client.

    Returns:

        "client"
        "server"
        None
    """

    source_port = direction.get(
        "source_port"
    )

    destination_port = direction.get(
        "destination_port"
    )

    if protocol == "SMTP":

        if destination_port in SMTP_PORTS:
            return "client"

        if source_port in SMTP_PORTS:
            return "server"

    elif protocol == "IMAP":

        if destination_port in IMAP_PORTS:
            return "client"

        if source_port in IMAP_PORTS:
            return "server"

    elif protocol == "POP3":

        if destination_port in POP3_PORTS:
            return "client"

        if source_port in POP3_PORTS:
            return "server"

    return None


def _decode_direction(direction):
    """
    Decode one reconstructed TCP direction into text.

    Returns:

        str
    """

    payload_hex = direction.get(
        "payload_hex",
        ""
    )

    if not payload_hex:
        return ""

    try:

        payload_bytes = bytes.fromhex(
            payload_hex
        )

    except (
        ValueError,
        TypeError
    ):

        return ""

    return _normalize_text(
        payload_bytes.decode(
            "utf-8",
            errors="replace"
        )
    )


def _server_advertises_starttls(
    server_text,
    protocol
):
    """
    Determine whether the server advertised the TLS
    upgrade capability.
    """

    if not server_text:
        return False

    lines = server_text.splitlines()

    for line in lines:

        normalized = line.strip().upper()

        if protocol == "SMTP":

            # Examples:
            #
            # 250-STARTTLS
            # 250 STARTTLS
            #
            if (
                normalized.startswith("250")
                and "STARTTLS" in normalized
            ):
                return True

        elif protocol == "IMAP":

            if (
                "CAPABILITY" in normalized
                and "STARTTLS" in normalized
            ):
                return True

        elif protocol == "POP3":

            if (
                "STLS" in normalized
            ):
                return True

    return False


def _client_requests_starttls(
    client_text,
    protocol
):
    """
    Determine whether the client explicitly requested
    a TLS upgrade.
    """

    if not client_text:
        return False

    lines = client_text.splitlines()

    for line in lines:

        normalized = line.strip().upper()

        if protocol == "SMTP":

            if normalized == "STARTTLS":
                return True

        elif protocol == "IMAP":

            # Example:
            #
            # A001 STARTTLS
            #
            if "STARTTLS" in normalized:
                return True

        elif protocol == "POP3":

            if normalized == "STLS":
                return True

    return False


def _server_accepts_starttls(
    server_text,
    protocol
):
    """
    Determine whether the server accepted the TLS
    upgrade request.

    SMTP:
        220 2.0.0 Ready to start TLS

    IMAP:
        A001 OK Begin TLS negotiation now

    POP3:
        +OK Begin TLS negotiation now
    """

    if not server_text:
        return False

    lines = server_text.splitlines()

    for line in lines:

        normalized = line.strip().upper()

        if protocol == "SMTP":

            if normalized.startswith("220"):
                return True

        elif protocol == "IMAP":

            if (
                " OK " in
                f" {normalized} "
            ):
                return True

        elif protocol == "POP3":

            if normalized.startswith("+OK"):
                return True

    return False


def _find_request_position(
    client_text,
    protocol
):
    """
    Find the position of the STARTTLS/STLS request
    within the client direction.

    Returns:

        line index
        None
    """

    if not client_text:
        return None

    lines = client_text.splitlines()

    for index, line in enumerate(lines):

        normalized = line.strip().upper()

        if protocol == "SMTP":

            if normalized == "STARTTLS":
                return index

        elif protocol == "IMAP":

            if "STARTTLS" in normalized:
                return index

        elif protocol == "POP3":

            if normalized == "STLS":
                return index

    return None


def _find_acceptance_position(
    server_text,
    protocol
):
    """
    Find the position of the server's STARTTLS
    acceptance response.

    Returns:

        line index
        None
    """

    if not server_text:
        return None

    lines = server_text.splitlines()

    for index, line in enumerate(lines):

        normalized = line.strip().upper()

        if protocol == "SMTP":

            if normalized.startswith("220"):
                return index

        elif protocol == "IMAP":

            if (
                " OK " in
                f" {normalized} "
            ):
                return index

        elif protocol == "POP3":

            if normalized.startswith("+OK"):
                return index

    return None


def _detect_tls_handshake(stream):
    """
    Detect TLS handshake records directly from reconstructed
    binary TCP payload.

    TLS record structure:

        Byte 0     = Content Type
        Bytes 1-2  = Version
        Bytes 3-4  = Record Length

    TLS Handshake content type:

        22 / 0x16

    This is intentionally only a supporting signal.
    Detailed TLS parsing belongs to tls_analyzer.py.
    """

    directions = stream.get(
        "directions",
        []
    )

    for direction in directions:

        payload_hex = direction.get(
            "payload_hex",
            ""
        )

        if not payload_hex:
            continue

        try:

            payload = bytes.fromhex(
                payload_hex
            )

        except (
            ValueError,
            TypeError
        ):

            continue

        if len(payload) < 5:
            continue

        for index in range(
            0,
            len(payload) - 4
        ):

            content_type = payload[
                index
            ]

            version_major = payload[
                index + 1
            ]

            version_minor = payload[
                index + 2
            ]

            if (
                content_type == 22
                and version_major == 3
                and version_minor in {
                    0,
                    1,
                    2,
                    3,
                    4,
                }
            ):

                return True

    return False


def _analyze_directional_state(
    stream,
    protocol
):
    """
    Analyze STARTTLS state using separate client and
    server directions.

    This prevents a response from one direction from
    accidentally being interpreted as a response to a
    request in the other direction.
    """

    directions = stream.get(
        "directions",
        []
    )

    client_direction = None
    server_direction = None

    for direction in directions:

        role = _get_direction_role(
            direction,
            protocol
        )

        if role == "client":
            client_direction = direction

        elif role == "server":
            server_direction = direction

    if (
        client_direction is None
        or server_direction is None
    ):
        return {
            "client_text": "",
            "server_text": "",
            "starttls_supported": False,
            "starttls_requested": False,
            "starttls_accepted": False,
            "request_position": None,
            "acceptance_position": None,
        }

    client_text = _decode_direction(
        client_direction
    )

    server_text = _decode_direction(
        server_direction
    )

    starttls_supported = (
        _server_advertises_starttls(
            server_text,
            protocol
        )
    )

    starttls_requested = (
        _client_requests_starttls(
            client_text,
            protocol
        )
    )

    request_position = (
        _find_request_position(
            client_text,
            protocol
        )
    )

    acceptance_position = (
        _find_acceptance_position(
            server_text,
            protocol
        )
    )

    starttls_accepted = False

    if starttls_requested:

        starttls_accepted = (
            _server_accepts_starttls(
                server_text,
                protocol
            )
        )

    return {
        "client_text": client_text,
        "server_text": server_text,
        "starttls_supported": (
            starttls_supported
        ),
        "starttls_requested": (
            starttls_requested
        ),
        "starttls_accepted": (
            starttls_accepted
        ),
        "request_position": (
            request_position
        ),
        "acceptance_position": (
            acceptance_position
        ),
    }


def analyze_starttls(stream=None, protocol=None, payloads=None, tls_detected=False):
    """
    Analyze STARTTLS/STLS behavior in a reconstructed
    TCP stream.

    The analyzer uses directional client/server evidence
    instead of simply searching the entire stream.

    Returned fields:

        protocol
        starttls
        starttls_supported
        starttls_requested
        starttls_accepted
        tls_handshake_observed
        encrypted_after_starttls
        sni
    """

    if payloads is not None:
        stream = {"directions": [{"payload_hex": p} for p in payloads]}
    elif stream is None:
        stream = {"directions": []}

    if protocol is None:
        protocol = _get_protocol(stream)

    if protocol not in {
        "SMTP",
        "IMAP",
        "POP3",
    }:

        return {
            "protocol": protocol,
            "starttls": False,
            "starttls_supported": False,
            "starttls_requested": False,
            "starttls_accepted": False,
            "tls_handshake_observed": False,
            "encrypted_after_starttls": False,
            "sni": None,
        }

    state = _analyze_directional_state(
        stream,
        protocol
    )

    starttls_supported = state[
        "starttls_supported"
    ]

    starttls_requested = state[
        "starttls_requested"
    ]

    starttls_accepted = state[
        "starttls_accepted"
    ]

    tls_handshake_observed = tls_detected or _detect_tls_handshake(
        stream
    )

    encrypted_after_starttls = (
        starttls_accepted
        and tls_handshake_observed
    )

    starttls = (
        starttls_supported
        or starttls_requested
        or starttls_accepted
    )

    return {
        "protocol": protocol,

        # Backward-compatible field.
        "starttls": starttls,

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
    }


def detect_starttls(stream):
    """
    Backward-compatible helper.

    Returns only the legacy STARTTLS boolean.
    """

    result = analyze_starttls(
        stream
    )

    return result["starttls"]